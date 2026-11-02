"""Parser for a concatenated Apache httpd configuration dump -> certificate references.

Input format is the one produced by the remote helper: ``# configuration file <path>:`` header lines
followed by the verbatim content of each file (the first file is the root config). ``Include`` /
``IncludeOptional`` are expanded from the dumped files; ``Define`` / ``${VAR}`` are expanded in order.
"""
from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from dataclasses import dataclass

from app.integrations.contracts import ConfigCertRef, ServiceType
from app.integrations.services.parsers._common import match_files, resolve_path, split_dump

DEFAULT_SERVER_ROOT = "/etc/apache2"
_MAX_INCLUDE_DEPTH = 10
_VAR = re.compile(r"\$\{([A-Za-z0-9_.\-]+)\}")


@dataclass
class Node:
    name: str  # lower-cased directive / section name
    args: list[str]
    line: int
    file: str
    root: str  # ServerRoot in effect where the directive appeared
    children: list[Node] | None = None  # sections only
    unresolved: bool = False


def _split_args(s: str) -> list[str]:
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
        elif c in "\"'":
            q = c
            i += 1
            buf: list[str] = []
            while i < n and s[i] != q:
                if s[i] == "\\" and i + 1 < n and s[i + 1] in (q, "\\"):
                    buf.append(s[i + 1])
                    i += 2
                else:
                    buf.append(s[i])
                    i += 1
            i += 1
            out.append("".join(buf))
        else:
            buf = []
            while i < n and not s[i].isspace():
                if s[i] == "\\" and i + 1 < n and s[i + 1] in " \"'":
                    buf.append(s[i + 1])
                    i += 2
                else:
                    buf.append(s[i])
                    i += 1
            out.append("".join(buf))
    return out


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    buf: list[str] = []
    start = 0
    for no, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if not buf:
            start = no
            if line.lstrip().startswith("#"):
                continue
        if line.endswith("\\"):
            buf.append(line[:-1])
            continue
        buf.append(line)
        joined = " ".join(p.strip() if i else p for i, p in enumerate(buf)).strip()
        buf = []
        if joined and not joined.startswith("#"):
            yield start, joined
    if buf:
        joined = " ".join(buf).strip()
        if joined and not joined.startswith("#"):
            yield start, joined


class _Parser:
    def __init__(self, files: dict[str, str], server_root: str):
        self.files = files
        self.server_root = server_root
        self.defines: dict[str, str] = {}

    def _expand(self, s: str) -> tuple[str, bool]:
        def sub(m: re.Match[str]) -> str:
            return self.defines.get(m.group(1), m.group(0))

        out = _VAR.sub(sub, s)
        return out, bool(_VAR.search(out))

    def parse_file(self, path: str, stack: tuple[str, ...]) -> list[Node]:
        root_nodes: list[Node] = []
        open_sections: list[Node] = []
        current = root_nodes
        for line_no, line in _logical_lines(self.files[path]):
            if line.startswith("</"):
                name = line[2:].rstrip(">").strip().lower()
                for idx in range(len(open_sections) - 1, -1, -1):
                    if open_sections[idx].name == name:
                        del open_sections[idx:]
                        break
                current = open_sections[-1].children if open_sections else root_nodes  # type: ignore[assignment]
                continue
            is_section = line.startswith("<")
            if is_section:
                inner = line[1:]
                inner = inner[: inner.rfind(">")] if ">" in inner else inner
                parts = _split_args(inner)
            else:
                parts = _split_args(line)
            if not parts:
                continue
            name = parts[0].lower()
            args, unresolved = [], False
            for a in parts[1:]:
                v, u = self._expand(a)
                args.append(v)
                unresolved = unresolved or u
            node = Node(name, args, line_no, path, self.server_root, None, unresolved)
            if is_section:
                node.children = []
                current.append(node)
                open_sections.append(node)
                current = node.children
                continue
            if name == "define" and args:
                self.defines[args[0]] = args[1] if len(args) > 1 else ""
            elif name == "undefine" and args:
                self.defines.pop(args[0], None)
            elif name == "serverroot" and args:
                self.server_root = resolve_path(args[0], self.server_root)
            elif name in ("include", "includeoptional") and args:
                current.extend(self._include(args[0], path, stack))
                continue
            current.append(node)
        return root_nodes

    def _include(self, pattern: str, path: str, stack: tuple[str, ...]) -> list[Node]:
        if "${" in pattern or len(stack) >= _MAX_INCLUDE_DEPTH:
            return []
        pattern = resolve_path(pattern, self.server_root)
        nodes: list[Node] = []
        for name in match_files(pattern, list(self.files)):
            if name == path or name in stack:
                continue
            nodes.extend(self.parse_file(name, (*stack, path)))
        return nodes


# --------------------------------------------------------------------------- semantics
def _flatten(nodes: list[Node], conf: float = 1.0) -> Iterator[tuple[Node, float]]:
    """Directives and VirtualHost sections, looking through conditional sections."""
    for n in nodes:
        if n.children is None or n.name == "virtualhost":
            yield n, conf
        elif n.name.startswith("if"):
            negated = any(a.startswith("!") for a in n.args[:1])
            c = conf if (n.name == "ifmodule" and not negated) else min(conf, 0.8)
            yield from _flatten(n.children, c)


def _port_of(addr: str) -> int | None:
    addr = addr.strip()
    if addr.startswith("["):
        m = re.match(r"^\[[^\]]*\](?::(\d+|\*))?$", addr)
        tail = m.group(1) if m else None
    elif addr.count(":") == 1:
        tail = addr.rsplit(":", 1)[1]
    elif addr.isdigit():
        tail = addr
    else:
        tail = None
    if tail and tail.isdigit() and 0 < int(tail) < 65536:
        return int(tail)
    return None


def _norm_name(v: str) -> str:
    v = re.sub(r"^[a-zA-Z]+://", "", v)
    if v.count(":") == 1:
        v = v.split(":")[0]
    return v.rstrip("/")


class _Scope:
    def __init__(self, items: list[tuple[Node, float]]):
        self.items = items

    def get(self, name: str) -> list[tuple[Node, float]]:
        return [(n, c) for n, c in self.items if n.name == name]


def _names(scope: _Scope) -> tuple[str, ...]:
    out: list[str] = []
    for n, _ in scope.get("servername") + scope.get("serveralias"):
        out.extend(_norm_name(a) for a in n.args)
    return tuple(dict.fromkeys(a for a in out if a))


def _build(scope_own: _Scope, scope_global: _Scope, ports: tuple[int, ...], context: str,
           names: tuple[str, ...]) -> list[ConfigCertRef]:
    def eff(name: str) -> tuple[list[tuple[Node, float]], bool]:
        own = scope_own.get(name)
        return (own, True) if own else (scope_global.get(name), False)

    certs, own_certs = eff("sslcertificatefile")
    if not certs:
        return []
    # key and chain follow the certificate's scope: a vhost with its own certificate never borrows a
    # global key (that vhost's key is then assumed to be in the certificate file)
    keys = scope_own.get("sslcertificatekeyfile") if own_certs else scope_global.get("sslcertificatekeyfile")
    chains, _ = eff("sslcertificatechainfile")
    engine_nodes, _ = eff("sslengine")
    engine = engine_nodes[-1][0].args[0].lower() if engine_nodes and engine_nodes[-1][0].args else None
    if engine == "off":
        return []
    engine_factor = 1.0
    if engine is None:
        if not own_certs:
            return []
        engine_factor = 0.5
    refs: list[ConfigCertRef] = []
    chain_node = chains[0] if chains else None
    for i, (cn, cconf) in enumerate(certs):
        kn = keys[i] if i < len(keys) else None
        cval = cn.args[0] if cn.args else ""
        kval = kn[0].args[0] if kn is not None and kn[0].args else None
        chval = chain_node[0].args[0] if chain_node and chain_node[0].args else None
        unresolved = []
        for v in (cval, kval, chval):
            if v and _VAR.search(v):
                unresolved.append(v)
        conf = cconf * engine_factor
        if kn is not None:
            conf = min(conf, kn[1])
        if chain_node is not None:
            conf = min(conf, chain_node[1])
        refs.append(ConfigCertRef(
            service=ServiceType.APACHE,
            config_file=cn.file,
            line=cn.line,
            context=context,
            server_names=names,
            listen_ports=ports,
            cert_path=None if (not cval or _VAR.search(cval)) else resolve_path(cval, cn.root),
            key_path=None if (kval is None or _VAR.search(kval)) else resolve_path(kval, kn[0].root),
            chain_path=None if (chval is None or _VAR.search(chval)) else resolve_path(chval, chain_node[0].root),
            is_combined_pem=kn is None,
            unresolved_expression="; ".join(unresolved) if unresolved else None,
            confidence=0.0 if unresolved else round(conf, 2),
        ))
    return refs


def parse_apache_dump(text: str, server_root: str = DEFAULT_SERVER_ROOT) -> list[ConfigCertRef]:
    """Extract ``SSLCertificateFile`` references from an Apache config dump."""
    files_list = split_dump(text, posixpath.join(server_root, "apache2.conf"))
    parser = _Parser(dict(files_list), server_root)
    tree = parser.parse_file(files_list[0][0], ())
    items = list(_flatten(tree))
    global_scope = _Scope([(n, c) for n, c in items if n.children is None])
    listen_ports: list[int] = []
    for n, _ in global_scope.get("listen"):
        if n.args:
            p = _port_of(n.args[0])
            if p is None and n.args[0].isdigit():
                p = int(n.args[0])
            if p:
                listen_ports.append(p)
    listen_ports = sorted(set(listen_ports))
    refs: list[ConfigCertRef] = []
    any_ssl_vhost = False
    for node, vconf in ((n, c) for n, c in items if n.children is not None):
        own = _Scope([(n, min(c, vconf)) for n, c in _flatten(node.children or [])])
        ports: list[int] = []
        for a in node.args:
            p = _port_of(a)
            if p:
                ports.append(p)
        if not ports:
            ports = list(listen_ports) or [443]
        ctx = f"<VirtualHost {' '.join(node.args)}>"
        built = _build(own, global_scope, tuple(sorted(set(ports))), ctx, _names(own))
        if built:
            any_ssl_vhost = True
        refs.extend(built)
    if not any_ssl_vhost:
        built = _build(_Scope([]), global_scope, tuple(listen_ports) or (443,), "<global>", _names(global_scope))
        refs.extend(built)
    return refs
