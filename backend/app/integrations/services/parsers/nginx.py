"""Parser for ``nginx -T`` output -> certificate references. Pure text processing."""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from app.integrations.contracts import ConfigCertRef, ServiceType
from app.integrations.services.parsers._common import match_files, resolve_path, split_dump

DEFAULT_PREFIX = "/etc/nginx"
_MAX_INCLUDE_DEPTH = 10
_UNSUPPORTED_SCHEME = re.compile(r"^(data|engine|store):", re.IGNORECASE)


# --------------------------------------------------------------------------- tokenizer
@dataclass
class Token:
    kind: str  # "word" | ";" | "{" | "}"
    value: str
    line: int
    quoted: bool = False


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


def tokenize(text: str) -> list[Token]:
    """nginx lexer: comments, single/double quotes with backslash escapes, ``${var}``, braces, ';'.
    Lenient: an unterminated quote swallows the rest of the file."""
    toks: list[Token] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r\f\v":
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in ";{}":
            toks.append(Token(c, c, line))
            i += 1
        elif c in "\"'":
            quote, start_line = c, line
            i += 1
            buf: list[str] = []
            while i < n and text[i] != quote:
                ch = text[i]
                if ch == "\\" and i + 1 < n:
                    nxt = text[i + 1]
                    if nxt in "\"'\\":
                        buf.append(nxt)
                    elif nxt in _ESCAPES:
                        buf.append(_ESCAPES[nxt])
                    else:
                        buf.append(ch + nxt)
                    if nxt == "\n":
                        line += 1
                    i += 2
                    continue
                if ch == "\n":
                    line += 1
                buf.append(ch)
                i += 1
            i += 1  # closing quote
            toks.append(Token("word", "".join(buf), start_line, True))
        else:
            buf = []
            start_line = line
            while i < n and text[i] not in " \t\r\n\f\v;{}\"'":
                ch = text[i]
                if ch == "\\" and i + 1 < n:
                    buf.append(text[i + 1] if text[i + 1] in " ;{}\"'\\" else ch + text[i + 1])
                    i += 2
                    continue
                if ch == "$" and i + 1 < n and text[i + 1] == "{":
                    j = text.find("}", i)
                    j = n - 1 if j == -1 else j
                    buf.append(text[i : j + 1])
                    i = j + 1
                    continue
                buf.append(ch)
                i += 1
            if buf:
                toks.append(Token("word", "".join(buf), start_line))
            else:  # stray quote char handled above; avoid infinite loop
                i += 1
    return toks


# --------------------------------------------------------------------------- block tree
@dataclass
class Node:
    name: str
    args: list[str]
    line: int
    file: str
    children: list[Node] | None = None  # None for simple directives
    arg_quoted: list[bool] = field(default_factory=list)

    def directives(self, name: str) -> list[Node]:
        return [c for c in (self.children or []) if c.name == name and c.children is None]

    def blocks(self, name: str) -> list[Node]:
        return [c for c in (self.children or []) if c.name == name and c.children is not None]


class _Parser:
    def __init__(self, files: dict[str, str], prefix: str):
        self.files = files
        self.prefix = prefix
        self.tokens_cache: dict[str, list[Token]] = {}

    def parse_file(self, path: str, stack: tuple[str, ...]) -> list[Node]:
        toks = self.tokens_cache.get(path)
        if toks is None:
            toks = self.tokens_cache[path] = tokenize(self.files[path])
        nodes, _ = self._statements(toks, 0, path, stack, top=True)
        return nodes

    def _statements(self, toks: list[Token], pos: int, path: str, stack: tuple[str, ...],
                    top: bool) -> tuple[list[Node], int]:
        out: list[Node] = []
        n = len(toks)
        while pos < n:
            t = toks[pos]
            if t.kind == "}":
                if top:  # stray brace: ignore
                    pos += 1
                    continue
                return out, pos + 1
            if t.kind in (";", "{"):
                if t.kind == "{":  # anonymous block: skip its contents
                    _, pos = self._statements(toks, pos + 1, path, stack, top=False)
                else:
                    pos += 1
                continue
            words: list[Token] = []
            while pos < n and toks[pos].kind == "word":
                words.append(toks[pos])
                pos += 1
            name, args = words[0].value, [w.value for w in words[1:]]
            node = Node(name, args, words[0].line, path, None, [w.quoted for w in words[1:]])
            end = toks[pos] if pos < n else None
            if end is not None and end.kind == "{":
                node.children, pos = self._statements(toks, pos + 1, path, stack, top=False)
                out.append(node)
            else:
                if end is not None and end.kind == ";":
                    pos += 1
                if name == "include" and args:
                    out.extend(self._include(args[0], path, stack))
                else:
                    out.append(node)
        return out, pos

    def _include(self, pattern: str, path: str, stack: tuple[str, ...]) -> list[Node]:
        if "$" in pattern or len(stack) >= _MAX_INCLUDE_DEPTH:
            return []
        pattern = resolve_path(pattern, self.prefix)
        nodes: list[Node] = []
        for name in match_files(pattern, list(self.files)):
            if name in stack or name == path:
                continue
            nodes.extend(self.parse_file(name, (*stack, path)))
        return nodes


# --------------------------------------------------------------------------- semantics
def _parse_listen(args: list[str]) -> tuple[int | None, bool]:
    """-> (port or None for unix sockets, ssl flag)."""
    if not args:
        return None, False
    addr = args[0]
    flags = {a.lower() for a in args[1:]}
    ssl = bool(flags & {"ssl", "quic"})
    if addr.startswith("unix:"):
        return None, ssl
    port: int | None = None
    if addr.startswith("["):
        m = re.match(r"^\[[^\]]*\]:(\d+)$", addr)
        port = int(m.group(1)) if m else None
    elif addr.isdigit():
        port = int(addr)
    elif ":" in addr:
        tail = addr.rsplit(":", 1)[1]
        port = int(tail) if tail.isdigit() else None
    if port is not None and not 0 < port < 65536:
        port = None
    if port is None:
        port = 443 if ssl else 80
    return port, ssl


def _inherited(node_chain: list[Node], name: str) -> list[Node]:
    """Array-style directive: the innermost level that defines it wins entirely."""
    for node in reversed(node_chain):
        found = node.directives(name)
        if found:
            return found
    return []


def _is_unresolved(value: str) -> bool:
    return "$" in value or bool(_UNSUPPORTED_SCHEME.match(value))


def _server_refs(server: Node, parents: list[Node], prefix: str, stream: bool) -> list[ConfigCertRef]:
    chain = [*parents, server]
    certs = _inherited(chain, "ssl_certificate")
    if not certs:
        return []
    keys = _inherited(chain, "ssl_certificate_key")

    names: list[str] = []
    for d in server.directives("server_name"):
        names.extend(a for a in d.args if a)
    ssl_on = any(d.args[:1] == ["on"] for d in _inherited(chain, "ssl"))
    ports: list[int] = []
    for d in server.directives("listen"):
        port, ssl = _parse_listen(d.args)
        if port is None:
            continue
        if ssl or ssl_on:
            ports.append(port)
    if not ports:
        # no ssl listener: report every listener (ssl may be enabled elsewhere), or the default port
        for d in server.directives("listen"):
            port, _ = _parse_listen(d.args)
            if port is not None:
                ports.append(port)
        if not server.directives("listen"):
            ports.append(443 if (ssl_on or stream) else 80)
    ports = sorted(set(ports))
    ctx = (
        f"{'stream ' if stream else ''}server{{server_name={' '.join(names)}; "
        f"listen={','.join(str(p) for p in ports)}}}"
    )

    refs: list[ConfigCertRef] = []
    for i, cert in enumerate(certs):
        key = keys[i] if i < len(keys) else None
        cval = cert.args[0] if cert.args else ""
        kval = key.args[0] if key is not None and key.args else None
        unresolved = [v for v in (cval, kval) if v and _is_unresolved(v)]
        cert_path = None if (not cval or _is_unresolved(cval)) else resolve_path(cval, prefix)
        key_path = None if (kval is None or _is_unresolved(kval)) else resolve_path(kval, prefix)
        refs.append(ConfigCertRef(
            service=ServiceType.NGINX,
            config_file=cert.file,
            line=cert.line,
            context=ctx,
            server_names=tuple(names),
            listen_ports=tuple(ports),
            cert_path=cert_path,
            key_path=key_path,
            chain_path=None,
            is_combined_pem=False,
            unresolved_expression="; ".join(unresolved) if unresolved else None,
            confidence=0.0 if unresolved else 1.0,
        ))
    return refs


def _walk_container(container: Node, parents: list[Node], prefix: str, stream: bool,
                    refs: list[ConfigCertRef]) -> None:
    chain = [*parents, container]
    for child in container.children or []:
        if child.children is not None and child.name == "server":
            refs.extend(_server_refs(child, chain, prefix, stream))


def parse_nginx_dump(text: str, prefix: str = DEFAULT_PREFIX) -> list[ConfigCertRef]:
    """Parse ``nginx -T`` output (or a single config file) into certificate references.

    Includes are expanded using the file contents present in the dump. ``ssl_certificate`` /
    ``ssl_certificate_key`` are inherited from ``http`` / ``stream`` when a server does not set them.
    """
    files_list = split_dump(text, posixpath.join(prefix, "nginx.conf"))
    files = dict(files_list)
    root = files_list[0][0]
    parser = _Parser(files, prefix)
    tree = parser.parse_file(root, ())
    refs: list[ConfigCertRef] = []
    top = Node("<root>", [], 0, root, tree)
    for node in tree:
        if node.children is None:
            continue
        if node.name in ("http", "stream"):
            _walk_container(node, [], prefix, node.name == "stream", refs)
        elif node.name == "server":  # config fragment without an http wrapper
            refs.extend(_server_refs(node, [top], prefix, False))
    return refs
