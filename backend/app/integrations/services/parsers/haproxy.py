"""Parser for HAProxy configuration -> certificate references (``bind ... ssl crt ...``)."""
from __future__ import annotations

import posixpath
import re
import shlex

from app.integrations.contracts import ConfigCertRef, ServiceType
from app.integrations.services.parsers._common import resolve_path, split_dump

DEFAULT_BASE_DIR = "/etc/haproxy"
_SECTIONS = {
    "global", "defaults", "frontend", "backend", "listen", "resolvers", "peers", "userlist", "cache",
    "program", "mailers", "http-errors", "ring", "fcgi-app", "crt-store", "log-forward", "traces",
}
_NON_INET = ("unix@", "abns@", "fd@", "sockpair@", "/")
_MAX_RANGE = 20


def _tokens(line: str) -> list[str]:
    try:
        lex = shlex.shlex(line, posix=True)
        lex.whitespace_split = True
        lex.commenters = "#"
        return list(lex)
    except ValueError:
        return line.split("#", 1)[0].split()


def _ports_of(addr_list: str) -> list[int]:
    ports: list[int] = []
    for addr in addr_list.split(","):
        addr = addr.strip()
        if not addr or addr.startswith(_NON_INET):
            continue
        addr = re.sub(r"^(ipv4|ipv6|tcp4|tcp6|tcp|udp|udp4|udp6|quic4|quic6|quic)@", "", addr)
        if addr.startswith("["):
            m = re.match(r"^\[[^\]]*\]:(.+)$", addr)
            tail = m.group(1) if m else ""
        elif ":" in addr:
            tail = addr.rsplit(":", 1)[1]
        else:
            tail = ""
        m2 = re.fullmatch(r"(\d+)(?:-(\d+))?", tail)
        if not m2:
            continue
        lo = int(m2.group(1))
        hi = int(m2.group(2)) if m2.group(2) else lo
        if hi - lo >= _MAX_RANGE:
            hi = lo + _MAX_RANGE - 1
        ports.extend(p for p in range(lo, hi + 1) if 0 < p < 65536)
    return ports


def _bind_refs(args: list[str], *, section: str, name: str, file: str, line: int, crt_base: str | None,
               base_dir: str) -> list[ConfigCertRef]:
    if not args:
        return []
    lowered = [a.lower() for a in args]
    if "ssl" not in lowered:
        return []
    ports = tuple(sorted(set(_ports_of(args[0]))))
    ctx = f"{section} {name} bind {args[0]}".strip()
    refs: list[ConfigCertRef] = []
    rel_base = crt_base or base_dir
    i = 1
    while i < len(args):
        kw = lowered[i]
        if kw in ("crt", "crt-list", "default-crt") and i + 1 < len(args):
            val = args[i + 1]
            i += 2
            common = {
                "service": ServiceType.HAPROXY, "config_file": file, "line": line,
                "server_names": (), "listen_ports": ports, "key_path": None, "chain_path": None,
                "is_combined_pem": True,
            }
            if kw == "crt-list":
                refs.append(ConfigCertRef(
                    context=f"{ctx}; crt-list is not supported for deployment",
                    cert_path=None, unresolved_expression=f"crt-list {val}", confidence=0.2, **common,
                ))
                continue
            if "$" in val:
                refs.append(ConfigCertRef(context=ctx, cert_path=None, unresolved_expression=val,
                                          confidence=0.0, **common))
                continue
            path = resolve_path(val, rel_base)
            trailing = val.endswith("/")
            no_ext = "." not in posixpath.basename(path)
            is_dir = trailing or no_ext
            note = (
                "; directory (every certificate file inside is loaded)" if is_dir
                else f"; sibling key convention: {path}.key"
            )
            refs.append(ConfigCertRef(
                context=ctx + note, cert_path=path, is_directory=is_dir, unresolved_expression=None,
                confidence=1.0 if (trailing or not no_ext) else 0.7, **common,
            ))
        else:
            i += 1
    return refs


def parse_haproxy_cfg(text: str, base_dir: str = DEFAULT_BASE_DIR) -> list[ConfigCertRef]:
    """Extract certificate references from ``frontend`` / ``listen`` sections.

    ``text`` may be a single config or the ``# configuration file X:`` concatenated dump format;
    section state carries across files in order, like HAProxy's multi-file loading.
    """
    refs: list[ConfigCertRef] = []
    section, sec_name = "", ""
    crt_base: str | None = None
    pending: list[tuple[list[str], str, str, str, int]] = []
    for fname, content in split_dump(text, posixpath.join(base_dir, "haproxy.cfg")):
        for no, raw in enumerate(content.split("\n"), 1):
            toks = _tokens(raw.rstrip("\r"))
            if not toks:
                continue
            kw = toks[0].lower()
            if kw in _SECTIONS:
                section, sec_name = kw, toks[1] if len(toks) > 1 else ""
                continue
            if section == "global" and kw == "crt-base" and len(toks) > 1:
                crt_base = resolve_path(toks[1], base_dir)
            elif section in ("frontend", "listen") and kw == "bind":
                pending.append((toks[1:], section, sec_name, fname, no))
    # crt-base is global-wide regardless of where it appears relative to binds
    for args, section, sec_name, fname, no in pending:
        refs.extend(_bind_refs(args, section=section, name=sec_name, file=fname, line=no,
                               crt_base=crt_base, base_dir=base_dir))
    return refs
