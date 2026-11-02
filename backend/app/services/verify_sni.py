"""Choice of the TLS server name (SNI) used to verify an installation (known issue K1).

The composite ``vhost`` string (``names:ports``) is *never* a hostname and is never used here. Resolution order:

1. the installation's explicit ``verify_sni``;
2. the first concrete (non-wildcard, non-regex) ``server_name``;
3. for wildcard-only names: the first concrete DNS SAN of the certificate leaf (preferring one the wildcard covers);
4. a deterministic concrete name derived from the wildcard (``*`` becomes ``cdp-verify``), which the wildcard matches;
5. no names at all: ``None`` (connect by address without SNI).
"""
from __future__ import annotations

import fnmatch
import ipaddress
from collections.abc import Iterable

DERIVED_LABEL = "cdp-verify"


def _clean(name: str | None) -> str | None:
    n = (name or "").strip().lower()
    if not n or n in ("_", "-") or n.startswith("~") or "$" in n or any(c in n for c in " \t,:/"):
        return None
    n = n.removeprefix(".")
    return n or None


def is_wildcard(name: str) -> bool:
    return "*" in name


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _covered(name: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        head, _, rest = name.partition(".")
        return bool(head) and rest == pattern[2:]
    return fnmatch.fnmatchcase(name, pattern)


def resolve_verify_sni(verify_sni: str | None, server_names: Iterable[str] | None,
                       leaf_sans: Iterable[str] | None = None) -> str | None:
    if verify_sni and verify_sni.strip():
        return verify_sni.strip()
    names = [n for n in (_clean(x) for x in (server_names or [])) if n]
    for n in names:
        if not is_wildcard(n):
            return n
    wildcards = [n for n in names if is_wildcard(n)]
    if not wildcards:
        return None
    sans = [s.strip().lower() for s in (leaf_sans or []) if s and s.strip() and not is_wildcard(s) and not _is_ip(s.strip())]
    for s in sans:
        if any(_covered(s, w) for w in wildcards):
            return s
    if sans:
        return sans[0]
    return wildcards[0].replace("*", DERIVED_LABEL)


def vhost_names(vhost: str | None) -> list[str]:
    """Name part of the composite ``vhost`` label ``name1,name2:port1,port2`` written by discovery (``-`` = no names)."""
    if not vhost:
        return []
    head = vhost.rsplit(":", 1)[0] if ":" in vhost else vhost
    return [x for x in head.split(",") if x and x != "-"]


def required_hostnames(server_names: Iterable[str] | None, vhost: str | None, verify_sni: str | None) -> list[str]:
    """Concrete hostnames a deployed certificate must cover (wildcards, regexes and variables are skipped).
    The vhost label is never taken as a hostname itself, only its name part."""
    out: list[str] = []
    for n in [*(server_names or []), *vhost_names(vhost), verify_sni or ""]:
        if not n or n == "_" or n.startswith("~") or "*" in n or "$" in n:
            continue
        if n not in out:
            out.append(n)
    return out
