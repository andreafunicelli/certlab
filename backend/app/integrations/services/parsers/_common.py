"""Helpers shared by the config parsers (pure text, no I/O)."""
from __future__ import annotations

import posixpath
import re

_HEADER = re.compile(r"^# configuration file (.+?):\s*$")


def split_dump(text: str, default_name: str) -> list[tuple[str, str]]:
    """Split ``nginx -T`` style output ("# configuration file X:" headers) into ``[(path, content)]``.

    Text before the first header is dropped when headers exist; without any header the whole text is
    returned as a single file called ``default_name``. Line numbers inside each file start at 1.
    """
    files: list[tuple[str, list[str]]] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        m = _HEADER.match(line)
        if m:
            files.append((m.group(1), []))
        elif files:
            files[-1][1].append(line)
    if not files:
        return [(default_name, text.replace("\r\n", "\n"))]
    return [(name, "\n".join(lines)) for name, lines in files]


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Shell glob (``*`` ``?`` ``[..]``) to regex; wildcards never cross a ``/``."""
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 2)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1 : j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


def has_glob(s: str) -> bool:
    return any(c in s for c in "*?[")


def resolve_path(value: str, base: str) -> str:
    if not value.startswith("/"):
        value = posixpath.join(base, value)
    return posixpath.normpath(value)


def match_files(pattern: str, names: list[str]) -> list[str]:
    """Names matching ``pattern`` (sorted); a plain directory pattern matches files beneath it."""
    if has_glob(pattern):
        rx = glob_to_regex(pattern)
        return sorted(n for n in names if rx.match(n))
    if pattern in names:
        return [pattern]
    prefix = pattern.rstrip("/") + "/"
    return sorted(n for n in names if n.startswith(prefix))
