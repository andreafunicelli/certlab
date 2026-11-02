"""Output sanitising: remote output is untrusted and must never carry key material into logs/DB/UI."""
from __future__ import annotations

import re

_PEM_FULL = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", re.DOTALL)
_PEM_OPEN = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*", re.DOTALL)  # truncated block: drop to end
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{80,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]+")


def _b64_sub(m: re.Match[str]) -> str:
    return m.group(0) if len(m.group(0)) <= 128 and _HEX.fullmatch(m.group(0)) else "[REDACTED-BASE64]"


def sanitize_output(text: str, max_len: int = 8192) -> str:
    """Strip PEM blocks and long base64 runs (hex digests are kept), then truncate."""
    if not text:
        return ""
    text = _PEM_FULL.sub("[REDACTED-PEM]", text)
    text = _PEM_OPEN.sub("[REDACTED-PEM]", text)
    text = _B64_RUN.sub(_b64_sub, text)
    if len(text) > max_len:
        text = text[:max_len] + "...[truncated]"
    return text
