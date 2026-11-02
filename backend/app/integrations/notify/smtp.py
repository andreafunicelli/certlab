"""SMTP delivery via smtplib (STARTTLS / implicit SSL / plain for local relays)."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

from app.integrations.notify.base import ChannelError, Message

SECURITY_MODES = ("starttls", "ssl", "none")


def validate_smtp_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Normalize + validate a channel config (no secrets here: the password lives in the vault)."""
    host = str(cfg.get("host", "")).strip()
    if not host or any(c in host for c in " \r\n/"):
        raise ValueError("smtp.host is required")
    security = str(cfg.get("security", "starttls")).lower()
    if security not in SECURITY_MODES:
        raise ValueError("smtp.security must be one of starttls, ssl, none")
    port = int(cfg.get("port") or {"starttls": 587, "ssl": 465, "none": 25}[security])
    if not 1 <= port <= 65535:
        raise ValueError("smtp.port out of range")
    to = cfg.get("to") or []
    if isinstance(to, str):
        to = [t.strip() for t in to.split(",") if t.strip()]
    if not to or any(("@" not in t or "\n" in t or "\r" in t) for t in to):
        raise ValueError("smtp.to must list at least one valid recipient address")
    sender = str(cfg.get("from_address", "")).strip()
    if "@" not in sender or "\n" in sender or "\r" in sender:
        raise ValueError("smtp.from_address must be a valid address")
    username = cfg.get("username")
    return {
        "host": host, "port": port, "security": security, "to": list(to), "from_address": sender,
        "username": str(username) if username else None,
        "timeout": float(cfg.get("timeout") or 15),
        "verify_certificates": bool(cfg.get("verify_certificates", True)),
    }


def _clean(s: str) -> str:
    return s.replace("\r", " ").replace("\n", " ")[:200]


def send_smtp(cfg: dict[str, Any], password: str | None, msg: Message) -> None:
    c = validate_smtp_config(cfg)
    email = EmailMessage()
    email["Subject"] = _clean(msg.subject)
    email["From"] = c["from_address"]
    email["To"] = ", ".join(c["to"])
    email["Date"] = formatdate(localtime=False)
    email["Message-ID"] = make_msgid(domain="cert-deploy-pro.invalid")
    email["X-CDP-Event"] = _clean(msg.event_type)
    email.set_content(msg.text)
    ctx = ssl.create_default_context()
    if not c["verify_certificates"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        if c["security"] == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(c["host"], c["port"], timeout=c["timeout"], context=ctx)
        else:
            server = smtplib.SMTP(c["host"], c["port"], timeout=c["timeout"])
        with server:
            server.ehlo()
            if c["security"] == "starttls":
                server.starttls(context=ctx)
                server.ehlo()
            if c["username"] and password:
                server.login(c["username"], password)
            server.send_message(email)
    except smtplib.SMTPAuthenticationError as exc:
        raise ChannelError("SMTP authentication failed", retryable=False) from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise ChannelError("SMTP server refused all recipients", retryable=False) from exc
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise ChannelError(f"SMTP delivery failed ({type(exc).__name__})") from exc
