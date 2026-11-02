"""Generic JSON webhook.

Request: ``POST <url>`` with a JSON body ``{"event_type","severity","subject","text","payload","event_id","created_at"}``.
When a signing secret is configured the request carries

* ``X-CDP-Timestamp``: unix seconds
* ``X-CDP-Signature``: ``sha256=<hex hmac_sha256(secret, f"{timestamp}.{raw_body}")>``

Redirects are never followed; ``https`` is required unless the channel config explicitly sets ``allow_http: true``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.integrations.notify.base import ChannelError, Message


def validate_webhook_config(cfg: dict[str, Any]) -> dict[str, Any]:
    url = str(cfg.get("url", "")).strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("webhook.url must be an absolute http(s) URL")
    if parts.username or parts.password:
        raise ValueError("webhook.url must not embed credentials; use the secret field")
    allow_http = bool(cfg.get("allow_http", False))
    if parts.scheme == "http" and not allow_http:
        raise ValueError("webhook.url must use https (set allow_http=true to explicitly allow plain http)")
    timeout = float(cfg.get("timeout") or 10)
    if not 1 <= timeout <= 60:
        raise ValueError("webhook.timeout must be between 1 and 60 seconds")
    return {"url": url, "allow_http": allow_http, "timeout": timeout,
            "verify_tls": bool(cfg.get("verify_tls", True))}


def sign_body(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def build_webhook_request(cfg: dict[str, Any], secret: str | None, msg: Message,
                          now: float | None = None) -> tuple[str, bytes, dict[str, str]]:
    c = validate_webhook_config(cfg)
    body = json.dumps({
        "event_type": msg.event_type, "severity": msg.severity, "subject": msg.subject, "text": msg.text,
        "payload": msg.payload, "event_id": msg.event_id, "created_at": msg.created_at,
    }, sort_keys=True, default=str, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "cert-deploy-pro/1", "X-CDP-Event": msg.event_type}
    if secret:
        ts = str(int(now if now is not None else time.time()))
        headers["X-CDP-Timestamp"] = ts
        headers["X-CDP-Signature"] = sign_body(secret, ts, body)
    return c["url"], body, headers


def send_webhook(cfg: dict[str, Any], secret: str | None, msg: Message, *,
                 transport: httpx.BaseTransport | None = None) -> int:
    c = validate_webhook_config(cfg)
    url, body, headers = build_webhook_request(cfg, secret, msg)
    try:
        with httpx.Client(timeout=c["timeout"], follow_redirects=False, verify=c["verify_tls"],
                          transport=transport, trust_env=False) as client:
            resp = client.post(url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        raise ChannelError(f"webhook request failed ({type(exc).__name__})") from exc
    if 200 <= resp.status_code < 300:
        return resp.status_code
    retryable = resp.status_code >= 500 or resp.status_code in (408, 425, 429)
    raise ChannelError(f"webhook returned HTTP {resp.status_code}", retryable=retryable)
