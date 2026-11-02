"""Outbound notification channels (SMTP, webhook). Pure transport: no DB access."""
from app.integrations.notify.base import ChannelError, Message
from app.integrations.notify.smtp import send_smtp, validate_smtp_config
from app.integrations.notify.webhook import (
    build_webhook_request,
    send_webhook,
    sign_body,
    validate_webhook_config,
)

__all__ = [
    "ChannelError", "Message", "build_webhook_request", "send_smtp", "send_webhook", "sign_body",
    "validate_smtp_config", "validate_webhook_config",
]
