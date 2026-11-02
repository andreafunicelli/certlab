"""SSH layer: strict host keys, helper-only privileged operations, connection tests."""
from app.integrations.ssh.connection import (
    SSHRemoteHost,
    connect,
    open_connection,
    set_host_concurrency_limit,
)
from app.integrations.ssh.errors import classify_exception
from app.integrations.ssh.hostkeys import host_key_info_from_openssh, scan_host_key
from app.integrations.ssh.models import (
    ConnectionStep,
    ConnectionTestReport,
    HostKeyInfo,
    SSHCredential,
    SSHTarget,
)
from app.integrations.ssh.sanitize import sanitize_output
from app.integrations.ssh.testconn import test_connection

__all__ = [
    "ConnectionStep",
    "ConnectionTestReport",
    "HostKeyInfo",
    "SSHCredential",
    "SSHRemoteHost",
    "SSHTarget",
    "classify_exception",
    "connect",
    "host_key_info_from_openssh",
    "open_connection",
    "sanitize_output",
    "scan_host_key",
    "set_host_concurrency_limit",
    "test_connection",
]
