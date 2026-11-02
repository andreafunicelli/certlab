"""Fixtures for tests against the disposable local target (infra/test-target/setup-local.sh)."""
from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest

from app.integrations.ssh import SSHCredential, SSHTarget, connect

REPO = Path(__file__).resolve().parents[3]
STATE = Path("/var/lib/cdp-test")
CERTS = Path("/etc/ssl/cdp-test")
SCRATCH = CERTS / "scratch"
SSH_PORT = 2222


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/integration" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.integration)


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session", autouse=True)
def target_up():
    """Bring the local target up if it is not (idempotent), skip everything if impossible."""
    if all(_port_open(p) for p in (SSH_PORT, 8443, 9443, 10443)) and (STATE / "id_ed25519").exists():
        return
    script = REPO / "infra/test-target/setup-local.sh"
    try:
        subprocess.run(["bash", str(script)], check=True, capture_output=True, timeout=300)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"local test target unavailable: {exc}")


@pytest.fixture(scope="session")
def host_pub() -> str:
    return " ".join((STATE / "ssh_host_ed25519_key.pub").read_text().split()[:2])


@pytest.fixture(scope="session")
def credential() -> SSHCredential:
    return SSHCredential((STATE / "id_ed25519").read_bytes(), None)


@pytest.fixture(scope="session")
def enc_credential() -> SSHCredential:
    return SSHCredential((STATE / "id_rsa_enc").read_bytes(), (STATE / "id_rsa_enc.passphrase").read_text())


@pytest.fixture(scope="session")
def unauthorized_credential() -> SSHCredential:
    return SSHCredential((STATE / "id_ed25519_unauthorized").read_bytes(), None)


@pytest.fixture
def target(host_pub) -> SSHTarget:
    return SSHTarget("127.0.0.1", SSH_PORT, "cdpdeploy", host_pub, connect_timeout=5, command_timeout=30)


@pytest.fixture
async def host(target, credential):
    async with connect(target, credential) as h:
        yield h


@pytest.fixture
def scratch():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    yield SCRATCH
    for p in SCRATCH.iterdir():
        if p.is_dir() and not p.is_symlink():
            subprocess.run(["rm", "-rf", str(p)], check=False)
        else:
            p.unlink()
