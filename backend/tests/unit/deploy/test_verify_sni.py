"""K1: the verification SNI is always a real hostname (or None), never the composite vhost string."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.integrations.contracts import ServiceType
from app.integrations.services.adapters import NginxAdapter
from app.models import DeploymentTarget
from app.services import deployment_engine as engine
from app.services import deployment_planner as planner
from app.services import deployments, discovery
from app.services.verify_sni import DERIVED_LABEL, resolve_verify_sni
from tests.fixtures.pki import make_pki
from tests.unit.deploy.conftest import FAST
from tests.unit.deploy.helpers import add_installation, add_server, add_version
from tests.unit.test_discovery_logic import FakeHost, adapter_with, ref

pytestmark = pytest.mark.usefixtures("net", "dispatched")


# --------------------------------------------------------------------------- pure resolution
def test_explicit_verify_sni_wins():
    assert resolve_verify_sni("explicit.example.com", ["a.example.com"], ["san.example.com"]) == "explicit.example.com"


def test_first_non_wildcard_server_name():
    assert resolve_verify_sni(None, ["*.example.com", "_", "~^x$", "www.example.com", "b.example.com"]) == "www.example.com"


def test_wildcard_only_uses_first_non_wildcard_san_preferring_one_the_wildcard_covers():
    assert resolve_verify_sni(None, ["*.example.com"], ["*.example.com", "other.test", "app.example.com"]) == "app.example.com"
    # no SAN is covered by the wildcard: still the first concrete DNS SAN (IP SANs are never an SNI)
    assert resolve_verify_sni(None, ["*.example.com"], ["10.0.0.1", "other.test"]) == "other.test"


def test_wildcard_only_without_san_derives_a_label_the_wildcard_matches():
    sni = resolve_verify_sni(None, ["*.example.com"])
    assert sni == f"{DERIVED_LABEL}.example.com" and "*" not in sni
    assert resolve_verify_sni(None, ["*.example.com"], ["*.example.com"]) == sni      # only wildcard SANs: derive
    assert resolve_verify_sni(None, ["mail.*"]) == f"mail.{DERIVED_LABEL}"
    assert resolve_verify_sni(None, [], None) is None


def test_nameless_means_no_sni():
    for names in ([], None, ["_"], ["-"], ["~^(?<x>.+)$"], [""]):
        assert resolve_verify_sni(None, names, ["leaf.example.com"]) is None


def test_vhost_style_strings_are_never_a_hostname():
    assert resolve_verify_sni(None, ["*.example.com:443"]) is None            # colon: not a hostname at all
    assert resolve_verify_sni(None, ["-:8443"]) is None


# --------------------------------------------------------------------------- planner
def _inst(**kw):
    base = {"verify_host": "10.0.0.5", "verify_port": 443, "listen_port": 443, "verify_sni": None, "vhost": "*.example.com:443",
                "server_names": ["*.example.com"]}
    base.update(kw)
    return SimpleNamespace(**base)


def test_verify_endpoints_never_use_the_composite_vhost():
    srv = SimpleNamespace(address="10.0.0.5", hostname="h")
    [ep] = planner.verify_endpoints_for(_inst(), srv)
    assert ep["sni"] == f"{DERIVED_LABEL}.example.com" and ep["sni"] != "*.example.com:443"
    [ep] = planner.verify_endpoints_for(_inst(), srv, ["www.example.com"])
    assert ep["sni"] == "www.example.com"
    [ep] = planner.verify_endpoints_for(_inst(vhost="-:8443", server_names=[], listen_port=8443, verify_port=None), srv)
    assert ep["sni"] is None and ep["port"] == 8443 and ep["host"] == "10.0.0.5"


# --------------------------------------------------------------------------- discovery
async def test_discovery_populates_verify_sni_with_the_same_helper():
    host = FakeHost(files={"/etc/ssl/a/fullchain.pem": b"x", "/etc/ssl/a/privkey.pem": b"k"})

    async def run(names):
        col = await discovery.collect(host, endpoint_host="10.0.0.5", ssh={"connect_timeout": 5, "discovery_roots": [],
                                      "discovery_max_depth": 4, "discovery_max_files": 100, "discovery_exclude": []},
                                      probe_fn=None, adapter_for=adapter_with([ref(names=names)], NginxAdapter))
        return next(d for d in col.items if d.service_type == ServiceType.NGINX.value)

    wild = await run(("*.example.com",))
    assert wild.verify_sni == f"{DERIVED_LABEL}.example.com" and wild.vhost.startswith("*.example.com:")
    none = await run(())
    assert none.verify_sni is None and none.verify_port == 443 and none.verify_host == "10.0.0.5"
    assert (await run(("a.example.com", "*.example.com"))).verify_sni == "a.example.com"


# --------------------------------------------------------------------------- end to end
def _deploy(db, net, operator, names, sans, *, vhost, key):
    server = add_server(db, f"sni-{key}")
    fs = net.add(server)
    old, new = make_pki(sans), make_pki(sans)
    inst = add_installation(db, server, fs, old, name=key, names=names or ["placeholder.test"])
    inst.server_names, inst.vhost, inst.verify_sni = list(names), vhost, None
    db.commit()
    version = add_version(db, new)
    job, _ = deployments.create(db, operator, f"k-{key}", {"version_id": version.id, "installation_ids": [inst.id],
                                                          "strategy": dict(FAST), "acknowledged_warnings": []})
    return job, inst, fs


def test_wildcard_only_installation_deploys_and_verifies(db, net, operator):
    job, _inst, _fs = _deploy(db, net, operator, ["*.test.local"], ["*.test.local", "www.test.local"],
                              vhost="*.test.local:8443", key="wild")
    assert engine.run_job(job.id) == "completed"
    t = db.query(DeploymentTarget).filter_by(job_id=job.id).one()
    [ep] = t.verification["endpoints"]
    assert ep["sni"] == "www.test.local" and ep["hostname_matches"] is True


def test_wildcard_only_without_san_hostname_uses_derived_label(db, net, operator):
    job, _inst, _fs = _deploy(db, net, operator, ["*.test.local"], ["*.test.local"], vhost="*.test.local:8443", key="wild2")
    assert engine.run_job(job.id) == "completed"
    t = db.query(DeploymentTarget).filter_by(job_id=job.id).one()
    assert t.verification["endpoints"][0]["sni"] == f"{DERIVED_LABEL}.test.local"


def test_nameless_installation_connects_without_sni(db, net, operator):
    job, _inst, _fs = _deploy(db, net, operator, [], ["anything.test.local"], vhost="-:8443", key="nameless")
    assert engine.run_job(job.id) == "completed"
    t = db.query(DeploymentTarget).filter_by(job_id=job.id).one()
    [ep] = t.verification["endpoints"]
    assert ep["sni"] is None and ep["reachable"] and ep["served_fingerprint"] == t.new_fingerprint


def test_required_hostnames_never_use_the_composite_vhost_label():
    from app.services.verify_sni import required_hostnames, vhost_names

    assert vhost_names("a.example.com,b.example.com:443,8443") == ["a.example.com", "b.example.com"]
    assert vhost_names("-:8443") == [] and vhost_names(None) == [] and vhost_names("plain.example.com") == ["plain.example.com"]
    assert required_hostnames(["a.example.com", "*.x.com"], "a.example.com,b.example.com:443", None) == ["a.example.com", "b.example.com"]
    assert required_hostnames([], "*.example.com:443", None) == [] and required_hostnames([], "-:8443", "v.example.com") == ["v.example.com"]
    inst = SimpleNamespace(server_names=["a.example.com"], vhost="a.example.com:443", verify_sni=None)
    assert planner.required_hostnames(inst) == ["a.example.com"]
