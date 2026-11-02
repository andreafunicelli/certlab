from __future__ import annotations

import json
import threading
import time

from app.models import DiscoveryJob, Server
from app.services import events


def _parse(frame: str):
    lines = [ln for ln in frame.strip().splitlines() if ln]
    if lines and lines[0].startswith(":"):
        return "comment", None
    ev = lines[0].removeprefix("event: ")
    return ev, json.loads(lines[1].removeprefix("data: "))


def _job(db, status="running"):
    s = Server(name="ev", hostname="ev.example.com", ssh_username="u", environment="Test")
    db.add(s)
    db.flush()
    j = DiscoveryJob(server_id=s.id, status=status)
    db.add(j)
    db.commit()
    return j


def test_sse_stream_snapshot_progress_and_end(db):
    job = _job(db)
    out: list[tuple] = []
    gen = events.sse_stream("discovery", job.id, poll_seconds=0.2, resnapshot_seconds=0.5, heartbeat_seconds=60)

    def consume():
        for frame in gen:
            out.append(_parse(frame))

    t = threading.Thread(target=consume)
    t.start()
    time.sleep(0.6)
    assert events.publish_job_event("discovery", job.id, {"type": "progress", "stage": "probe", "percent": 15})
    time.sleep(0.4)
    job.status = "completed"
    db.commit()
    t.join(timeout=10)
    assert not t.is_alive()
    kinds = [k for k, _ in out]
    assert kinds[0] == "snapshot" and kinds[-1] == "end"
    prog = [d for k, d in out if k == "progress"]
    assert prog and prog[0]["stage"] == "probe" and prog[0]["job_id"] == str(job.id) and prog[0]["kind"] == "discovery"
    assert out[-1][1]["status"] == "completed"


def test_sse_finished_job_ends_immediately_and_unknown_job_errors(db):
    job = _job(db, "completed")
    frames = [_parse(f) for f in events.sse_stream("discovery", job.id, poll_seconds=0.1)]
    assert [k for k, _ in frames] == ["snapshot", "end"]
    import uuid
    frames = [_parse(f) for f in events.sse_stream("discovery", uuid.uuid4(), poll_seconds=0.1)]
    assert frames[0][0] == "error"


def test_publish_never_raises_and_redacts(monkeypatch):
    class Boom:
        def publish(self, *a):
            raise ConnectionError("down")
    monkeypatch.setattr(events, "_client", lambda: Boom())
    assert events.publish_job_event("discovery", "x", {"password": "p"}) is False


def test_discovery_events_endpoint_streams_and_requires_auth(admin, anon, db):
    job = _job(db, "completed")
    r = admin.get(f"/api/v1/discovery-jobs/{job.id}/events")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert "event: snapshot" in r.text and "event: end" in r.text
    assert anon.get(f"/api/v1/discovery-jobs/{job.id}/events").status_code == 401
    assert admin.get("/api/v1/discovery-jobs/00000000-0000-0000-0000-000000000000/events").status_code == 404
