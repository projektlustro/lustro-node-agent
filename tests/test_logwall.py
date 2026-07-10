"""Tests for the local, read-only log-wall dashboard (node_agent/logwall.py).

Covers the endpoints, the live SSE tail, and the regressions an adversarial
review found in the first implementation pass:
  - SSE must NOT replay existing history on connect (would duplicate events
    and throttle replay at SSE_INTERVAL on every reconnect).
  - An idle log must still emit a heartbeat so dead clients are detected and
    release their slot instead of exhausting MAX_SSE_CLIENTS forever.
  - The dashboard is read-only on disk: it must never resurrect
    ~/.lustro-node-agent style state for a joblog whose directory is gone
    (e.g. right after `node-agent leave`).
  - A DNS-name Host header must be rejected on both a loopback bind and a
    wildcard (0.0.0.0) bind, while an IP-literal Host stays allowed
    (DNS-rebinding guard).
  - A fresh agent's very first record must not be dropped from the live tail.
  - A corrupt joblog line must not crash /api/log.
  - The page must never render log content via innerHTML.
"""

import http.client
import json
import threading
import time

import httpx
import pytest

from node_agent import logwall
from node_agent.joblog import JobLog


@pytest.fixture
def running_server(tmp_path):
    joblog_path = tmp_path / "joblog.jsonl"
    server = logwall.LogWallServer(joblog_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.port}", joblog_path
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _collect_sse(base, count, timeout=5):
    """Collect up to `count` non-comment SSE data payloads."""
    events = []
    with httpx.stream("GET", f"{base}/events", timeout=timeout) as resp:
        for line in resp.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[len("data: "):]))
                if len(events) >= count:
                    break
    return events


def test_logwall_html_and_api(running_server):
    base, joblog = running_server
    JobLog(joblog).append({"event": "wu_processed", "wu_id": "wu-1"})

    r = httpx.get(f"{base}/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]

    r = httpx.get(f"{base}/api/log")
    assert r.status_code == 200
    assert r.json()[0]["wu_id"] == "wu-1"

    r = httpx.get(f"{base}/api/log?event=no_work")
    assert r.json() == []

    r = httpx.get(f"{base}/nonexistent")
    assert r.status_code == 404


def test_logwall_rejects_write_methods(running_server):
    base, _ = running_server
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        r = httpx.request(method, f"{base}/api/log")
        assert r.status_code == 405


def test_logwall_never_uses_innerhtml_for_log_data(running_server):
    """PAGE_HTML must render log fields via textContent/createElement only.

    Regression guard for the XSS risk flagged before implementation: the
    payload field originates from signed work units and must never be piped
    through innerHTML.
    """
    base, joblog = running_server
    JobLog(joblog).append(
        {"event": "wu_processed", "wu_id": "wu-x", "payload": "<script>alert(1)</script>"}
    )
    r = httpx.get(f"{base}/")
    assert r.status_code == 200
    assert "innerHTML" not in r.text
    assert "textContent" in r.text

    # The static page never embeds log content server-side.
    assert "<script>alert(1)</script>" not in r.text


def test_logwall_preserves_file_permissions(running_server):
    base, joblog = running_server
    JobLog(joblog).append({"event": "x"})
    assert joblog.stat().st_mode & 0o777 == 0o600
    assert joblog.parent.stat().st_mode & 0o777 == 0o700


def test_logwall_api_limits_validated(running_server):
    base, _ = running_server
    assert httpx.get(f"{base}/api/log?limit=0").status_code == 400
    assert httpx.get(f"{base}/api/log?limit=-1").status_code == 400
    assert httpx.get(f"{base}/api/log?limit=10000").status_code == 400
    assert httpx.get(f"{base}/api/log?limit=abc").status_code == 400


def test_logwall_readonly_does_not_recreate_state(tmp_path):
    """A GET must not resurrect a joblog directory that doesn't exist.

    Regression test: `node-agent leave` deletes ALL local state in one
    command; a dashboard left running in another terminal must not undo that
    by mkdir'ing the directory back into existence on the next request.
    """
    missing_dir = tmp_path / "not_created_yet"
    joblog_path = missing_dir / "joblog.jsonl"
    server = logwall.LogWallServer(joblog_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.port}"
        r = httpx.get(f"{base}/api/log")
        assert r.status_code == 200
        assert r.json() == []
        assert not missing_dir.exists()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _request_with_host(port, host_header):
    conn = http.client.HTTPConnection("127.0.0.1", port)
    try:
        conn.putrequest("GET", "/api/log", skip_host=True)
        conn.putheader("Host", host_header)
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def test_logwall_host_header_rejected(running_server):
    """A DNS-name Host header is refused; an IP-literal Host is allowed."""
    base, _ = running_server
    port = int(base.rsplit(":", 1)[1])
    assert _request_with_host(port, "evil.example:1234") == 403
    assert _request_with_host(port, "127.0.0.1:1234") == 200


def test_logwall_host_header_rejected_on_wildcard_bind(tmp_path):
    """DNS-rebinding guard must also hold on a 0.0.0.0 bind.

    Regression test: this is the documented Docker path (`serve-log --host
    0.0.0.0` behind `-p 127.0.0.1:8787:8787`). An earlier fix only enforced
    the guard on a loopback bind and returned True unconditionally for any
    wildcard bind, silently disabling it on exactly the config the README
    recommends.
    """
    joblog_path = tmp_path / "joblog.jsonl"
    server = logwall.LogWallServer(joblog_path, host="0.0.0.0", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert _request_with_host(server.port, "evil.example:1234") == 403
        assert _request_with_host(server.port, "127.0.0.1:1234") == 200
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_logwall_sse_does_not_replay_history(running_server):
    """Connecting to /events must not replay existing records.

    Regression test for the BLOCKER an adversarial review found: the first
    implementation followed the file from byte 0, so every connect (and every
    browser auto-reconnect) replayed the entire history, duplicating events
    already shown and throttling replay at SSE_INTERVAL.
    """
    base, joblog = running_server
    JobLog(joblog).append({"event": "wu_processed", "wu_id": "wu-old-1"})
    JobLog(joblog).append({"event": "wu_processed", "wu_id": "wu-old-2"})

    events = []

    def collect():
        events.extend(_collect_sse(base, count=1, timeout=10))

    t = threading.Thread(target=collect, daemon=True)
    t.start()
    time.sleep(0.5)
    JobLog(joblog).append({"event": "wu_processed", "wu_id": "wu-new"})
    t.join(timeout=10)

    assert len(events) == 1
    assert events[0]["wu_id"] == "wu-new"


def test_logwall_sse_heartbeat_on_idle(running_server):
    """An idle log must still produce SSE traffic so dead clients are noticed.

    Regression test for the MAJOR finding: without a heartbeat, an idle
    handler thread only detects a closed socket on its next *write*, which
    never happens on an idle log, so repeated reconnects could exhaust
    MAX_SSE_CLIENTS permanently.
    """
    base, _ = running_server
    with httpx.stream("GET", f"{base}/events", timeout=5) as resp:
        line = next(line for line in resp.iter_lines() if line.strip())
    assert line.startswith(":")


def test_logwall_sse_delivers_first_record_on_fresh_agent(tmp_path):
    """The very first record from a never-run-before agent must not be lost.

    Regression test: a fresh joblog file doesn't exist yet when the SSE client
    connects. `since_end` must not skip past the first record once the file is
    created — a naive "seek to EOF after the file appears" would silently drop
    exactly the first job a brand-new volunteer processes.
    """
    joblog_path = tmp_path / "joblog.jsonl"
    server = logwall.LogWallServer(joblog_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.port}"
        events = []

        def collect():
            events.extend(_collect_sse(base, count=1, timeout=10))

        t = threading.Thread(target=collect, daemon=True)
        t.start()
        time.sleep(0.5)
        JobLog(joblog_path).append({"event": "wu_processed", "wu_id": "wu-first"})
        t.join(timeout=10)

        assert len(events) == 1
        assert events[0]["wu_id"] == "wu-first"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_logwall_api_survives_corrupt_line(running_server):
    """A corrupt line in the joblog must not crash /api/log.

    Regression test: read_all() previously called json.loads() directly and
    raised JSONDecodeError on any malformed line, taking down /api/log (and
    dump-log) entirely instead of surfacing a _parse_error marker like the
    live SSE tail does.
    """
    base, joblog_path = running_server
    JobLog(joblog_path).append({"event": "ok1"})
    with joblog_path.open("a", encoding="utf-8") as f:
        f.write("not valid json\n")
    JobLog(joblog_path).append({"event": "ok2"})

    r = httpx.get(f"{base}/api/log")
    assert r.status_code == 200
    events = [row.get("event") for row in r.json()]
    assert "ok1" in events
    assert "ok2" in events
    assert "_parse_error" in events
