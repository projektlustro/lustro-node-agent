"""Unit red tests for the persistent node-agent runtime (plan §4.1).

RED until node_agent/daemon.py exists: `run --once` claims at most one
compatible work unit and exits; heartbeat/retry; bounded concurrency.
Per-test agent state comes from the existing conftest (isolated seen path).
"""

import importlib

import pytest


def _daemon():
    return importlib.import_module("node_agent.daemon")


def test_run_once_claims_at_most_one_work_unit(tmp_path):
    daemon = _daemon()
    calls = []

    class FakeClient:
        def claim(self):
            calls.append(1)
            return {"wu_id": "l2_test", "kind": "text"}

        def process(self, wu):
            return {"ok": True}

    result = daemon.run_once(FakeClient(), state_dir=tmp_path)
    assert result.claimed == 1
    assert len(calls) == 1


def test_run_once_with_empty_queue_claims_zero(tmp_path):
    daemon = _daemon()

    class EmptyClient:
        def claim(self):
            return None

    result = daemon.run_once(EmptyClient(), state_dir=tmp_path)
    assert result.claimed == 0


def test_heartbeat_fences_on_lease_expiry(tmp_path):
    daemon = _daemon()
    with pytest.raises(daemon.LeaseLost):
        daemon.heartbeat(state_dir=tmp_path, lease_id="gone", generation=1)
