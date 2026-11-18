"""`run --loop` behavior: bounded cadence, error backoff, consecutive-failure cap.

Loop mode exists for long-running ephemeral workers (SCW Serverless Jobs):
one process, classifier loaded once, poll-pull-sleep until the job timeout
kills it. These tests monkeypatch the real client so no network happens.
"""

import pytest

from node_agent import cli
from node_agent.client import NodeAgentClient

EDGE = "https://edge.lustro.test"


def _patch_state(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)
    (tmp_path / "registered").write_text("existing", encoding="utf-8")


def test_loop_parser_defaults():
    args = cli.build_parser().parse_args(["run"])
    assert args.loop is False
    assert args.interval == 300.0
    args = cli.build_parser().parse_args(["run", "--loop", "--interval", "7"])
    assert args.loop is True
    assert args.interval == 7.0


def test_single_run_ignores_loop_path(tmp_path, monkeypatch):
    _patch_state(tmp_path, monkeypatch)
    calls = {"pulls": 0}

    monkeypatch.setattr(
        NodeAgentClient, "pull_and_process",
        lambda self, http=None: calls.__setitem__("pulls", calls["pulls"] + 1) or None,
    )

    assert cli.main(["run", "--stub"]) == 0
    assert calls["pulls"] == 1


def test_loop_cycles_until_interrupted(tmp_path, monkeypatch):
    _patch_state(tmp_path, monkeypatch)
    calls = {"pulls": 0, "sleeps": []}

    def _no_work(self, http=None):
        calls["pulls"] += 1
        if calls["pulls"] >= 3:
            raise KeyboardInterrupt
        return None

    monkeypatch.setattr(NodeAgentClient, "pull_and_process", _no_work)
    monkeypatch.setattr(cli.time, "sleep", lambda s: calls["sleeps"].append(s))

    with pytest.raises(KeyboardInterrupt):
        cli.main(["run", "--stub", "--loop", "--interval", "5"])
    assert calls["pulls"] == 3
    assert calls["sleeps"] == [5.0, 5.0]


def test_loop_survives_transient_errors(tmp_path, monkeypatch):
    _patch_state(tmp_path, monkeypatch)
    calls = {"pulls": 0, "sleeps": []}

    def _flaky(self, http=None):
        calls["pulls"] += 1
        if calls["pulls"] == 1:
            raise ConnectionError("edge unreachable")
        if calls["pulls"] >= 2:
            raise KeyboardInterrupt
        return None

    monkeypatch.setattr(NodeAgentClient, "pull_and_process", _flaky)
    monkeypatch.setattr(cli.time, "sleep", lambda s: calls["sleeps"].append(s))

    with pytest.raises(KeyboardInterrupt):
        cli.main(["run", "--stub", "--loop", "--interval", "9"])
    assert calls["pulls"] == 2
    assert calls["sleeps"] == [9.0]


def test_loop_exits_nonzero_after_consecutive_error_cap(tmp_path, monkeypatch):
    _patch_state(tmp_path, monkeypatch)
    calls = {"pulls": 0}
    cap = cli.MAX_LOOP_ERRORS

    def _always_fails(self, http=None):
        calls["pulls"] += 1
        raise RuntimeError("poisoned edge")

    monkeypatch.setattr(NodeAgentClient, "pull_and_process", _always_fails)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)

    assert cli.main(["run", "--stub", "--loop", "--interval", "1"]) == 1
    assert calls["pulls"] == cap


def test_loop_error_counter_resets_on_success(tmp_path, monkeypatch):
    _patch_state(tmp_path, monkeypatch)
    calls = {"pulls": 0}

    def _mostly_fails(self, http=None):
        calls["pulls"] += 1
        if calls["pulls"] in (1, 2):
            raise ConnectionError("blip")
        if calls["pulls"] >= cli.MAX_LOOP_ERRORS + 2:
            raise KeyboardInterrupt
        return None

    monkeypatch.setattr(NodeAgentClient, "pull_and_process", _mostly_fails)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)

    with pytest.raises(KeyboardInterrupt):
        cli.main(["run", "--stub", "--loop", "--interval", "1"])
    assert calls["pulls"] == cli.MAX_LOOP_ERRORS + 2


def test_loop_rejects_nonpositive_interval(tmp_path, monkeypatch, capsys):
    _patch_state(tmp_path, monkeypatch)
    assert cli.main(["run", "--stub", "--loop", "--interval", "0"]) == 2
    assert "interval" in capsys.readouterr().err


def test_loop_rejects_nonpositive_exit_after_no_work(tmp_path, monkeypatch, capsys):
    _patch_state(tmp_path, monkeypatch)
    assert cli.main(
        ["run", "--stub", "--loop", "--exit-after-no-work-seconds", "0"]
    ) == 2
    assert "exit-after-no-work" in capsys.readouterr().err


def test_loop_drain_exits_after_quiet_window(tmp_path, monkeypatch):
    _patch_state(tmp_path, monkeypatch)
    calls = {"pulls": 0, "sleeps": []}

    def _no_work(self, http=None):
        calls["pulls"] += 1
        return None

    monkeypatch.setattr(NodeAgentClient, "pull_and_process", _no_work)
    monkeypatch.setattr(cli.time, "sleep", lambda s: calls["sleeps"].append(s))

    # interval=2: cycles at t=0, 2, 4 — quiet window 5s expires on the 4s check
    # (4 - 0 >= 5 is false → sleeps; next cycle 6 - 0 >= 5 → exits).
    assert cli.main(
        ["run", "--stub", "--loop", "--interval", "2",
         "--exit-after-no-work-seconds", "5"]
    ) == 0
    assert calls["pulls"] >= 3


def test_loop_drain_keeps_running_when_work_flows(tmp_path, monkeypatch):
    _patch_state(tmp_path, monkeypatch)
    calls = {"pulls": 0}

    def _always_work(self, http=None):
        calls["pulls"] += 1
        if calls["pulls"] >= 4:
            raise KeyboardInterrupt
        return {"labels": ["x"], "score": 0.5, "authority": "core", "text_preview": "t"}

    monkeypatch.setattr(NodeAgentClient, "pull_and_process", _always_work)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)

    with pytest.raises(KeyboardInterrupt):
        cli.main(
            ["run", "--stub", "--loop", "--interval", "1",
             "--exit-after-no-work-seconds", "3"]
        )
    assert calls["pulls"] == 4


def test_loop_drain_error_resets_quiet_window(tmp_path, monkeypatch):
    _patch_state(tmp_path, monkeypatch)
    calls = {"pulls": 0}

    def _flaky_then_quiet(self, http=None):
        calls["pulls"] += 1
        if calls["pulls"] % 2 == 1:
            raise ConnectionError("blip")
        if calls["pulls"] >= 8:
            raise KeyboardInterrupt
        return None

    monkeypatch.setattr(NodeAgentClient, "pull_and_process", _flaky_then_quiet)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)

    with pytest.raises(KeyboardInterrupt):
        cli.main(
            ["run", "--stub", "--loop", "--interval", "1",
             "--exit-after-no-work-seconds", "2"]
        )
    assert calls["pulls"] == 8
