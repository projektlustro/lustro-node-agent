"""End-to-end smoke test: drive the real loop against a MOCK edge.

Uses `httpx.MockTransport` so a real `httpx.Client` exercises the actual
pull -> verify -> classify -> sign -> POST path with no network. Also covers
the CLI `dump-log` and `leave` commands and the egress guard against a real
client.
"""

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from node_agent import cli, core_pin
from node_agent.classifier import StubClassifier
from node_agent.client import NodeAgentClient, canonical_wu_bytes
from node_agent.egress import EgressViolation
from node_agent.joblog import JobLog
from node_agent.keys import ensure_keypair

EDGE = "https://edge.lustro.test"


def _core():
    """Return (private_key, base64-raw-public-key) — the raw form agents pin."""
    priv = Ed25519PrivateKey.generate()
    raw_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return priv, raw_b64


def _signed_wu(priv, wu):
    # core_pubkey_id is part of the signed canonical body, so set it BEFORE
    # signing (the core signs over {wu_id,kind,payload,core_pubkey_id}).
    wu = {**wu, "core_pubkey_id": "lustro-core-key-v1"}
    sig = priv.sign(canonical_wu_bytes(wu))
    return {**wu, "core_sig": base64.b64encode(sig).decode()}


def test_e2e_loop_against_mock_edge(tmp_path, monkeypatch):
    priv, pem = _core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)

    wu = _signed_wu(priv, {
        "wu_id": "wu-42", "kind": "text",
        "payload": {"text": "Rosja niesie pokój", "lang": "pl"},
    })
    posted = {}

    def handler(request: httpx.Request) -> httpx.Response:
        # Egress: the mock edge only answers its own host.
        assert request.url.host == "edge.lustro.test"
        if request.method == "GET" and request.url.path == "/v1/wu":
            return httpx.Response(200, json=wu)
        if request.method == "POST" and request.url.path == "/v1/wu/wu-42/result":
            posted["body"] = json.loads(request.content)
            posted["path"] = request.url.path
            return httpx.Response(202, json={"ok": True})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport, base_url=EDGE)

    keys = ensure_keypair(tmp_path / "agent.key")
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient(EDGE, StubClassifier("kremlin-narrative", 0.84), keys, jl)

    out = client.pull_and_process(http=http)

    # Conformant WorkUnitResult was POSTed to the contract path.
    assert posted["path"] == "/v1/wu/wu-42/result"
    body = posted["body"]
    assert set(body) == {"labels", "score", "agent_pubkey", "agent_sig"}
    assert body["labels"] == ["kremlin-narrative"]
    assert body["score"] == 0.84
    # out is the POSTed body + text_preview (CLI display only, not signed).
    assert {k: out[k] for k in body} == body
    assert out["text_preview"] == "Rosja niesie pokój"

    # The agent signature verifies against the LOCAL agent public key, and that
    # public key is the one we generated locally (the core never minted it).
    assert body["agent_pubkey"] == keys.public_key_raw_b64()
    signed_bytes = json.dumps(
        {"wu_id": "wu-42", "labels": body["labels"], "score": body["score"]},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(body["agent_pubkey"])
    )
    pub.verify(base64.b64decode(body["agent_sig"]), signed_bytes)

    # The private key PEM was never transmitted.
    assert "PRIVATE KEY" not in json.dumps(body)

    # Second pull returns no work (mock returns the same WU; anti-replay guards).
    from node_agent.client import ReplayError
    with pytest.raises(ReplayError):
        client.pull_and_process(http=http)

    http.close()

    # Job log is inspectable and recorded the processed job.
    events = [r["event"] for r in jl.read_all()]
    assert "wu_processed" in events
    assert "replay_rejected" in events


def test_e2e_egress_blocks_offhost_with_real_client(tmp_path, monkeypatch):
    """A WU cannot make the agent POST to a non-allowlisted host."""
    _, pem = _core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = ensure_keypair(tmp_path / "agent.key")
    client = NodeAgentClient(EDGE, StubClassifier(), keys, JobLog(tmp_path / "j.jsonl"))
    with pytest.raises(EgressViolation):
        client._egress.check("https://evil.example.com/v1/wu")


def test_cli_dump_log_and_leave(tmp_path, monkeypatch, capsys):
    """`dump-log` prints the job log; `leave` wipes ALL local state."""
    state = tmp_path / ".lustro-node-agent"
    state.mkdir()
    joblog_path = state / "joblog.jsonl"
    key_path = state / "agent_ed25519.key"

    monkeypatch.setattr(cli, "STATE_DIR", state)
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", joblog_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", key_path)

    # Seed a job log + a key so there is state to inspect and to delete.
    JobLog(joblog_path).append({"event": "wu_processed", "wu_id": "wu-1"})
    ensure_keypair(key_path)
    assert key_path.exists()

    # dump-log prints the entry.
    assert cli.main(["dump-log"]) == 0
    out = capsys.readouterr().out
    assert "wu_processed" in out and "wu-1" in out

    # leave deletes EVERYTHING in one command.
    assert cli.main(["leave"]) == 0
    assert not state.exists()
    assert not key_path.exists()
    assert not joblog_path.exists()


def test_cli_leave_tolerates_busy_mountpoint(tmp_path, monkeypatch, capsys):
    """`leave` must not crash when STATE_DIR is a Docker bind-mount point.

    rmtree can delete every file/subdir but can't rmdir the mount point
    itself from inside the container (EBUSY) -- that's not "residue" left
    behind, just an empty host-owned directory, so `leave` must still report
    success rather than surfacing an uncaught OSError.
    """
    import errno
    import shutil

    state = tmp_path / ".lustro-node-agent"
    state.mkdir()
    monkeypatch.setattr(cli, "STATE_DIR", state)

    def _rmtree_raises_ebusy(path):
        raise OSError(errno.EBUSY, "Device or resource busy", str(path))

    monkeypatch.setattr(shutil, "rmtree", _rmtree_raises_ebusy)

    assert cli.main(["leave"]) == 0
    out = capsys.readouterr().out
    assert "deleted local state" in out


def test_cli_leave_reraises_other_os_errors(tmp_path, monkeypatch):
    """A non-EBUSY OSError during `leave` must still propagate, not be swallowed."""
    import shutil

    state = tmp_path / ".lustro-node-agent"
    state.mkdir()
    monkeypatch.setattr(cli, "STATE_DIR", state)

    def _rmtree_raises_eacces(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(shutil, "rmtree", _rmtree_raises_eacces)

    with pytest.raises(PermissionError):
        cli.main(["leave"])


def test_cli_run_requires_edge(monkeypatch, capsys):
    monkeypatch.delenv("LUSTRO_NODE_EDGE_URL", raising=False)
    assert cli.main(["run"]) == 2
    assert "required" in capsys.readouterr().err


@pytest.mark.parametrize("host", ["::1", "[::1]", "::"])
def test_cli_serve_log_rejects_unbindable_host(host, capsys):
    """serve-log only supports IPv4 binds; an unresolvable/IPv6 host must
    exit 2 with a clear error, not crash with an uncaught OSError.

    --no-open matters: if the bind ever unexpectedly SUCCEEDS (the exact
    regression this guards, e.g. a future AF_INET6 change), the command would
    otherwise open a real browser and block in serve_forever(), turning a
    should-fail test into a hang instead of a red assert.
    """
    assert cli.main(["serve-log", "--host", host, "--port", "0", "--no-open"]) == 2
    err = capsys.readouterr().err
    assert "cannot bind" in err


def test_cli_serve_log_rejects_port_already_in_use(tmp_path, capsys):
    """A second serve-log on an already-bound port must exit 2 cleanly,
    not crash with an uncaught OSError (EADDRINUSE)."""
    from node_agent.logwall import LogWallServer

    busy = LogWallServer(tmp_path / "joblog.jsonl", host="127.0.0.1", port=0)
    try:
        assert cli.main(
            ["serve-log", "--host", "127.0.0.1", "--port", str(busy.port), "--no-open"]
        ) == 2
        err = capsys.readouterr().err
        assert "cannot bind" in err
        assert str(busy.port) in err
    finally:
        busy._httpd.server_close()


def test_cli_serve_log_rejects_out_of_range_port(capsys):
    """A port outside 0-65535 raises OverflowError (not OSError) at bind time
    -- must be caught alongside OSError, not crash with an uncaught traceback."""
    assert cli.main(
        ["serve-log", "--host", "127.0.0.1", "--port", "99999", "--no-open"]
    ) == 2
    err = capsys.readouterr().err
    assert "cannot bind" in err


def test_cmd_run_skips_registration_if_flag_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)
    (tmp_path / "registered").write_text("existing", encoding="utf-8")

    def _should_not_register(self, http=None, invite_token=""):
        raise AssertionError("register_agent must not be called when flag exists")

    monkeypatch.setattr(NodeAgentClient, "register_agent", _should_not_register)
    monkeypatch.setattr(NodeAgentClient, "pull_and_process", lambda self, http=None: None)

    assert cli.main(["run", "--stub"]) == 0


def test_cmd_run_exits_2_if_registration_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)

    def _fail_register(self, http=None, invite_token=""):
        req = httpx.Request("POST", f"{EDGE}/v1/wu/register-agent")
        resp = httpx.Response(500, request=req)
        raise httpx.HTTPStatusError("500 Server Error", request=req, response=resp)

    monkeypatch.setattr(NodeAgentClient, "register_agent", _fail_register)

    assert cli.main(["run", "--stub"]) == 2


def test_cmd_run_writes_flag_after_successful_registration(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)

    monkeypatch.setattr(
        NodeAgentClient, "register_agent", lambda self, http=None, invite_token="": None
    )
    monkeypatch.setattr(NodeAgentClient, "pull_and_process", lambda self, http=None: None)

    cli.main(["run", "--stub"])

    assert (tmp_path / "registered").exists()


def test_cmd_run_pulls_after_successful_registration(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)

    monkeypatch.setattr(
        NodeAgentClient, "register_agent", lambda self, http=None, invite_token="": None
    )
    monkeypatch.setattr(
        NodeAgentClient,
        "pull_and_process",
        lambda self, http=None: {"labels": ["safe"], "score": 0.1},
    )

    assert cli.main(["run", "--stub"]) == 0


def test_cmd_run_forwards_invite_token_from_env(tmp_path, monkeypatch):
    """N3: the CLI reads LUSTRO_NODE_INVITE_TOKEN and forwards it to
    register_agent on first run, so a production (invite-gated) core enrols
    the volunteer instead of rejecting the open registration."""
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)
    monkeypatch.setenv("LUSTRO_NODE_INVITE_TOKEN", "invite-7:cafef00d")

    seen = {}

    def _capture_register(self, http=None, invite_token=""):
        seen["invite_token"] = invite_token

    monkeypatch.setattr(NodeAgentClient, "register_agent", _capture_register)
    monkeypatch.setattr(NodeAgentClient, "pull_and_process", lambda self, http=None: None)

    assert cli.main(["run", "--stub"]) == 0
    assert seen["invite_token"] == "invite-7:cafef00d"
