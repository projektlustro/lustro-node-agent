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
    assert out == body

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


def test_cli_run_requires_edge(monkeypatch, capsys):
    monkeypatch.delenv("LUSTRO_NODE_EDGE_URL", raising=False)
    assert cli.main(["run"]) == 2
    assert "required" in capsys.readouterr().err


def test_cmd_run_skips_registration_if_flag_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)
    (tmp_path / "registered").write_text("existing", encoding="utf-8")

    def _should_not_register(self, http=None):
        raise AssertionError("register_agent must not be called when flag exists")

    monkeypatch.setattr(NodeAgentClient, "register_agent", _should_not_register)
    monkeypatch.setattr(NodeAgentClient, "pull_and_process", lambda self, http=None: None)

    assert cli.main(["run", "--stub"]) == 0


def test_cmd_run_exits_2_if_registration_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)

    def _fail_register(self, http=None):
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

    monkeypatch.setattr(NodeAgentClient, "register_agent", lambda self, http=None: None)
    monkeypatch.setattr(NodeAgentClient, "pull_and_process", lambda self, http=None: None)

    cli.main(["run", "--stub"])

    assert (tmp_path / "registered").exists()


def test_cmd_run_pulls_after_successful_registration(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_KEY_PATH", tmp_path / "agent.key")
    monkeypatch.setattr(cli, "DEFAULT_JOBLOG_PATH", tmp_path / "joblog.jsonl")
    monkeypatch.setenv("LUSTRO_NODE_EDGE_URL", EDGE)

    monkeypatch.setattr(NodeAgentClient, "register_agent", lambda self, http=None: None)
    monkeypatch.setattr(
        NodeAgentClient,
        "pull_and_process",
        lambda self, http=None: {"labels": ["safe"], "score": 0.1},
    )

    assert cli.main(["run", "--stub"]) == 0
