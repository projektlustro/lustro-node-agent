"""End-to-end tests for the node-agent loop, against the FROZEN wu contract.

Contract (packages/shared-types):
  WorkUnit:        wu_id, kind ("text"|"media"), payload, core_pubkey_id, core_sig
  WorkUnitResult:  labels[], score, agent_pubkey, agent_sig

Invariants asserted here:
  - the agent private key is generated LOCALLY and never returned/transmitted;
  - the core cannot mint the agent key;
  - pinned-key verification works (key-id mismatch and bad-sig both reject);
  - anti-replay rejects a repeated wu_id / nonce;
  - egress refuses a non-allowlisted host;
  - the job log appends every job.
"""

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from node_agent import core_pin
from node_agent.classifier import StubClassifier
from node_agent.client import NodeAgentClient, ReplayError, canonical_wu_bytes
from node_agent.core_pin import CorePinError, verify_wu_signature
from node_agent.egress import EgressGuard, EgressViolation
from node_agent.joblog import JobLog
from node_agent.keys import ensure_keypair


# --- keys: generated locally, private key never returned by a public function ---

def test_keypair_generated_locally_and_private_never_exposed(tmp_path):
    key_path = tmp_path / "agent.key"
    keys = ensure_keypair(key_path)

    # Key file exists on the local machine.
    assert key_path.exists()

    # Public key is exposed.
    assert b"PUBLIC KEY" in keys.public_key_pem()

    # No public attribute/method returns the private key object or bytes.
    public_names = [n for n in dir(keys) if not n.startswith("_")]
    for name in public_names:
        attr = getattr(keys, name)
        if callable(attr):
            continue
        assert not isinstance(attr, Ed25519PrivateKey)
    # Signing works (proves the private key is held internally) without leaking.
    sig = keys.sign(b"hello")
    keys.public_key().verify(sig, b"hello")


def test_private_key_bytes_are_never_returned_by_any_public_method(tmp_path):
    """Belt-and-braces: no public method returns the private key (PEM or raw)."""
    keys = ensure_keypair(tmp_path / "agent.key")
    for name in [n for n in dir(keys) if not n.startswith("_")]:
        attr = getattr(keys, name)
        try:
            val = attr() if callable(attr) else attr
        except TypeError:
            continue  # method needs args (e.g. sign); not a key accessor
        if isinstance(val, (bytes, bytearray)):
            assert b"PRIVATE KEY" not in bytes(val)
        assert not isinstance(val, Ed25519PrivateKey)


def test_core_cannot_mint_the_agent_key(tmp_path, monkeypatch):
    """The agent key is local; nothing in a (core-signed) WU can set it.

    We feed a WU that tries to smuggle an attacker pubkey and assert the posted
    result still carries the LOCALLY-generated agent pubkey.
    """
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = ensure_keypair(tmp_path / "agent.key")
    local_pub = keys.public_key_pem().decode()

    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier("benign", 0.1), keys,
        JobLog(tmp_path / "joblog.jsonl"),
    )
    attacker_key = Ed25519PrivateKey.generate()
    attacker_pub = attacker_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    # Smuggle the attacker pubkey INSIDE the (validly) core-signed WU, so the
    # core itself is trying to dictate the agent key. The agent must ignore it.
    wu = _signed_wu(priv, {
        "wu_id": "wu-x", "kind": "text", "payload": {"text": "hi"},
        "agent_pubkey": attacker_pub,
    })
    http = _FakeHttp()
    out = client.process_wu(wu, http=http)
    assert out["agent_pubkey"] == local_pub
    assert out["agent_pubkey"] != attacker_pub


def test_private_key_file_permissions(tmp_path):
    key_path = tmp_path / "agent.key"
    ensure_keypair(key_path)
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600


# --- core_pin: rejects wrong pinned key / bad sig ---

def _make_core():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def test_core_sig_verifies_with_pinned_key():
    priv, pem = _make_core()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"}}
    sig = priv.sign(canonical_wu_bytes(wu))
    verify_wu_signature(
        canonical_wu_bytes(wu), sig, "lustro-core-key-v1",
        pinned_key_id="lustro-core-key-v1", pinned_public_key_pem=pem,
    )


def test_core_sig_rejects_wrong_key_id():
    priv, pem = _make_core()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"}}
    sig = priv.sign(canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        verify_wu_signature(
            canonical_wu_bytes(wu), sig, "some-other-key",
            pinned_key_id="lustro-core-key-v1", pinned_public_key_pem=pem,
        )


def test_core_sig_rejects_wrong_signing_key():
    _, pem = _make_core()
    attacker = Ed25519PrivateKey.generate()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"}}
    sig = attacker.sign(canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        verify_wu_signature(
            canonical_wu_bytes(wu), sig, "lustro-core-key-v1",
            pinned_key_id="lustro-core-key-v1", pinned_public_key_pem=pem,
        )


def test_core_sig_fails_closed_with_no_pinned_key():
    priv, _ = _make_core()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"}}
    sig = priv.sign(canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        verify_wu_signature(
            canonical_wu_bytes(wu), sig, "lustro-core-key-v1",
            pinned_key_id="lustro-core-key-v1", pinned_public_key_pem=b"",
        )


# --- egress: refuses non-allowlisted host ---

def test_egress_allows_allowlisted_host():
    g = EgressGuard("https://edge.example.com")
    assert g.check("https://edge.example.com/v1/wu") == "https://edge.example.com/v1/wu"


def test_egress_refuses_other_host():
    g = EgressGuard("https://edge.example.com")
    with pytest.raises(EgressViolation):
        g.check("https://evil.example.com/steal")


def test_egress_refuses_scheme_mismatch():
    g = EgressGuard("https://edge.example.com")
    with pytest.raises(EgressViolation):
        g.check("http://edge.example.com/v1/wu")


# --- joblog: appends ---

def test_joblog_appends(tmp_path):
    jl = JobLog(tmp_path / "joblog.jsonl")
    jl.append({"event": "a", "wu_id": "1"})
    jl.append({"event": "b", "wu_id": "2"})
    rows = jl.read_all()
    assert len(rows) == 2
    assert rows[0]["event"] == "a"
    assert rows[1]["wu_id"] == "2"
    assert all("ts" in r for r in rows)


# --- client: full loop + anti-replay ---

def _agent_keys(tmp_path):
    return ensure_keypair(tmp_path / "agent.key")


def _signed_wu(priv, wu):
    sig = priv.sign(canonical_wu_bytes(wu))
    return {
        **wu,
        "core_sig": base64.b64encode(sig).decode(),
        "core_pubkey_id": "lustro-core-key-v1",
    }


class _FakeHttp:
    def __init__(self, wu=None):
        self.posts = []
        self.gets = []
        self._wu = wu

    def get(self, url):
        self.gets.append(url)
        wu = self._wu

        class _R:
            status_code = 200 if wu is not None else 204

            @staticmethod
            def json():
                return wu

        return _R()

    def post(self, url, json=None):
        self.posts.append((url, json))

        class _R:
            status_code = 200

        return _R()

    def close(self):
        pass


def test_full_loop_pull_verify_classify_sign_post(tmp_path, monkeypatch):
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier("disinfo", 0.91), keys, jl
    )

    wu = _signed_wu(priv, {
        "wu_id": "wu-1", "kind": "text", "payload": {"text": "hi", "lang": "pl"},
    })
    http = _FakeHttp(wu=wu)

    out = client.pull_and_process(http=http)

    # The result body conforms to the FROZEN WorkUnitResult contract.
    assert set(out) == {"labels", "score", "agent_pubkey", "agent_sig"}
    assert out["labels"] == ["disinfo"]
    assert out["score"] == 0.91
    assert out["agent_pubkey"] == keys.public_key_pem().decode()

    # The agent signature verifies against the agent's local public key.
    signed_bytes = json.dumps(
        {"wu_id": "wu-1", "labels": out["labels"], "score": out["score"]},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    pub: Ed25519PublicKey = serialization.load_pem_public_key(
        out["agent_pubkey"].encode()
    )
    pub.verify(base64.b64decode(out["agent_sig"]), signed_bytes)

    # Pulled + posted on the contract paths.
    assert http.gets == ["https://edge.example.com/v1/wu"]
    assert http.posts[0][0] == "https://edge.example.com/v1/wu/wu-1/result"

    # Job log recorded the processed job.
    events = [r["event"] for r in jl.read_all()]
    assert "wu_processed" in events


def test_pull_returns_none_when_no_work(tmp_path, monkeypatch):
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "joblog.jsonl"),
    )
    http = _FakeHttp(wu=None)  # 204 No Content
    assert client.pull_and_process(http=http) is None
    assert http.posts == []


def test_anti_replay_rejects_repeated_wu_id(tmp_path, monkeypatch):
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)

    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier("bad", 0.9), keys, jl
    )

    wu = _signed_wu(priv, {
        "wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"},
    })
    http = _FakeHttp()

    out = client.process_wu(wu, http=http)
    assert out["labels"] == ["bad"]
    assert len(http.posts) == 1

    with pytest.raises(ReplayError):
        client.process_wu(wu, http=http)

    events = [r["event"] for r in jl.read_all()]
    assert "replay_rejected" in events


def test_anti_replay_rejects_repeated_nonce(tmp_path, monkeypatch):
    """If a WU carries an explicit nonce, a repeated nonce is also rejected
    even when the wu_id differs (defence in depth)."""
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "joblog.jsonl"),
    )
    http = _FakeHttp()
    wu1 = _signed_wu(priv, {
        "wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"}, "nonce": "n1",
    })
    wu2 = _signed_wu(priv, {
        "wu_id": "wu-2", "kind": "text", "payload": {"text": "hi"}, "nonce": "n1",
    })
    client.process_wu(wu1, http=http)
    with pytest.raises(ReplayError):
        client.process_wu(wu2, http=http)


def test_client_rejects_unsigned_wu(tmp_path, monkeypatch):
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "joblog.jsonl"),
    )
    attacker = Ed25519PrivateKey.generate()
    base = {"wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"}}
    wu = {
        **base,
        "core_pubkey_id": "lustro-core-key-v1",
        "core_sig": base64.b64encode(
            attacker.sign(canonical_wu_bytes(base))
        ).decode(),
    }
    with pytest.raises(CorePinError):
        client.process_wu(wu, http=_FakeHttp())


def test_client_egress_bound_to_edge(tmp_path):
    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)
    assert client._edge == "https://edge.example.com"


def test_missing_core_sig_is_rejected_not_crash(tmp_path, monkeypatch):
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"),
    )
    wu = {"wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"},
          "core_pubkey_id": "lustro-core-key-v1"}  # no core_sig
    with pytest.raises(CorePinError):
        client.process_wu(wu, http=_FakeHttp())


def test_malformed_core_sig_is_rejected_not_crash(tmp_path, monkeypatch):
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"),
    )
    wu = {"wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"},
          "core_pubkey_id": "lustro-core-key-v1", "core_sig": "!!!not-base64!!!"}
    with pytest.raises(CorePinError):
        client.process_wu(wu, http=_FakeHttp())


def test_missing_wu_id_is_rejected(tmp_path, monkeypatch):
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"),
    )
    wu = _signed_wu(priv, {"kind": "text", "payload": {"text": "hi"}})  # no wu_id
    with pytest.raises(CorePinError):
        client.process_wu(wu, http=_FakeHttp())


def test_wu_not_marked_seen_when_post_fails(tmp_path, monkeypatch):
    """A transient POST failure must NOT consume the WU: a later retry succeeds."""
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier("bad", 0.9), keys,
        JobLog(tmp_path / "j.jsonl"),
    )
    wu = _signed_wu(priv, {"wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"}})

    class _FailingHttp:
        def __init__(self):
            self.calls = 0

        def post(self, url, json=None):
            self.calls += 1
            raise RuntimeError("edge 500 / network blip")

        def close(self):
            pass

    failing = _FailingHttp()
    with pytest.raises(RuntimeError):
        client.process_wu(wu, http=failing)

    # The WU was not consumed; a retry on a healthy connection now succeeds.
    ok = _FakeHttp()
    out = client.process_wu(wu, http=ok)
    assert out["labels"] == ["bad"]
    assert len(ok.posts) == 1
