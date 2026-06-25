import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from node_agent import core_pin
from node_agent.classifier import StubClassifier
from node_agent.client import NodeAgentClient, ReplayError, _canonical_wu_bytes
from node_agent.core_pin import CorePinError, verify_wu_signature
from node_agent.egress import EgressGuard, EgressViolation
from node_agent.joblog import JobLog
from node_agent.keys import AgentKeys, ensure_keypair


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
    wu = {"id": "1", "content": "x", "nonce": "n1"}
    sig = priv.sign(_canonical_wu_bytes(wu))
    # Correct key id + pem -> no raise.
    verify_wu_signature(
        _canonical_wu_bytes(wu), sig, "lustro-core-key-v1",
        pinned_key_id="lustro-core-key-v1", pinned_public_key_pem=pem,
    )


def test_core_sig_rejects_wrong_key_id():
    priv, pem = _make_core()
    wu = {"id": "1", "content": "x"}
    sig = priv.sign(_canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        verify_wu_signature(
            _canonical_wu_bytes(wu), sig, "some-other-key",
            pinned_key_id="lustro-core-key-v1", pinned_public_key_pem=pem,
        )


def test_core_sig_rejects_wrong_signing_key():
    _, pem = _make_core()
    attacker = Ed25519PrivateKey.generate()
    wu = {"id": "1", "content": "x"}
    sig = attacker.sign(_canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        verify_wu_signature(
            _canonical_wu_bytes(wu), sig, "lustro-core-key-v1",
            pinned_key_id="lustro-core-key-v1", pinned_public_key_pem=pem,
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


# --- client: anti-replay rejects repeated nonce ---

def _agent_keys(tmp_path):
    return ensure_keypair(tmp_path / "agent.key")


def _signed_wu(priv, wu):
    sig = priv.sign(_canonical_wu_bytes(wu))
    return {**wu, "core_sig": base64.b64encode(sig).decode(), "core_key_id": "lustro-core-key-v1"}


class _FakeHttp:
    def __init__(self):
        self.posts = []

    def post(self, url, json=None):
        self.posts.append((url, json))

        class _R:
            status_code = 200

        return _R()

    def close(self):
        pass


def test_anti_replay_rejects_repeated_nonce(tmp_path, monkeypatch):
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_PEM", pem)

    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient("https://edge.example.com", StubClassifier("bad", 0.9), keys, jl)

    wu = _signed_wu(priv, {"id": "wu-1", "content": "hi", "nonce": "nonce-1", "lang": "pl"})
    http = _FakeHttp()

    # First processing succeeds and posts a signed result.
    out = client.process_wu(wu, http=http)
    assert out["label"] == "bad"
    assert len(http.posts) == 1
    assert "/v1/wu/wu-1/result" in http.posts[0][0]
    assert "agent_sig" in http.posts[0][1]

    # Replaying the same WU (same nonce/id) is rejected.
    with pytest.raises(ReplayError):
        client.process_wu(wu, http=http)


def test_client_egress_bound_to_edge(tmp_path, monkeypatch):
    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)
    # The client only ever targets the edge base URL.
    assert client._edge == "https://edge.example.com"
