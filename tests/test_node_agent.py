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

import httpx
import pytest
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
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = ensure_keypair(tmp_path / "agent.key")
    # agent_pubkey is posted as base64 of the raw 32-byte public key.
    local_pub = keys.public_key_raw_b64()

    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier("benign", 0.1), keys,
        JobLog(tmp_path / "joblog.jsonl"),
    )
    attacker_key = Ed25519PrivateKey.generate()
    attacker_pub = base64.b64encode(
        attacker_key.public_key().public_bytes_raw()
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


def test_state_dir_0700_and_key_0600(tmp_path):
    """N-L2: after ensure_keypair the state dir is 0700 and the key file 0600."""
    state = tmp_path / ".lustro-node-agent"
    key_path = state / "agent_ed25519.key"
    ensure_keypair(key_path)
    assert state.stat().st_mode & 0o777 == 0o700
    assert key_path.stat().st_mode & 0o777 == 0o600


def test_key_write_refuses_preexisting_symlink(tmp_path):
    """N-L2: O_NOFOLLOW|O_EXCL refuses to write the key through a pre-planted
    (dangling) symlink at the key path — a symlink-attack guard."""
    import os as _os

    state = tmp_path / ".lustro-node-agent"
    state.mkdir()
    key_path = state / "agent_ed25519.key"
    # Dangling symlink: exists() is False so ensure_keypair reaches os.open,
    # where O_NOFOLLOW must refuse to follow the link.
    _os.symlink(tmp_path / "elsewhere.key", key_path)
    with pytest.raises(OSError):
        ensure_keypair(key_path)
    # Nothing was written through the link.
    assert not (tmp_path / "elsewhere.key").exists()


def test_joblog_file_permissions(tmp_path):
    """N-L2: the joblog file is created 0600 and its dir 0700."""
    state = tmp_path / ".lustro-node-agent"
    jl = JobLog(state / "joblog.jsonl")
    jl.append({"event": "x"})
    assert state.stat().st_mode & 0o777 == 0o700
    assert jl.path.stat().st_mode & 0o777 == 0o600


# --- core_pin: rejects wrong pinned key / bad sig ---

def _make_core():
    """Return (private_key, base64-raw-public-key) — the raw form agents pin."""
    priv = Ed25519PrivateKey.generate()
    raw_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return priv, raw_b64


def test_core_sig_verifies_with_pinned_key():
    priv, pem = _make_core()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"}, "core_pubkey_id": "lustro-core-key-v1"}
    sig = priv.sign(canonical_wu_bytes(wu))
    verify_wu_signature(
        canonical_wu_bytes(wu), sig, "lustro-core-key-v1",
        pinned_key_id="lustro-core-key-v1", pinned_public_key_b64=pem,
    )


def test_core_sig_rejects_wrong_key_id():
    priv, pem = _make_core()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"}, "core_pubkey_id": "lustro-core-key-v1"}
    sig = priv.sign(canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        verify_wu_signature(
            canonical_wu_bytes(wu), sig, "some-other-key",
            pinned_key_id="lustro-core-key-v1", pinned_public_key_b64=pem,
        )


def test_core_sig_rejects_wrong_signing_key():
    _, pem = _make_core()
    attacker = Ed25519PrivateKey.generate()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"}, "core_pubkey_id": "lustro-core-key-v1"}
    sig = attacker.sign(canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        verify_wu_signature(
            canonical_wu_bytes(wu), sig, "lustro-core-key-v1",
            pinned_key_id="lustro-core-key-v1", pinned_public_key_b64=pem,
        )


def test_core_sig_fails_closed_with_no_pinned_key():
    priv, _ = _make_core()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"}, "core_pubkey_id": "lustro-core-key-v1"}
    sig = priv.sign(canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        verify_wu_signature(
            canonical_wu_bytes(wu), sig, "lustro-core-key-v1",
            pinned_key_id="lustro-core-key-v1", pinned_public_key_b64="",
        )


def test_default_fails_closed_without_dev_flag_or_env(monkeypatch):
    """N-H1: with neither LUSTRO_NODE_AGENT_PINNED_KEY_B64 nor
    LUSTRO_NODE_AGENT_DEV set, a build trusts NO core key and rejects even a
    validly (dev-)signed WU — fail-closed, never fail-open on the dev key."""
    monkeypatch.delenv("LUSTRO_NODE_AGENT_PINNED_KEY_B64", raising=False)
    monkeypatch.delenv("LUSTRO_NODE_AGENT_DEV", raising=False)
    # The module constant must default empty when the dev flag is unset.
    monkeypatch.setattr(
        core_pin, "PINNED_CORE_PUBLIC_KEY_B64", core_pin._default_pinned_key_b64()
    )
    assert core_pin._effective_pinned_key() == ""

    priv, _ = _make_core()
    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"},
          "core_pubkey_id": "lustro-core-key-v1"}
    sig = priv.sign(canonical_wu_bytes(wu))
    with pytest.raises(CorePinError):
        # No explicit pinned_public_key_b64 -> falls through to the (empty)
        # effective key -> fail closed.
        verify_wu_signature(canonical_wu_bytes(wu), sig, "lustro-core-key-v1")


def test_dev_flag_activates_baked_in_dev_key(monkeypatch):
    """N-H1: with LUSTRO_NODE_AGENT_DEV=1 (and no env override), the baked-in
    dev key becomes the effective pinned key and verifies a dev-signed WU.

    The dev *private* key is not in this public repo, so we pin a controlled
    keypair onto the dev-key slot to exercise the gating branch faithfully."""
    monkeypatch.delenv("LUSTRO_NODE_AGENT_PINNED_KEY_B64", raising=False)
    monkeypatch.setenv("LUSTRO_NODE_AGENT_DEV", "1")
    priv, raw_b64 = _make_core()
    monkeypatch.setattr(core_pin, "_DEV_CORE_PUBLIC_KEY_B64", raw_b64)
    monkeypatch.setattr(
        core_pin, "PINNED_CORE_PUBLIC_KEY_B64", core_pin._default_pinned_key_b64()
    )
    assert core_pin._effective_pinned_key() == raw_b64

    wu = {"wu_id": "1", "kind": "text", "payload": {"text": "x"},
          "core_pubkey_id": "lustro-core-key-v1"}
    sig = priv.sign(canonical_wu_bytes(wu))
    verify_wu_signature(canonical_wu_bytes(wu), sig, "lustro-core-key-v1")


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
    # core_pubkey_id is part of the signed canonical body, so set it BEFORE
    # signing (the core signs over {wu_id,kind,payload,core_pubkey_id}).
    wu = {**wu, "core_pubkey_id": "lustro-core-key-v1"}
    sig = priv.sign(canonical_wu_bytes(wu))
    return {**wu, "core_sig": base64.b64encode(sig).decode()}


class _StreamCtx:
    """Minimal stand-in for the httpx.Client.stream() context manager."""

    def __init__(self, status_code, body_bytes):
        self.status_code = status_code
        self._body = body_bytes

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_bytes(self):
        yield self._body


class _FakeHttp:
    def __init__(self, wu=None):
        self.posts = []
        self.gets = []
        self._wu = wu

    def stream(self, method, url):
        self.gets.append(url)
        wu = self._wu
        if wu is None:
            return _StreamCtx(204, b"")
        return _StreamCtx(200, json.dumps(wu).encode())

    def post(self, url, json=None):
        self.posts.append((url, json))

        class _R:
            status_code = 200

            @staticmethod
            def raise_for_status():
                pass

        return _R()

    def close(self):
        pass


def test_full_loop_pull_verify_classify_sign_post(tmp_path, monkeypatch):
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
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

    # The result body conforms to the FROZEN WorkUnitResult contract +
    # text_preview (added for CLI display, not part of the signed contract).
    assert set(out) == {"labels", "score", "agent_pubkey", "agent_sig", "text_preview"}
    assert out["labels"] == ["disinfo"]
    assert out["score"] == 0.91
    # agent_pubkey is base64 of the raw 32-byte public key (core wire format).
    assert out["agent_pubkey"] == keys.public_key_raw_b64()

    # The agent signature verifies against the agent's local public key.
    signed_bytes = json.dumps(
        {"wu_id": "wu-1", "labels": out["labels"], "score": out["score"]},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(out["agent_pubkey"])
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
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
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
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)

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
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
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


def test_anti_replay_persists_across_restart(tmp_path, monkeypatch):
    """N-M1: a wu_id processed by one client is rejected by a FRESH client on
    the same seen_path — the cross-restart replay the in-memory set misses."""
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    seen_path = tmp_path / "seen.jsonl"
    wu = _signed_wu(priv, {"wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"}})

    client_a = NodeAgentClient(
        "https://edge.example.com", StubClassifier("bad", 0.9), keys,
        JobLog(tmp_path / "a.jsonl"), seen_path=seen_path,
    )
    out = client_a.process_wu(wu, http=_FakeHttp())
    assert out["labels"] == ["bad"]
    assert seen_path.exists()

    # A brand-new client (process restart) with no in-memory state, same store.
    client_b = NodeAgentClient(
        "https://edge.example.com", StubClassifier("bad", 0.9), keys,
        JobLog(tmp_path / "b.jsonl"), seen_path=seen_path,
    )
    with pytest.raises(ReplayError):
        client_b.process_wu(wu, http=_FakeHttp())


def test_anti_replay_persists_nonce_across_restart(tmp_path, monkeypatch):
    """N-M1: an explicit nonce is also persisted and blocks a restart replay."""
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    seen_path = tmp_path / "seen.jsonl"
    wu1 = _signed_wu(priv, {
        "wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"}, "nonce": "n1",
    })
    wu2 = _signed_wu(priv, {
        "wu_id": "wu-2", "kind": "text", "payload": {"text": "hi"}, "nonce": "n1",
    })
    client_a = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "a.jsonl"), seen_path=seen_path,
    )
    client_a.process_wu(wu1, http=_FakeHttp())

    client_b = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "b.jsonl"), seen_path=seen_path,
    )
    with pytest.raises(ReplayError):
        client_b.process_wu(wu2, http=_FakeHttp())


def test_seen_store_permissions(tmp_path, monkeypatch):
    """N-M1: the seen store dir is 0700 and the file 0600."""
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    seen_dir = tmp_path / "state"
    seen_path = seen_dir / "seen.jsonl"
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier("bad", 0.9), keys,
        JobLog(tmp_path / "a.jsonl"), seen_path=seen_path,
    )
    client.process_wu(
        _signed_wu(priv, {"wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"}}),
        http=_FakeHttp(),
    )
    assert seen_dir.stat().st_mode & 0o777 == 0o700
    assert seen_path.stat().st_mode & 0o777 == 0o600


def test_client_rejects_unsigned_wu(tmp_path, monkeypatch):
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "joblog.jsonl"),
    )
    attacker = Ed25519PrivateKey.generate()
    base = {
        "wu_id": "wu-1", "kind": "text", "payload": {"text": "hi"},
        "core_pubkey_id": "lustro-core-key-v1",
    }
    wu = {
        **base,
        "core_sig": base64.b64encode(
            attacker.sign(canonical_wu_bytes(base))
        ).decode(),
    }
    with pytest.raises(CorePinError):
        client.process_wu(wu, http=_FakeHttp())


def test_oversized_wu_text_is_truncated_before_classify(tmp_path, monkeypatch):
    """N-M2: a 1 MB `text` field is capped at MAX_WU_TEXT_LEN before it ever
    reaches the classifier, and process_wu still completes."""
    from node_agent.client import MAX_WU_TEXT_LEN

    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)

    seen_text = {}

    class _CapturingClassifier:
        def classify(self, text, lang=None):
            seen_text["len"] = len(text)
            return StubClassifier("bad", 0.9).classify(text, lang)

    client = NodeAgentClient(
        "https://edge.example.com", _CapturingClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"), seen_path=tmp_path / "seen.jsonl",
    )
    big = "x" * (1024 * 1024)
    wu = _signed_wu(priv, {"wu_id": "wu-big", "kind": "text", "payload": {"text": big}})

    out = client.process_wu(wu, http=_FakeHttp())

    assert out["labels"] == ["bad"]
    assert seen_text["len"] == MAX_WU_TEXT_LEN
    assert seen_text["len"] < len(big)


def test_oversized_response_refused_before_parse(tmp_path, monkeypatch):
    """N-M2: an edge response whose actual streamed body exceeds the cap is
    refused before json.loads() is called, so a hostile edge can't OOM the
    volunteer — regardless of whether it declares an (untrustworthy, and
    here deliberately absent) Content-Length header."""
    from node_agent.client import MAX_WU_RESPONSE_BYTES

    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"), seen_path=tmp_path / "seen.jsonl",
    )

    class _HugeStreamCtx:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def iter_bytes(self):
            # Stream real bytes over the cap, in chunks, with NO
            # Content-Length declared anywhere — this is exactly the
            # chunked-transfer bypass that a naive header-only check misses.
            chunk = b"a" * 65536
            sent = 0
            while sent <= MAX_WU_RESPONSE_BYTES:
                sent += len(chunk)
                yield chunk

    class _HugeHttp:
        def stream(self, method, url):
            return _HugeStreamCtx()

        def close(self):
            pass

    http = _HugeHttp()
    with pytest.raises(CorePinError):
        client.pull_and_process(http=http)


def test_client_egress_bound_to_edge(tmp_path):
    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)
    assert client._edge == "https://edge.example.com"


def test_missing_core_sig_is_rejected_not_crash(tmp_path, monkeypatch):
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
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
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
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
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"),
    )
    # No wu_id: process_wu must reject it up front (before signature checks),
    # so we don't (and can't) compute a canonical signature over it.
    wu = {
        "kind": "text", "payload": {"text": "hi"},
        "core_pubkey_id": "lustro-core-key-v1", "core_sig": "",
    }
    with pytest.raises(CorePinError):
        client.process_wu(wu, http=_FakeHttp())


def test_edge_returning_json_list_is_rejected_not_crash(tmp_path, monkeypatch):
    """N-L1: a JSON list (not object) from the edge rejects cleanly."""
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"), seen_path=tmp_path / "seen.jsonl",
    )
    http = _FakeHttp(wu=[])  # edge returns a JSON array
    with pytest.raises(CorePinError):
        client.pull_and_process(http=http)


def test_wu_missing_kind_is_rejected_not_crash(tmp_path, monkeypatch):
    """N-L1: a WU missing a signed field (kind) rejects with CorePinError, not
    a KeyError from canonical_wu_bytes."""
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"), seen_path=tmp_path / "seen.jsonl",
    )
    # Valid wu_id + core_sig present, but no `kind`: canonical_wu_bytes would
    # KeyError without the up-front field check.
    wu = {
        "wu_id": "wu-1", "payload": {"text": "hi"},
        "core_pubkey_id": "lustro-core-key-v1", "core_sig": "",
    }
    with pytest.raises(CorePinError):
        client.process_wu(wu, http=_FakeHttp())


def test_wu_not_a_dict_is_rejected_not_crash(tmp_path, monkeypatch):
    """N-L1: process_wu on a non-dict raises CorePinError, not AttributeError."""
    _, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier(), keys,
        JobLog(tmp_path / "j.jsonl"), seen_path=tmp_path / "seen.jsonl",
    )
    with pytest.raises(CorePinError):
        client.process_wu(["not", "a", "dict"], http=_FakeHttp())


def test_wu_not_marked_seen_when_post_fails(tmp_path, monkeypatch):
    """A transient POST failure must NOT consume the WU: a later retry succeeds."""
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
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


def test_non_2xx_result_leaves_wu_unseen(tmp_path, monkeypatch):
    """A 5xx response from /result must raise and leave the WU eligible for retry."""
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    client = NodeAgentClient(
        "https://edge.example.com", StubClassifier("bad", 0.9), keys,
        JobLog(tmp_path / "j.jsonl"),
    )
    wu = _signed_wu(priv, {"wu_id": "wu-500", "kind": "text", "payload": {"text": "hi"}})

    class _Http500:
        def post(self, url, json=None):
            req = httpx.Request("POST", url)
            return httpx.Response(500, request=req)

        def close(self):
            pass

    with pytest.raises(httpx.HTTPStatusError):
        client.process_wu(wu, http=_Http500())

    assert "wu-500" not in client._seen_wu_ids


def test_participant_token_syncs_accepted_work_to_dashboard(tmp_path, monkeypatch):
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    joblog = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient(
        "https://edge.example.com",
        StubClassifier("benign", 0.1),
        keys,
        joblog,
        participant_token="participant-token",
    )
    wu = _signed_wu(
        priv,
        {"wu_id": "wu-attributed", "kind": "text", "payload": {"text": "hi"}},
    )

    class _ActivityHttp:
        def __init__(self):
            self.posts = []

        def post(self, url, json=None, headers=None):
            self.posts.append((url, json, headers))

            class _R:
                status_code = 201

                @staticmethod
                def raise_for_status():
                    pass

            return _R()

        def close(self):
            pass

    http = _ActivityHttp()
    client.process_wu(wu, http=http)

    assert len(http.posts) == 2
    activity_url, activity_body, activity_headers = http.posts[1]
    assert activity_url == "https://edge.example.com/elfik/node/activity"
    assert activity_body == {
        "wu_id": "wu-attributed",
        "agent_pubkey": keys.public_key_raw_b64(),
    }
    assert activity_headers == {"Authorization": "Bearer participant-token"}
    assert "activity_synced" in [row["event"] for row in joblog.read_all()]


def test_activity_sync_failure_does_not_retry_consumed_work_unit(
    tmp_path, monkeypatch
):
    priv, pem = _make_core()
    monkeypatch.setattr(core_pin, "PINNED_CORE_PUBLIC_KEY_B64", pem)
    keys = _agent_keys(tmp_path)
    joblog = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient(
        "https://edge.example.com",
        StubClassifier("benign", 0.1),
        keys,
        joblog,
        participant_token="participant-token",
    )
    wu = _signed_wu(
        priv,
        {"wu_id": "wu-sync-fails", "kind": "text", "payload": {"text": "hi"}},
    )

    class _ActivityFails:
        def __init__(self):
            self.calls = 0

        def post(self, url, json=None, headers=None):
            self.calls += 1
            request = httpx.Request("POST", url)
            if self.calls == 1:
                return httpx.Response(202, request=request)
            return httpx.Response(503, request=request)

        def close(self):
            pass

    out = client.process_wu(wu, http=_ActivityFails())

    assert out["labels"] == ["benign"]
    assert "wu-sync-fails" in client._seen_wu_ids
    assert "activity_sync_failed" in [row["event"] for row in joblog.read_all()]


# --- register_agent ---

def test_register_agent_on_first_run(tmp_path):
    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)

    class _RegisterHttp:
        def post(self, url, json=None):
            class _R:
                status_code = 200

                @staticmethod
                def raise_for_status():
                    pass

            return _R()

        def close(self):
            pass

    client.register_agent(http=_RegisterHttp())

    events = [r["event"] for r in jl.read_all()]
    assert "agent_registered" in events
    registered_rows = [r for r in jl.read_all() if r["event"] == "agent_registered"]
    assert registered_rows[0]["agent_pubkey"] == keys.public_key_raw_b64()


def test_register_agent_non_2xx_raises(tmp_path):
    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)

    class _Register500Http:
        def post(self, url, json=None):
            req = httpx.Request("POST", url)
            return httpx.Response(500, request=req)

        def close(self):
            pass

    with pytest.raises(httpx.HTTPStatusError):
        client.register_agent(http=_Register500Http())

    events = [r["event"] for r in jl.read_all()]
    assert "agent_registered" not in events


class _CapturingHttp:
    """Records the JSON body of the register POST so tests can assert what the
    agent actually sent to the edge."""

    def __init__(self):
        self.sent_json = None

    def post(self, url, json=None):
        self.sent_json = json

        class _R:
            status_code = 200

            @staticmethod
            def raise_for_status():
                pass

        return _R()

    def close(self):
        pass


def test_register_agent_sends_invite_token_when_provided(tmp_path):
    # N3: a production core gates registration behind an invite token; the
    # agent must forward it in the register body.
    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)
    http = _CapturingHttp()

    client.register_agent(http=http, invite_token="invite-001:deadbeef")

    assert http.sent_json["agent_pubkey"] == keys.public_key_raw_b64()
    assert http.sent_json["invite_token"] == "invite-001:deadbeef"


def test_register_agent_omits_invite_token_when_absent(tmp_path):
    # Open dev/local core: no invite token -> the key must NOT appear in the
    # body at all (not sent as an empty string), so the open path is unchanged.
    keys = _agent_keys(tmp_path)
    jl = JobLog(tmp_path / "joblog.jsonl")
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)
    http = _CapturingHttp()

    client.register_agent(http=http)

    assert "invite_token" not in http.sent_json


# --- _ship_logs tests (Phase 1) ---


def _make_joblog_with_entries(tmp_path):
    """Create a joblog with entries containing text_preview and _parse_error.raw."""
    jl = JobLog(tmp_path / "joblog.jsonl")
    jl.append({"event": "wu_processed", "wu_id": "wu-1", "labels": ["disinfo"], "score": 0.9, "text_preview": "First 200 chars of scraped content"})
    jl.append({"event": "wu_processed", "wu_id": "wu-2", "labels": ["benign"], "score": 0.1, "text_preview": "Another scraped post preview"})
    jl.append({"event": "_parse_error", "raw": "<html>adversary controlled content</html>"})
    return jl


class _ShipHttpCapturing:
    """Captures POST calls to /v1/wu/node-logs."""
    def __init__(self):
        self.posts = []
        self.next_status = 202

    def post(self, url, json=None):
        self.posts.append((url, json))

        class _R:
            status_code = 202

            @staticmethod
            def raise_for_status():
                pass

        return _R()

    def close(self):
        pass


class _ShipHttp4xx:
    """Simulates a 4xx rejection from the edge."""
    def post(self, url, json=None):
        req = httpx.Request("POST", url)
        return httpx.Response(403, request=req)

    def close(self):
        pass


class _ShipHttpTransportError:
    """Simulates a transport error (connection refused)."""
    def post(self, url, json=None):
        raise httpx.ConnectError("Connection refused")

    def close(self):
        pass


def test_ship_logs_signs_batch_and_strips_content(tmp_path, monkeypatch):
    """_ship_logs signs batch_bytes, strips text_preview and _parse_error.raw before serializing."""
    keys = _agent_keys(tmp_path)
    jl = _make_joblog_with_entries(tmp_path)
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)

    # Set up offset so we ship from start
    offset_dir = tmp_path / ".lustro-node-agent"
    offset_dir.mkdir(parents=True, exist_ok=True)
    offset_file = offset_dir / "shipped.offset"
    offset_file.write_text("0")

    http = _ShipHttpCapturing()
    client._ship_logs(http=http, shipped_path=offset_file)

    assert len(http.posts) == 1
    url, body = http.posts[0]
    assert "/v1/wu/node-logs" in url

    # Body contains agent_pubkey, agent_sig, batch_bytes
    assert "agent_pubkey" in body
    assert "agent_sig" in body
    assert "batch_bytes" in body

    # Decode batch_bytes to verify content stripping
    import base64
    batch_json = json.loads(base64.b64decode(body["batch_bytes"]))

    # Verify text_preview is stripped
    for entry in batch_json:
        assert "text_preview" not in entry

    # Verify _parse_error.raw is stripped
    for entry in batch_json:
        if entry.get("event") == "_parse_error":
            assert "raw" not in entry

    # Verify signature is valid over batch_bytes
    pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(body["agent_pubkey"])
    )
    pub.verify(base64.b64decode(body["agent_sig"]), base64.b64decode(body["batch_bytes"]))


def test_ship_logs_advances_cursor_on_success(tmp_path):
    """_ship_logs advances the cursor after successful POST."""
    keys = _agent_keys(tmp_path)
    jl = _make_joblog_with_entries(tmp_path)
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)

    offset_dir = tmp_path / ".lustro-node-agent"
    offset_dir.mkdir(parents=True, exist_ok=True)
    offset_file = offset_dir / "shipped.offset"
    offset_file.write_text("0")

    http = _ShipHttpCapturing()
    client._ship_logs(http=http, shipped_path=offset_file)

    # Cursor should have advanced past all entries
    new_offset = int(offset_file.read_text())
    assert new_offset > 0


def test_ship_logs_gaps_cursor_on_4xx(tmp_path):
    """_ship_logs gaps the cursor (advances past batch) on 4xx rejection."""
    keys = _agent_keys(tmp_path)
    jl = _make_joblog_with_entries(tmp_path)
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)

    offset_dir = tmp_path / ".lustro-node-agent"
    offset_dir.mkdir(parents=True, exist_ok=True)
    offset_file = offset_dir / "shipped.offset"
    offset_file.write_text("0")

    http = _ShipHttp4xx()
    client._ship_logs(http=http, shipped_path=offset_file)

    # Cursor should have advanced past the failed batch (gap)
    new_offset = int(offset_file.read_text())
    assert new_offset > 0


def test_ship_logs_does_not_advance_cursor_on_transport_error(tmp_path):
    """_ship_logs does NOT advance cursor on transport error."""
    keys = _agent_keys(tmp_path)
    jl = _make_joblog_with_entries(tmp_path)
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)

    offset_dir = tmp_path / ".lustro-node-agent"
    offset_dir.mkdir(parents=True, exist_ok=True)
    offset_file = offset_dir / "shipped.offset"
    offset_file.write_text("0")

    http = _ShipHttpTransportError()
    client._ship_logs(http=http, shipped_path=offset_file)

    # Cursor should NOT have advanced
    new_offset = int(offset_file.read_text())
    assert new_offset == 0


def test_ship_logs_canonical_json_format(tmp_path):
    """_ship_logs uses canonical JSON: sort_keys, compact separators, ensure_ascii=False."""
    keys = _agent_keys(tmp_path)
    jl = _make_joblog_with_entries(tmp_path)
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)

    offset_dir = tmp_path / ".lustro-node-agent"
    offset_dir.mkdir(parents=True, exist_ok=True)
    offset_file = offset_dir / "shipped.offset"
    offset_file.write_text("0")

    http = _ShipHttpCapturing()
    client._ship_logs(http=http, shipped_path=offset_file)

    _, body = http.posts[0]
    batch_json = json.loads(base64.b64decode(body["batch_bytes"]))

    # Re-serialize canonically and verify byte-for-byte match
    expected_bytes = json.dumps(batch_json, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    actual_bytes = base64.b64decode(body["batch_bytes"])
    assert actual_bytes == expected_bytes


def test_ship_logs_best_effort_never_raises(tmp_path):
    """_ship_logs never raises — failures are logged to joblog."""
    keys = _agent_keys(tmp_path)
    jl = _make_joblog_with_entries(tmp_path)
    client = NodeAgentClient("https://edge.example.com", StubClassifier(), keys, jl)

    offset_dir = tmp_path / ".lustro-node-agent"
    offset_dir.mkdir(parents=True, exist_ok=True)
    offset_file = offset_dir / "shipped.offset"
    offset_file.write_text("0")

    # This should not raise even though transport fails
    client._ship_logs(http=_ShipHttpTransportError(), shipped_path=offset_file)

    # Check joblog for failure entry
    events = [r["event"] for r in jl.read_all()]
    assert "ship_logs_failed" in events
