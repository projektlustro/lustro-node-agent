"""Red->green for the core-signed model-registry manifest (plan §4.2).

Every classifier/tokenizer/config/ONNX artifact must carry immutable id/version,
byte length and SHA-256 in a manifest signed by a pinned Ed25519 key; unknown or
revoked keys are rejected; artifacts are verified (signature + all bytes) before
any load — including before any joblib.load.
"""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _registry():
    import importlib

    return importlib.import_module("node_agent.model_registry")


def _make_manifest(key, artifacts):
    reg = _registry()
    manifest = {
        "registry_version": 1,
        "key_id": reg.key_id_of(key.public_key()),
        "artifacts": artifacts,
    }
    manifest["signature"] = base64.b64encode(
        key.sign(reg.canonical_manifest_bytes(manifest))
    ).decode()
    return manifest


def test_manifest_signature_verifies_and_tamper_rejected():
    reg = _registry()
    key = Ed25519PrivateKey.generate()
    art = [{"id": "classifier", "version": "1", "sha256": "a" * 64, "bytes": 10}]
    m = _make_manifest(key, art)
    assert reg.verify_manifest(m, key.public_key())
    m["artifacts"][0]["sha256"] = "b" * 64
    assert not reg.verify_manifest(m, key.public_key())


def test_unknown_or_revoked_key_rejected():
    reg = _registry()
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    m = _make_manifest(key, [])
    assert not reg.verify_manifest(m, other.public_key())  # wrong key
    reg2 = _registry()
    reg2.revoke_key(reg2.key_id_of(key.public_key()))
    assert not reg2.verify_manifest(m, key.public_key())  # revoked


def test_artifact_bytes_verified_before_load(tmp_path):
    reg = _registry()
    key = Ed25519PrivateKey.generate()
    payload = b"weights-bytes"
    digest = hashlib.sha256(payload).hexdigest()
    art = [{"id": "classifier", "version": "1", "sha256": digest, "bytes": len(payload)}]
    m = _make_manifest(key, art)
    f = tmp_path / "classifier.bin"
    f.write_bytes(payload)
    assert reg.verify_artifact(m, key.public_key(), "classifier", f)
    f.write_bytes(payload + b"x")  # tampered
    with pytest.raises(reg.ArtifactVerificationError):
        reg.verify_artifact(m, key.public_key(), "classifier", f)


def test_duplicate_json_keys_rejected_in_manifest():
    reg = _registry()
    with pytest.raises(ValueError):
        reg.parse_manifest(b'{"a": 1, "a": 2}')
