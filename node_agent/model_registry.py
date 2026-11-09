"""Core-signed model-registry manifest (plan §4.2).

The registry manifest lists every classifier/tokenizer/config/ONNX artifact with
immutable id/version, byte length and SHA-256, signed with a pinned Ed25519 key.
Signature AND all bytes are verified before any artifact is loaded (including
before any joblib.load). Unknown or revoked keys are rejected; downloaded
work-unit code is never executed.
"""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ArtifactVerificationError(Exception):
    pass


_revoked_keys: set = set()


def _no_duplicates(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate JSON key: {k}")
        seen.add(k)
    return dict(pairs)


def parse_manifest(raw: bytes):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)


def key_id_of(pubkey: Ed25519PublicKey) -> str:
    raw = pubkey.public_bytes_raw()
    return "ed25519-" + hashlib.sha256(raw).hexdigest()[:16]


def canonical_manifest_bytes(manifest: dict) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def revoke_key(key_id: str) -> None:
    _revoked_keys.add(key_id)


def verify_manifest(manifest: dict, pubkey: Ed25519PublicKey) -> bool:
    """Verify the manifest signature against the pinned key; revoked keys fail."""
    key_id = key_id_of(pubkey)
    if key_id in _revoked_keys:
        return False
    if manifest.get("key_id") != key_id:
        return False
    sig = manifest.get("signature")
    if not sig:
        return False
    try:
        pubkey.verify(base64.b64decode(sig), canonical_manifest_bytes(manifest))
        return True
    except Exception:
        return False


def verify_artifact(manifest: dict, pubkey: Ed25519PublicKey, artifact_id: str, path) -> bool:
    """Verify manifest signature, then the artifact's length and SHA-256."""
    if not verify_manifest(manifest, pubkey):
        raise ArtifactVerificationError("manifest signature invalid or key revoked")
    entry = next((a for a in manifest["artifacts"] if a["id"] == artifact_id), None)
    if entry is None:
        raise ArtifactVerificationError(f"artifact {artifact_id} not in manifest")
    data = path.read_bytes() if hasattr(path, "read_bytes") else open(path, "rb").read()
    if len(data) != entry["bytes"]:
        raise ArtifactVerificationError(f"{artifact_id}: length {len(data)} != {entry['bytes']}")
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ArtifactVerificationError(f"{artifact_id}: sha256 mismatch")
    return True
