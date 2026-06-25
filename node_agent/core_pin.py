"""Pinned core public key.

Work units carry a `core_sig` produced by the core's signing-service. The agent
verifies that signature against a PINNED core public key, identified by
`PINNED_CORE_KEY_ID`. If a work unit references a different key id, it is
rejected outright (key-pinning: we never trust a substituted core key).

In production the pinned public key is baked into the release (cosign-verified);
here it is a config constant the volunteer can audit.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# Identifier of the core key this agent build trusts. A WU declaring any other
# key id is rejected.
PINNED_CORE_KEY_ID = "lustro-core-key-v1"

# PEM of the pinned core public key. Replaced at release time with the real
# core public key (cosign-verified). Empty by default — `verify_wu_signature`
# requires it to be set, so an unconfigured build fails closed.
PINNED_CORE_PUBLIC_KEY_PEM: bytes = b""


class CorePinError(Exception):
    """Raised when a work unit fails core key-pinning / signature checks."""


def _load_pinned_public_key(pem: bytes) -> Ed25519PublicKey:
    if not pem:
        raise CorePinError("no pinned core public key configured (fail-closed)")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise CorePinError("pinned core key is not Ed25519")
    return key


def verify_wu_signature(
    wu_bytes: bytes,
    core_sig: bytes,
    key_id: str,
    *,
    pinned_key_id: str = PINNED_CORE_KEY_ID,
    pinned_public_key_pem: bytes | None = None,
) -> None:
    """Verify a work unit's `core_sig` against the pinned core key.

    Raises `CorePinError` if the key id mismatches or the signature is invalid.
    Returns None on success.
    """
    if key_id != pinned_key_id:
        raise CorePinError(
            f"core key id mismatch: wu={key_id!r} pinned={pinned_key_id!r}"
        )
    pem = pinned_public_key_pem if pinned_public_key_pem is not None else PINNED_CORE_PUBLIC_KEY_PEM
    pub = _load_pinned_public_key(pem)
    try:
        pub.verify(core_sig, wu_bytes)
    except InvalidSignature as e:
        raise CorePinError("core signature invalid") from e
