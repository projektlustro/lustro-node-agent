"""Pinned core public key.

Work units carry a `core_sig` produced by the core's signing-service. The agent
verifies that signature against a PINNED core public key, identified by
`PINNED_CORE_KEY_ID`. If a work unit references a different key id, it is
rejected outright (key-pinning: we never trust a substituted core key).

The core emits its public key as a **raw 32-byte** Ed25519 key (see
``services/core/app/core_signer.py`` — ``CoreSigner.public_bytes`` returns
``public_bytes_raw()``). We therefore pin the raw key, not a PEM wrapper, so the
agent and the core agree byte-for-byte on the pinned identity. For auditability
the constant is stored as base64 of those 32 raw bytes.

In production the pinned public key is baked into the release (cosign-verified);
here it is a config constant the volunteer can audit.
"""

import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Identifier of the core key this agent build trusts. A WU declaring any other
# key id is rejected.
PINNED_CORE_KEY_ID = "lustro-core-key-v1"

# Base64 of the pinned core public key's raw 32 bytes.
#
# Dev builds ship with a real keypair so the WU pipeline works end-to-end
# out-of-the-box.  Production builds override this at release time via
# `LUSTRO_NODE_AGENT_PINNED_KEY_B64` (preferred) or by patching this constant.
# An empty value still triggers the fail-closed behaviour in
# `verify_wu_signature`.
_DEV_CORE_PUBLIC_KEY_B64 = "3xr2nMlHr2Lj+WMO+vZ09gIgUeSDk7d2HxW4UZ3ymOg="
PINNED_CORE_PUBLIC_KEY_B64: str = _DEV_CORE_PUBLIC_KEY_B64

# Env-var override so prod deployments (and tests) can swap the key without
# editing source.
_ENV_KEY = "LUSTRO_NODE_AGENT_PINNED_KEY_B64"


def _effective_pinned_key() -> str:
    """Return the pinned key, preferring the env override over the baked-in dev key."""
    return os.environ.get(_ENV_KEY, PINNED_CORE_PUBLIC_KEY_B64)


class CorePinError(Exception):
    """Raised when a work unit fails core key-pinning / signature checks."""


def _load_pinned_public_key(raw_b64: str) -> Ed25519PublicKey:
    if not raw_b64:
        raise CorePinError("no pinned core public key configured (fail-closed)")
    try:
        raw = base64.b64decode(raw_b64, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as e:
        raise CorePinError("pinned core key is not a valid raw Ed25519 key") from e


def verify_wu_signature(
    wu_bytes: bytes,
    core_sig: bytes,
    key_id: str,
    *,
    pinned_key_id: str = PINNED_CORE_KEY_ID,
    pinned_public_key_b64: str | None = None,
) -> None:
    """Verify a work unit's `core_sig` against the pinned core key.

    ``pinned_public_key_b64`` is base64 of the pinned raw 32-byte Ed25519 public
    key. Raises `CorePinError` if the key id mismatches or the signature is
    invalid. Returns None on success.
    """
    if key_id != pinned_key_id:
        raise CorePinError(
            f"core key id mismatch: wu={key_id!r} pinned={pinned_key_id!r}"
        )
    raw_b64 = (
        pinned_public_key_b64
        if pinned_public_key_b64 is not None
        else _effective_pinned_key()
    )
    pub = _load_pinned_public_key(raw_b64)
    try:
        pub.verify(core_sig, wu_bytes)
    except InvalidSignature as e:
        raise CorePinError("core signature invalid") from e
