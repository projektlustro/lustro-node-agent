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

# Identifier of the core key this agent build trusts. A WU declaring any other
# key id is rejected.
PINNED_CORE_KEY_ID = "lustro-core-key-v1"

# Base64 of the pinned core public key's raw 32 bytes.
#
# The baked-in dev key only becomes the default when `LUSTRO_NODE_AGENT_DEV=1`
# is set explicitly. Production builds ship with NO baked-in key: the default is
# empty, which fails CLOSED in `verify_wu_signature`, and the pinned key is
# supplied at release time via `LUSTRO_NODE_AGENT_PINNED_KEY_B64` (preferred) or
# by patching this constant. A build with neither the dev flag nor the env
# override trusts nothing rather than silently trusting the dev key (fail-open).
_DEV_CORE_PUBLIC_KEY_B64 = "3xr2nMlHr2Lj+WMO+vZ09gIgUeSDk7d2HxW4UZ3ymOg="

# Flag that opts a build into the baked-in dev key. Anything other than "1"
# leaves the default empty (fail-closed).
_DEV_FLAG = "LUSTRO_NODE_AGENT_DEV"

# Env-var override so prod deployments (and tests) can swap the key without
# editing source.
_ENV_KEY = "LUSTRO_NODE_AGENT_PINNED_KEY_B64"


def _default_pinned_key_b64(env: "os._Environ[str] | dict[str, str] | None" = None) -> str:
    """Baked-in default: the dev key only when the dev flag is explicitly set."""
    e = os.environ if env is None else env
    return _DEV_CORE_PUBLIC_KEY_B64 if e.get(_DEV_FLAG) == "1" else ""


PINNED_CORE_PUBLIC_KEY_B64: str = _default_pinned_key_b64()


def _effective_pinned_key() -> str:
    """Return the pinned key that this build trusts.

    Preference order:
      1. `LUSTRO_NODE_AGENT_PINNED_KEY_B64` env override (prod releases / tests);
      2. the module constant `PINNED_CORE_PUBLIC_KEY_B64` when non-empty (a
         prod-patched build, or a test that pins its own key);
      3. the baked-in dev key ONLY when `LUSTRO_NODE_AGENT_DEV=1`, else empty.

    With no override, no patched constant and no dev flag this returns "" and the
    caller fails CLOSED — the default trust set is empty, never the dev key.
    """
    override = os.environ.get(_ENV_KEY)
    if override is not None:
        return override
    if PINNED_CORE_PUBLIC_KEY_B64:
        return PINNED_CORE_PUBLIC_KEY_B64
    return _default_pinned_key_b64()


class CorePinError(Exception):
    """Raised when a work unit fails core key-pinning / signature checks."""


def _load_pinned_public_key(raw_b64: str):
    # Lazy import: cryptography is native and unavailable under Pyodide. The WASM
    # node never calls this (it uses node_agent.crypto.pure_verify_wu_signature),
    # so the module must import without pulling cryptography in.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
    except Exception as e:
        raise CorePinError("core signature invalid") from e
