"""Crypto backends: the WASM node uses pure-Python Ed25519 where the CLI uses
``cryptography``.

``NodeAgentClient`` only needs two things from a keyring — the agent's raw
public key (base64, wire format) and a signing primitive — plus a callable that
verifies a core work-unit signature against the pinned key. This module exposes
both for the pure-Python path so the SAME client loop runs unchanged in the
browser, just with different crypto underneath.

The two paths are proven interoperable by ``tests/test_ed25519_compat.py``:
the same seed yields identical keys and signatures across impls, and each
verifies the other's signatures.
"""

from __future__ import annotations

import base64

from node_agent import _ed25519_pure as ed25519
from node_agent.core_pin import CorePinError, PINNED_CORE_KEY_ID, _effective_pinned_key


class PureKeyring:
    """Seed-backed Ed25519 keyring exposing the surface ``NodeAgentClient`` needs.

    The seed is the 32-byte Ed25519 private seed. It is held in memory only; the
    browser persistence layer (IndexedDB) owns storing it. ``public_key_raw_b64``
    and ``sign`` are byte-compatible with ``AgentKeys`` (cryptography), so the
    client loop cannot tell the two apart.
    """

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self._seed = seed
        self._pub = ed25519.public_key(seed)

    @classmethod
    def generate(cls) -> "PureKeyring":
        return cls(ed25519.generate_seed())

    def public_key_raw_b64(self) -> str:
        return base64.b64encode(self._pub).decode()

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self._seed, message, pub=self._pub)


def pure_verify_wu_signature(
    wu_bytes: bytes,
    core_sig: bytes,
    key_id: str,
    *,
    pinned_key_id: str = PINNED_CORE_KEY_ID,
    pinned_public_key_b64: str | None = None,
) -> None:
    """Pure-Python twin of ``core_pin.verify_wu_signature``.

    Same contract: raise ``CorePinError`` on key-id mismatch or invalid
    signature; return None on success. Used by the WASM node where
    ``cryptography`` is unavailable. The pinned key resolution (env override
    over the baked-in constant) is shared with the cryptography path via
    ``_effective_pinned_key`` so both builds pin the same identity.
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
    if not raw_b64:
        raise CorePinError("no pinned core public key configured (fail-closed)")
    try:
        pub = base64.b64decode(raw_b64, validate=True)
    except (ValueError, TypeError) as e:
        raise CorePinError("pinned core key is not valid base64") from e
    if not ed25519.verify(pub, wu_bytes, core_sig):
        raise CorePinError("core signature invalid")
