"""Pure-Python Ed25519 (RFC 8032) for the browser/WASM node.

``cryptography`` does not run under Pyodide (native build), so the WASM node
signs and verifies with this implementation instead. It uses only ``hashlib``
(SHA-512), which Pyodide provides, and is byte-compatible with
``cryptography``'s RawEd25519: the same 32-byte seed yields the same 32-byte
public key and the same deterministic 64-byte signature.

The CLI path does NOT use this module — it keeps ``cryptography``. The two are
proven interchangeable by ``tests/test_ed25519_compat.py`` (same seed ->
identical sig/pubkey, and cross-verify).
"""

from __future__ import annotations

import hashlib
import os

# Curve/field parameters (RFC 8032, edwards25519).
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
_I = pow(2, (P - 1) // 4, P)  # sqrt(-1) mod P

# Base point B: By = 4/5, then recover Bx with even parity.
_BY = (4 * pow(5, P - 2, P)) % P


def _sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


def _xrecover(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * _I) % P
    if x % 2 != sign:
        x = (P - x) % P
    return x


_BX = _xrecover(_BY, 0)
B = (_BX, _BY, 1, _BX * _BY % P)  # extended homogeneous (X, Y, Z, T)


def _edwards(p1: tuple, p2: tuple) -> tuple:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(point: tuple, e: int) -> tuple:
    if e == 0:
        return (0, 1, 1, 0)  # identity
    q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            q = _edwards(q, point)
        point = _edwards(point, point)
        e >>= 1
    return q


def _encode_int(n: int) -> bytes:
    return n.to_bytes(32, "little")


def _encode_point(point: tuple) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, P - 2, P)
    x = x * zinv % P
    y = y * zinv % P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return _encode_int(sum(b << i for i, b in enumerate(bits)))


def _decode_point(s: bytes) -> tuple:
    if len(s) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = (s[31] >> 7) & 1
    if y >= P:
        raise ValueError("decoded y out of range")
    x = _xrecover(y, sign)
    point = (x, y, 1, x * y % P)
    if (-x * x + y * y - 1 - D * x * x * y * y) % P != 0:
        raise ValueError("decoded point not on curve")
    return point


def _hint(m: bytes) -> int:
    return int.from_bytes(_sha512(m), "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    h = bytearray(_sha512(seed))
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(bytes(h[:32]), "little")
    return a, bytes(h[32:])


def public_key(seed: bytes) -> bytes:
    """Derive the 32-byte raw public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a, _ = _expand(seed)
    return _encode_point(_scalarmult(B, a))


def sign(seed: bytes, msg: bytes, pub: bytes | None = None) -> bytes:
    """Sign ``msg`` with the keypair derived from ``seed`` (64-byte signature)."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a, prefix = _expand(seed)
    if pub is None:
        pub = _encode_point(_scalarmult(B, a))
    r = _hint(prefix + msg) % L
    r_point = _scalarmult(B, r)
    r_enc = _encode_point(r_point)
    s = (_hint(r_enc + pub + msg) * a + r) % L
    return r_enc + _encode_int(s)


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Return True iff ``sig`` is a valid Ed25519 signature of ``msg`` under ``pub``."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    try:
        r_point = _decode_point(sig[:32])
        a_point = _decode_point(pub)
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    h = _hint(sig[:32] + pub + msg) % L
    left = _scalarmult(B, s)
    right = _edwards(r_point, _scalarmult(a_point, h))
    return _encode_point(left) == _encode_point(right)


def generate_seed() -> bytes:
    """Return a fresh 32-byte seed (os.urandom in CPython; JS bridge in WASM)."""
    return os.urandom(32)
