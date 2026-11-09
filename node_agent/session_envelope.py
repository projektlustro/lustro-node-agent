"""Opted-in scraping session envelope (plan §6.4).

Account usernames/passwords/TOTP stay in the trusted operator broker. Each
opted-in node generates a separate X25519 key bound to its Ed25519 identity by
signature. The broker builds a target-specific allowlisted session from
necessary cookies and origin storage only — proxy credentials, unrelated
origins and other account secrets are excluded — and encrypts the envelope to
(node, account, target, deadline). Plaintext sessions never appear in logs or
public blob storage. A volunteer host operator can inspect/copy the decrypted
bearer; broker expiry does not revoke that copy.
"""

import base64
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EnvelopeExpired(Exception):
    pass


def generate_node_key() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def bind_key(x_key: x25519.X25519PrivateKey, ed_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Signature binding the X25519 public key to the Ed25519 identity."""
    return ed_key.sign(x_key.public_key().public_bytes_raw())


def verify_binding(x_pub_b64: bytes, proof: bytes, ed_pub: ed25519.Ed25519PublicKey) -> bool:
    try:
        ed_pub.verify(proof, x_pub_b64)
        return True
    except Exception:
        return False


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def check_deadline(deadline: str, now: str) -> None:
    if _parse(deadline) <= _parse(now):
        raise EnvelopeExpired("envelope deadline passed")


def _domain_match(cookie_domain: str, target: str) -> bool:
    # cookie domain must equal the target or be a PARENT of it (a cookie for
    # .sub.x.com must never be sent to x.com)
    d = (cookie_domain or "").lstrip(".")
    return target == d or target.endswith("." + d)


def build_envelope(session: dict, target: str, account: str, deadline: str) -> dict:
    """Target-specific allowlisted session: necessary cookies + origin storage
    for the target only; proxy credentials and unrelated origins excluded."""
    cookies = [c for c in session.get("cookies", []) if _domain_match(c.get("domain", ""), target)]
    origins = {k: v for k, v in session.get("origins", {}).items() if k == f"https://{target}"}
    return {
        "cookies": cookies,
        "origins": origins,
        "target": target,
        "account": account,
        "deadline": deadline,
    }


def encrypt_envelope(envelope: dict, node_pub: x25519.X25519PublicKey) -> bytes:
    """Encrypt the envelope to the node's X25519 key (ephemeral-static ECDH)."""
    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(node_pub)
    salt = eph.public_key().public_bytes_raw()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"lustro-session-envelope").derive(shared)
    nonce = ChaCha20Poly1305.generate_key()[:12]
    ct = ChaCha20Poly1305(key).encrypt(nonce, json.dumps(envelope).encode(), None)
    return salt + nonce + ct


def decrypt_envelope(sealed: bytes, node_key: x25519.X25519PrivateKey) -> dict:
    salt, nonce, ct = sealed[:32], sealed[32:44], sealed[44:]
    shared = node_key.exchange(x25519.X25519PublicKey.from_public_bytes(salt))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"lustro-session-envelope").derive(shared)
    return json.loads(ChaCha20Poly1305(key).decrypt(nonce, ct, None))
