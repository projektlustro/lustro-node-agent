"""Agent keypair management.

The Ed25519 keypair is generated LOCALLY on the volunteer's machine and the
private key is persisted to a local file (0600). It is NEVER returned by any
public function and NEVER transmitted. Only the public key is exposed (and only
the public key is ever sent to the edge, as the agent's identity).
"""

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DEFAULT_KEY_PATH = Path.home() / ".lustro-node-agent" / "agent_ed25519.key"


def _load_private(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    return serialization.load_pem_private_key(raw, password=None)


def ensure_keypair(path: Path | str = DEFAULT_KEY_PATH) -> "AgentKeys":
    """Load the local keypair, generating + persisting it if absent.

    Generation is purely local; nothing leaves the machine.
    """
    p = Path(path)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Write private key with restrictive permissions.
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, pem)
        finally:
            os.close(fd)
    return AgentKeys(p)


class AgentKeys:
    """Wraps the local keypair. Exposes the PUBLIC key only; never the private."""

    def __init__(self, path: Path | str = DEFAULT_KEY_PATH) -> None:
        self._path = Path(path)
        # Held privately; intentionally not exposed via any public accessor.
        self.__private = _load_private(self._path)

    @property
    def path(self) -> Path:
        return self._path

    def public_key(self) -> Ed25519PublicKey:
        return self.__private.public_key()

    def public_key_pem(self) -> bytes:
        return self.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def public_key_raw_b64(self) -> str:
        """Base64 of the raw 32-byte Ed25519 public key.

        This is the wire format the core expects for ``agent_pubkey``: the core
        reconstructs the verifying key via ``Ed25519PublicKey.from_public_bytes``
        on ``base64decode(agent_pubkey)``. Must match the core's raw-bytes
        encoding (``CoreSigner.from_public_bytes``).
        """
        return base64.b64encode(self.public_key().public_bytes_raw()).decode()

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the local private key. The key never leaves here."""
        return self.__private.sign(message)
