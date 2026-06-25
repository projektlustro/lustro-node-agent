"""LUSTRO node-agent: a volunteer-run, sandboxed classifier.

Guarantees, in plain words:
  - Outbound-only: the agent can only talk to ONE allowed base URL (the edge).
    It cannot be turned into a proxy for arbitrary hosts (see `egress`).
  - Local keys: the Ed25519 agent keypair is generated ON THE VOLUNTEER'S
    MACHINE and the private key is never transmitted (see `keys`).
  - Pinned trust: work units are signed by the core, and the agent verifies the
    signature against a PINNED core public key id (see `core_pin`).
  - Radical inspectability: every job is appended to a local JSONL the volunteer
    can read (see `joblog`).
"""
