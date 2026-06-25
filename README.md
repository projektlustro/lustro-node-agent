# node-agent

A **volunteer-run, sandboxed classifier** for LUSTRO. You run it on your own
machine to help classify work units. It is built to earn trust through hard
guarantees, not promises.

## Verify the release before running

Releases are signed. Verify the container image signature with
[cosign](https://github.com/sigstore/cosign) before running:

```bash
cosign verify --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer-regexp '.*' \
  ghcr.io/lustro/node-agent:<tag>
```

(Replace the identity/issuer regexes with the pinned values published in the
release notes.) Only run images whose signature verifies.

## The guarantees, in plain words

- **Outbound-only — it cannot become a proxy.** The agent can talk to exactly
  ONE host: the edge URL you configure. Every network call is checked against an
  allowlist (`node_agent/egress.py`); any other host is refused. A malicious
  work unit cannot make your machine fetch arbitrary URLs.
- **Your keys never leave your machine.** On first run the agent generates an
  Ed25519 keypair locally and stores the private key at
  `~/.lustro-node-agent/agent_ed25519.key` with `0600` permissions. The private
  key is never transmitted and is never returned by any function — only your
  public key is sent, as your agent identity.
- **The core is pinned.** Work units are signed by the LUSTRO core. The agent
  verifies that signature against a *pinned* core public key baked into the
  release (`node_agent/core_pin.py`). A work unit signed by any other key, or
  declaring a different key id, is rejected.
- **Anti-replay.** Each work unit's nonce / id is tracked; a replayed work unit
  is refused.
- **Radical inspectability.** Every job is appended to
  `~/.lustro-node-agent/joblog.jsonl`, a plain JSONL file you can read at any
  time. Nothing is hidden from you.

## Usage

```bash
# Run once (pull + process the next work unit):
python -m node_agent.cli run --edge https://edge.lustro.example

# One-command exit — deletes ALL local state (keys + job log):
python -m node_agent.cli leave
```

## Test

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```
