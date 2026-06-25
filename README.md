# node-agent

A **volunteer-run, sandboxed classifier** for LUSTRO. You run it on your own
machine to help classify *public* work units. It is built to earn trust through
hard, testable guarantees — not promises.

## Why this is NOT a botnet

Engineers are right to be suspicious of "run our agent on your machine." Here is
the short, falsifiable answer — each point is enforced in code and covered by a
test, not just asserted here.

- **Outbound-only — it cannot proxy.** The agent talks to exactly ONE host: the
  edge URL you configure. Every request is checked against an allowlist
  (`node_agent/egress.py`); any other host is refused with an `EgressViolation`.
  A malicious or compromised work unit cannot make your machine fetch arbitrary
  URLs, and it opens no inbound ports — so you are not an exit node, relay, or
  proxy for anyone.
- **Signed + inspectable — nothing is hidden.** Every work unit is signed by the
  LUSTRO core and verified against a *pinned* core public key before it runs
  (key-id mismatch or bad signature ⇒ rejected). Every job you process is
  appended to a plain-text log at `~/.lustro-node-agent/joblog.jsonl` that you
  can dump at any time (`node-agent dump-log`). You can see the exact work you
  did. This radical inspectability is the answer to "is this a botnet?".
- **Your key is yours — the core cannot mint it.** On first run the agent
  generates an Ed25519 keypair *locally*. The private key is stored at
  `~/.lustro-node-agent/agent_ed25519.key` (`0600`), is never transmitted, and
  is never returned by any function — only your public key is sent, as your
  agent identity. Nothing in a (core-signed) work unit can substitute your key.
- **One-command leave.** `node-agent leave` deletes ALL local state — keys and
  job log — in a single command. No lock-in, no residue.

## Verify the release before running

Releases are signed with [cosign](https://github.com/sigstore/cosign)
(keyless / Sigstore). Verify the container image signature **before** you run
it, and only run images whose signature verifies against the pinned identity:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/lustro/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/lustro/node-agent:<tag>
```

Replace the identity/issuer with the exact pinned values published in the
release notes. A reproducible build + published SBOM let you confirm the image
matches this source.

## How the loop works (FROZEN wu contract)

```
GET  /v1/wu                 -> WorkUnit  {wu_id, kind, payload, core_pubkey_id, core_sig}
POST /v1/wu/{id}/result     <- WorkUnitResult {labels, score, agent_pubkey, agent_sig}
```

1. **Pull** the next work unit from the edge.
2. **Verify** `core_sig` against the pinned core public key (reject on key-id
   mismatch or bad signature).
3. **Anti-replay**: a repeated `wu_id` (or `nonce`, if present) is refused.
4. **Classify** the payload with the local `StubClassifier` (swap in a real
   model later).
5. **Sign** the result `{wu_id, labels, score}` with your local Ed25519 key.
6. **POST** the signed `WorkUnitResult` back to the edge.

## Usage

```bash
# Run once (pull + process the next work unit):
python -m node_agent.cli run --edge https://edge.lustro.example

# Inspect every job you've processed (radical inspectability):
python -m node_agent.cli dump-log

# One-command exit — deletes ALL local state (keys + job log):
python -m node_agent.cli leave
```

The edge URL may also be supplied via `LUSTRO_NODE_EDGE_URL`.

## Test

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

The suite covers the trust invariants directly: the private key is never
returned/transmitted, the core cannot mint the agent key, pinned-key
verification (good/bad sig + key-id), anti-replay, egress refusal of off-host
requests, and the end-to-end loop against a mock edge.
