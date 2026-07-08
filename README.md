# node-agent

Part of [projektlustro](https://github.com/projektlustro) — see the LUSTRO
documentation site (access-gated pre-launch) for architecture and the trust
model. This repository is the canonical node-agent; the monorepo vendors it as a
submodule.

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

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

## Getting authorized

This repo is public — anyone can read the code and verify the guarantees
above. Running it against a **real** edge, however, means joining the
volunteer program: sign up at [projektlustro.eu](https://projektlustro.eu) to
be pointed at the current edge URL. Wire-level agent authorization beyond
that (mTLS or a signed JWT) is on the LUSTRO roadmap, not yet built —
registration on the wire is intentionally open today. See "Why this is NOT a
botnet" above for what's actually enforced right now.

## Usage

Run the published, signed container image — 3 steps.

```bash
# 1. Verify the release image before running it
cosign verify \
  --certificate-identity-regexp 'https://github.com/projektlustro/lustro-node-agent/\.github/workflows/ci\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/projektlustro/node-agent:v0.1.0  # example tag — replace with a real published release

# 2. Process one work unit, with the edge URL from projektlustro.eu and
#    persistent local state (your key + job log survive between runs)
mkdir -p ~/.lustro-node-agent
docker run --rm \
  -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
  -e LUSTRO_NODE_EDGE_URL=https://edge.lustro.example \
  ghcr.io/projektlustro/node-agent:v0.1.0

# 3. Inspect every job you've processed (radical inspectability)
docker run --rm -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
  ghcr.io/projektlustro/node-agent:v0.1.0 dump-log
```

`node-agent run` is **one-shot**: it pulls and processes a single work unit,
then exits. It is not a long-running loop. Schedule step 2 on cron (or a
systemd timer) for continuous participation.

`leave` deletes ALL local state (keys + job log) in one command:

```bash
docker run --rm -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
  ghcr.io/projektlustro/node-agent:v0.1.0 leave
```

**Bind-mount ownership note**: the container's non-root user has a fixed
UID that may not match the host user who created `~/.lustro-node-agent`
(e.g. via `mkdir -p` above). If the first run fails with a permissions error
writing the key or job log, either run with
`docker run --user "$(id -u):$(id -g)" ...` or `chown` the host directory to
match the container's UID.

The edge URL may also be supplied via `-e LUSTRO_NODE_EDGE_URL=...` as shown,
or via `--edge` if running from source (see "Test" below).

## Test

Running from source — for contributors, or if you'd rather not use Docker:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q

python -m node_agent.cli run --edge https://edge.lustro.example
python -m node_agent.cli dump-log
python -m node_agent.cli leave
```

The test suite covers the trust invariants directly: the private key is never
returned/transmitted, the core cannot mint the agent key, pinned-key
verification (good/bad sig + key-id), anti-replay, egress refusal of off-host
requests, and the end-to-end loop against a mock edge.
