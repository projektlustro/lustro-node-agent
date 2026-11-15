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

- **Outbound-only — the classifier loop cannot proxy.** The agent talks to
  exactly ONE host: the edge URL you configure. Every request is checked
  against an allowlist (`node_agent/egress.py`); any other host is refused
  with an `EgressViolation`. A malicious or compromised work unit cannot make
  your machine fetch arbitrary URLs. The loop itself opens no inbound ports —
  so you are not an exit node, relay, or proxy for anyone. The optional
  `serve-log` dashboard (below) is a separate, local-only, read-only command
  you explicitly start; it never talks to the edge or proxies traffic, but see
  its own security note for what it does change.
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
POST /v1/wu/register-agent -> registers your agent_pubkey (first run only)
GET  /v1/wu                 -> signed work-unit request in X-Lustro-Agent-* headers
                           <- WorkUnit {wu_id, kind, payload, core_pubkey_id, core_sig}
POST /v1/wu/{id}/result     <- signed WorkUnitResult {labels, score, agent_pubkey, agent_sig}
                           -> signed Core success or terminal receipt
```

0. **Register** (first run only): POST your local public key to
   `/v1/wu/register-agent`. A production core gates this behind a single-use
   operator invite: set `LUSTRO_NODE_INVITE_TOKEN` to the token you were issued
   and the agent forwards it in the register body. A dev/local core leaves
   registration open, so the token is optional there. If registration fails
   (e.g. the edge is unreachable, the invite is missing/invalid, or the edge
   returns a server error), `run` exits with a clear error naming this URL —
   that's what you're seeing if this is the first thing that fails.
1. **Pull** with the local key signing a timestamp, one-use nonce, configured
   tenant, and SHA-256 of the pinned Core public key. The proof travels in
   `X-Lustro-Agent-*` headers, not the URL. Core persists consumed nonces until
   their timestamps cannot pass validation, including across restarts. Production
   Core accepts only registered keys bound to trusted principals.
2. **Verify** `core_sig` against the pinned Core public key (reject on key-id
   mismatch or bad signature).
3. **Anti-replay**: a repeated `wu_id` (or `nonce`, if present) is refused.
4. **Classify** the payload with the local, artifact-backed multilingual E5
   model. Production runs fail closed if the model artifact is missing or its
   checksum does not match the signed model card; there is no keyword fallback.
5. **Sign** the result `{wu_id, labels, score}` with your local Ed25519 key.
6. Flush and `fsync` the exact signed result to the local job log before POST.
   Corrupt log records stop processing; delivery failures retry the same result.
7. **POST** the signed `WorkUnitResult` back to the edge. The Core's signed
   success acknowledgement binds the work-unit ID, agent signature, and
   authority; the agent verifies it before clearing the pending result.
8. A verified signed terminal receipt records permanent conflict, revocation,
   expiry, lease ownership mismatch, or a source that is no longer eligible.
   The agent clears that pending result; transient failures retry.
9. When `LUSTRO_NODE_TOKEN` is set, report the accepted `wu_id`
   idempotently so the volunteer's `/me` dashboard reflects the run.

The CLI displays the authority from the verified Core acknowledgement.
`authoritative-v1` creates an authoritative detection record;
`shadow-non-authoritative` stores a shadow without creating a detection;
`non-authoritative-local-stub` creates no detection.

## Getting authorized

This repo is public — anyone can read the code and verify the guarantees
above. Running it against a **real** edge, however, means joining the
volunteer program: sign up at [projektlustro.eu](https://projektlustro.eu) to
be pointed at the current edge URL and issued an **invite token**. The
production core requires that token on first registration (a single-use,
operator-minted `invite_id:mac` — see below); a self-generated key with no
invite cannot enrol. Production Core also requires an operator-bound trusted
principal before accepting pulls or results. Pass the invite via
`LUSTRO_NODE_INVITE_TOKEN`.

The separate `LUSTRO_NODE_TOKEN` comes from the Node-agent card in your
authenticated `/me` panel. It attributes accepted work units to that volunteer
account and can be rotated or revoked without replacing the agent's local
Ed25519 key. It is never written to the job log and does not authorize Core
requests. Production pulls use a short-lived signature and one-use nonce from
the enrolled local key.
Set the target tenant with `LUSTRO_NODE_TENANT` or `--tenant`; the default is
`pl`. The value must match the Core serving the edge. The signed pull proof
binds this tenant to the pinned Core key, so a proof cannot move across Core
instances or tenants. Core allows at most 10 outstanding leases per trusted
principal; leases expire after 24 hours.

## Usage

Run the published, signed container image — 3 steps.

```bash
# 1. Verify the release image before running it (install cosign first if you
#    don't have it: https://docs.sigstore.dev/cosign/system_config/installation/,
#    e.g. `brew install cosign` on macOS)
cosign verify \
  --certificate-identity 'https://github.com/projektlustro/lustro-node-agent/.github/workflows/ci.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/projektlustro/node-agent:latest

# 2. Process one work unit, with the edge URL from projektlustro.eu and
#    persistent local state (your key + job log survive between runs).
#    --pull=always guards against running a stale cached :latest if you
#    (or a fix) pulled this image before.
#    The published image already contains the pinned core public key, so you
#    provide the one-time invite and your revocable dashboard token.
mkdir -p ~/.lustro-node-agent
# The current published image is linux/amd64; keep this flag on Apple Silicon.
docker run --rm --pull=always --platform linux/amd64 \
  -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
  -e LUSTRO_NODE_EDGE_URL=https://projektlustro.eu \
  -e LUSTRO_NODE_TENANT=pl \
  -e LUSTRO_NODE_INVITE_TOKEN=REPLACE_WITH_INVITE_TOKEN \
  -e LUSTRO_NODE_TOKEN=REPLACE_WITH_NODE_TOKEN \
  ghcr.io/projektlustro/node-agent:latest

# 3. Inspect every job you've processed (radical inspectability)
docker run --rm --pull=always --platform linux/amd64 -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
  ghcr.io/projektlustro/node-agent:latest dump-log
```

Production images are published only by a push to `main`. Tags and feature
branches may be used for source organization and CI, but they cannot publish a
container image.

If the agent says “already registered” and then receives `403 agent_pubkey not
registered`, the local registration marker is stale. Remove only that marker
and run again with a fresh invite:

```bash
rm ~/.lustro-node-agent/registered
docker run --rm --pull=always --platform linux/amd64 \
  -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
  -e LUSTRO_NODE_EDGE_URL=https://projektlustro.eu \
  -e LUSTRO_NODE_INVITE_TOKEN="$LUSTRO_INVITE_TOKEN" \
  -e LUSTRO_NODE_TOKEN="$LUSTRO_NODE_TOKEN" \
  ghcr.io/projektlustro/node-agent:latest
```

### Model artifact

The production agent requires `LUSTRO_NODE_MODEL_ROOT` containing the model
bundle (`model_card.json`, `embedder_config.json`, `feature_config.json`,
`calibration.json`, and `disinfo_classifier.joblib`). The model card checksum
must match the classifier before inference begins. The multilingual E5 ONNX
weights must already be present in `LUSTRO_NODE_EMBED_CACHE`; the agent does not
download executable model material during a work unit.

For the Mac Studio worker, point the agent at the promoted artifact in the NLP
checkout and its pre-warmed FastEmbed cache:

```bash
export LUSTRO_NODE_MODEL_ROOT=/Users/jakubsikora/Repos/personal/lustro-nlp-analysis-remote/data/models/nlp_analyzer/current
export LUSTRO_NODE_EMBED_CACHE=/Users/jakubsikora/Library/Caches/lustro-fastembed
```

Run from source on the Mac Studio with the project Python environment:

```bash
PYTHONPATH=/path/to/lustro-node-agent \
LUSTRO_NODE_MODEL_ROOT=/path/to/lustro-nlp-analysis-remote/data/models/nlp_analyzer/current \
LUSTRO_NODE_EMBED_CACHE=/Users/jakubsikora/Library/Caches/lustro-fastembed \
python -m node_agent.cli run --edge https://projektlustro.eu
```

`node-agent run` is **one-shot**: it retries one pending result, or pulls and
processes one work unit, then exits. It is not a long-running loop. Schedule
step 2 on cron (or a systemd timer) for continuous participation.

`leave` deletes ALL local state (keys + job log) in one command:

```bash
docker run --rm --pull=always -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
  ghcr.io/projektlustro/node-agent:latest leave
```

## Inspect the log in a browser

For a live view of the same job log, run the local dashboard:

```bash
node-agent serve-log
```

This opens `http://127.0.0.1:8787` in your browser and updates as new work
units are processed. It binds to `127.0.0.1` by default, is read-only, and
makes no outbound calls. Do not pass `--host 0.0.0.0` unless you intend to
expose the dashboard to every device on the local network.

With Docker, publish the port from the host. The default `127.0.0.1` bind
does not work inside a container with `-p` (Docker's port mapping forwards to
the container's network interface, not its loopback), so use
`--host 0.0.0.0` and rely on the host-side `-p` mapping to keep it on
localhost:

```bash
docker run --rm --pull=always \
  -p 127.0.0.1:8787:8787 \
  -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
  ghcr.io/projektlustro/node-agent:latest serve-log --host 0.0.0.0 --no-open
```

**serve-log security note**: the dashboard exposes the same data that is
normally protected by the `0600` permissions on `joblog.jsonl` to any process
running as your user (and, with `--host 0.0.0.0`, to the local network). It
rejects requests whose `Host` header is a DNS name rather than a literal IP
address or `localhost`, as defence against DNS-rebinding attacks from a
malicious web page you have open in another tab — but it is still a local
inspectability convenience, not part of the classifier loop's outbound-only
guarantee.

**Bind-mount ownership note**: the container's non-root user has a fixed
UID that may not match the host user who created `~/.lustro-node-agent`
(e.g. via `mkdir -p` above). If the first run fails with a permissions error
writing the key or job log, either run with
`docker run --user "$(id -u):$(id -g)" ...` or `chown` the host directory to
match the container's UID.

The edge URL may also be supplied via `-e LUSTRO_NODE_EDGE_URL=...` as shown,
or via `--edge` if running from source (see "Test" below).

The published GHCR image contains the production core public key from the
Dockerfile's pinned default. CI verifies that the resulting image has a
non-empty `LUSTRO_NODE_AGENT_PINNED_KEY_B64` value before publishing, so a
missing repository build variable cannot silently replace the pin with an
empty value. Source runs still need the explicit value shown below.

**Apple Silicon note**: only a `linux/amd64` image is published today. On an
arm64 Mac, Docker runs it under emulation — it works, just slower to pull and
start than a native image would be.

## Browser wheel release

The checked-in wheel contains browser protocol code only. Browser work
processing is unavailable: no signed Pyodide-compatible model artifact or
verified inference loader ships. `FailClosedClassifier` raises
`ModelUnavailable`, and `run_once` refuses before registration or work pulls.

```bash
cd services/node-agent
python -m pip wheel --no-deps --wheel-dir dist .
cp dist/lustro_node_agent-0.1.5-py3-none-any.whl ../../apps/public-site/public/wasm/
```

Keep the wheel filename, `pyproject.toml` version, and `AGENT_WHEEL` in
`apps/public-site/app/node/page.tsx` aligned. Build and copy the wheel before
publishing the page that references it.

## Test

Running from source — for contributors, or if you'd rather not use Docker:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q

LUSTRO_NODE_INVITE_TOKEN=REPLACE_WITH_INVITE_TOKEN \
LUSTRO_NODE_AGENT_PINNED_KEY_B64=Zb4MWkGcrXN7U/V19Vi7wIHwzPlgqENKuypGr0WoW90= \
  python -m node_agent.cli run --edge https://projektlustro.eu
python -m node_agent.cli dump-log
python -m node_agent.cli leave
```

The test suite covers the trust invariants directly: the private key is never
returned/transmitted, the core cannot mint the agent key, pinned-key
verification (good/bad sig + key-id), anti-replay, egress refusal of off-host
requests, and the end-to-end loop against a mock edge.

## Security Limitations

### Browser WASM Node
The browser worker does not currently register or pull work. Its fail-closed
classifier requires a signed model bundle that runs under Pyodide, plus a
browser loader that verifies the signed manifest and every artifact before
inference. The native `ModelClassifier` depends on `fastembed`, `joblib`,
`numpy`, and a preloaded E5 ONNX cache; those native dependencies and model
files are not packaged as browser assets.
