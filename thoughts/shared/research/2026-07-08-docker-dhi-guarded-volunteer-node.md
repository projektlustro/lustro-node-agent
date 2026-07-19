---
date: 2026-07-08
commit: c4bce4a40d9a4e820d617f6e37804e93b8d0e575
branch: main
tags: [docker, dhi, ci, security, onboarding, trust-model]
status: complete
---
# Research: Docker (DHI) packaging + volunteer-gated node-agent

## Summary
The repo already ships a working `Dockerfile` (plain `python:3.12-slim`, non-root
`agent` user, no published ports) and a CI workflow that builds — but does not
publish, sign, or scan — that image. `README.md` already documents a `cosign
verify` step against a pinned identity, but nothing in CI produces a signed,
pushed image today, so that instruction is currently unverifiable.

**Correction after checking the private monorepo (`../lustro`) directly** (per
user instruction — the monorepo owner is a checked-out sibling repo, not an
inaccessible external system): the "authorized volunteers only" mechanism is
**not** a client-supplied enrollment token. `services/core/app/routers/wu.py`
in the monorepo states explicitly:

> "This endpoint is deliberately open (anyone can register) — registration is
> about identity, not authorization. Vetting (trust tiers, rate-gating) is
> layered on top."

And the monorepo's own live roadmap
(`thoughts/shared/plans/2026-07-06-mvp-v2-post-review.md`, Phase C.1, Day
18-19, **not yet implemented**) tracks the real mechanism as:

> "N3: node-agent mTLS or signed JWT with 14-day grandfathering for existing agents."

i.e. the monorepo itself hasn't decided between mTLS and signed-JWT yet, and
explicitly schedules it *after* go-live with a grandfathering window for
agents that already registered under open enrollment. There is no volunteer
token, header, or enrollment endpoint for the classifier node-agent to consume
today — inventing one client-side (as an earlier draft of this research/plan
did) would be building against a contract that doesn't exist and would likely
diverge from whichever of {mTLS, signed JWT} the monorepo team picks. This
repo's plan should not add a fabricated token gate; it should document the
current, intentional state (open registration, vetting layered on top later)
and flag the real dependency (N3) as an explicit blocker/future-work item.

## Files Involved

| File | Layer | Purpose |
|------|-------|---------|
| `Dockerfile` | Container | Current image: `python:3.12-slim`, deps, copies `node_agent/`, non-root `agent` (uid 10001), `ENTRYPOINT ["python","-m","node_agent.cli"]`, `CMD ["run"]` |
| `.github/workflows/ci.yml` | CI | Two jobs: `test` (pytest) and `docker-build` (`docker build -t node-agent .` — no push, no sign, no scan) |
| `node_agent/cli.py` | CLI | `cmd_run` — requires `--edge`/`LUSTRO_NODE_EDGE_URL`, generates/loads keypair, registers once (`STATE_DIR/registered` sentinel), then `pull_and_process()` |
| `node_agent/client.py` | Client | `register_agent()` (line 263) POSTs only `{"agent_pubkey": ...}` — no volunteer identity/authorization credential today |
| `node_agent/core_pin.py` | Trust | Fail-closed pinned-core-key pattern (`LUSTRO_NODE_AGENT_DEV`, `LUSTRO_NODE_AGENT_PINNED_KEY_B64`) — the template to follow for a new volunteer-token env var |
| `node_agent/egress.py` | Trust | Single-host egress allowlist (`EgressGuard`) — the token must ride on requests to this same allowed host, no new destination |
| `node_agent/keys.py` | Trust | Local Ed25519 keypair generation/storage (`~/.lustro-node-agent/agent_ed25519.key`, `0600`) |
| `README.md` | Docs | Already documents `cosign verify` against `ghcr.io/lustro/node-agent:<tag>` with a **placeholder** identity/issuer — no matching CI step exists yet |
| `SECURITY.md` / `CONTRIBUTING.md` / `AGENTS.md` / `CLAUDE.md` | Docs | Enforce "docs + trust model change in the same PR", "public repo — no public vuln issues", private tracker for security fixes |
| `pytest.ini`, `tests/` | Tests | `test_node_agent.py`, `test_e2e_smoke.py` — cover trust invariants; any new gating logic needs an accompanying test per repo convention |

## Data Flow (current)

1. `node-agent run --edge <url>` (`cli.py:24`) → `ensure_keypair()` (local Ed25519, generated once) → builds `NodeAgentClient`.
2. First run only: `client.register_agent()` (`client.py:263`) → `POST {edge}/v1/wu/register-agent` with `{"agent_pubkey": ...}` → writes a local `registered` sentinel file, **no server-side authorization credential is presented**.
3. `client.pull_and_process()` → `GET {edge}/v1/wu` (size-capped stream, `client.py:277`) → `process_wu()` verifies `core_sig` against the pinned core key (`core_pin.py`) → classifies → signs result with the local agent key → `POST {edge}/v1/wu/{id}/result`.
4. Every network call is routed through `EgressGuard.check()` (`egress.py`), which refuses any host but the configured edge — the single allowed egress point.

There is currently no step in this flow where "is this volunteer authorized to run at all" is checked — authorization, if it exists, must live entirely server-side (edge), which is out of this repo's scope.

## Existing Patterns (fail-closed credential gating)

`node_agent/core_pin.py` is the direct template for how this codebase already
solves "add a new environment-supplied secret without breaking the public,
auditable nature of the repo":

- A named env var override (`LUSTRO_NODE_AGENT_PINNED_KEY_B64`) takes precedence.
- A dev-only opt-in flag (`LUSTRO_NODE_AGENT_DEV=1`) unlocks a baked-in constant
  **only** for local dev/tests.
- With neither set, the default is empty and the code fails **closed** (raises
  `CorePinError`), never silently trusting a fallback.

The same three-tier shape (env override → explicit dev opt-in → fail-closed
empty default) is the template N3 (mTLS or signed JWT) should reuse when the
monorepo team designs it — but that design doesn't exist yet, so this repo
should not pre-empt it with a fabricated credential.

The Dockerfile's existing non-root user + no-inbound-ports + comment-documented
egress story is the template for how the DHI swap should be framed: swap the
base image, keep the same `USER agent`, same single `ENTRYPOINT`.

## Architecture Notes

- **Docker Hardened Images (DHI)**: Docker made the full DHI catalog free
  (Apache-2.0) in December 2025. The community tier is pulled as
  `dhi.io/<image>:<tag>` after `docker login dhi.io` — no org enablement
  needed for this. DHI images run as non-root by default and ship a `-dev`
  variant (shell/pip/compilers) alongside a minimal runtime variant (no
  shell), so the Dockerfile needs a multi-stage build (install in `-dev`,
  copy artifacts into the minimal runtime stage).
- **CI gap**: `docker-build` job builds but never pushes/signs an image, yet
  `README.md` already instructs volunteers to `cosign verify` a `ghcr.io/lustro/node-agent:<tag>` image. Any Docker packaging plan must either close this gap (add build→push→cosign-sign to CI) or explicitly flag it as a pre-existing, separate gap the plan does not fix.
- **Guard model (confirmed against the monorepo)**: registration
  (`POST /v1/wu/register-agent`, `services/core/app/routers/wu.py` in
  `../lustro`) is *intentionally* open today — "identity, not authorization"
  per the router's own docstring. Real authorization ("only authorized
  volunteers get work") is entirely edge/core-side and is explicitly tracked
  as unbuilt future work in the monorepo's own roadmap (N3: "node-agent mTLS
  or signed JWT with 14-day grandfathering for existing agents", Phase C.1,
  post-go-live — see `thoughts/shared/plans/2026-07-06-mvp-v2-post-review.md`
  in `../lustro`). This repo's node-agent is already compliant with the
  current, deliberate design. The Docker/CI packaging work in this plan must
  not invent a competing client-side credential; it should preserve today's
  open-registration behavior and leave a documented seam for N3 to land later
  without a breaking change.

## External Dependencies
- `ghcr.io` (GitHub Container Registry) — implied publish target per README.
- `cosign` / Sigstore keyless signing — referenced in README, not yet wired into CI.
- `dhi.io` — Docker Hardened Images community registry (free, Apache-2.0 catalog as of Dec 2025); requires `docker login dhi.io` including in CI.
- projektlustro.eu — the volunteer enrollment/vetting authority for the *program* (who gets pointed at an edge URL at all); not an API this repo's client code integrates with today.
- `../lustro` (this Mac's checkout of the private monorepo) — source of truth for `services/core/app/routers/wu.py` and the roadmap doc confirming the N3 gap; not a dependency this repo can programmatically read at build/release time (it's a local sibling checkout, not a public reference).

## Open Questions
1. ~~Does an edge-side "authorized volunteer" enrollment/token API already exist?~~ **Resolved**: no — registration is deliberately open; real vetting (N3: mTLS or signed JWT) is unbuilt, scheduled post-go-live in the monorepo roadmap.
2. Should this repo's Docker/CI work land now, ahead of N3, or wait so the eventual credential mechanism can be designed Docker-image-first (e.g. mTLS needs a client cert mount point in the container)? Recommend landing now — Docker packaging is independent of the auth mechanism and a client-cert mount is a small, additive change to add later.
3. When N3 lands in the monorepo, does the LUSTRO docs site / this repo's README need a follow-up PR? Yes — flagged in the plan's Rollback/Risk sections as a known follow-up, not in this plan's scope.
