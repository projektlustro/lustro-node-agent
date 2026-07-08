---
date: 2026-07-08
commit: c4bce4a40d9a4e820d617f6e37804e93b8d0e575
branch: main
ticket: null
status: draft
---
# Plan: Docker-package the node-agent on Docker Hardened Images, published + cosign-signed via CI, with a 3-step run flow

## Summary
Repackage `Dockerfile` on Docker Hardened Images (DHI) `python` base via a
multi-stage build, wire CI to publish + cosign-sign the image to GHCR (closing
an existing gap where `README.md` already documents a `cosign verify` step
that nothing in CI produces), and rewrite the README run section down to 3
commands with an honest explanation of the current volunteer-authorization
model. No client-side authorization gate is added — see the corrected note
below.

## Research References
- [thoughts/shared/research/2026-07-08-docker-dhi-guarded-volunteer-node.md](../research/2026-07-08-docker-dhi-guarded-volunteer-node.md)

## Corrected finding on volunteer authorization (checked directly against `../lustro`)

An earlier draft of this plan proposed a client-side `--token` /
`LUSTRO_NODE_VOLUNTEER_TOKEN` bearer-token gate on `register_agent()`. **That
was wrong and has been dropped.** Reading the monorepo directly
(`services/core/app/routers/wu.py`) shows registration is *deliberately* open:

> "This endpoint is deliberately open (anyone can register) — registration is
> about identity, not authorization. Vetting (trust tiers, rate-gating) is
> layered on top."

And the monorepo's own roadmap
(`thoughts/shared/plans/2026-07-06-mvp-v2-post-review.md`, Phase C.1) tracks
the real, **not-yet-built** mechanism:

> "N3: node-agent mTLS or signed JWT with 14-day grandfathering for existing agents."

So: there is no existing volunteer-token contract to comply with today, and
inventing one client-side would (a) not be enforced by the edge anyway, since
the edge doesn't check for it, and (b) likely conflict with whichever of
{mTLS, signed JWT} the monorepo team eventually picks for N3. This repo's
node-agent already complies with the current, intentional design (open
registration). This plan therefore:
- Does **not** add a client-side token/credential gate.
- Documents the real state honestly in the README (Phase 3 below): the
  *program* is by-invitation (sign up at projektlustro.eu, get pointed at an
  edge URL), but the *protocol* doesn't yet enforce that cryptographically —
  N3 is the tracked follow-up, owned by the monorepo, not this repo.
- Keeps the Docker/CI changes below decoupled from N3 so they can land now
  without inventing scope this repo doesn't own.

## Phase 1: Multi-stage Dockerfile on Docker Hardened Images ✅ Complete

**Actual result (implemented on branch `docker-dhi-packaging`)**: used
`dhi.io/python:3.13-dev` / `dhi.io/python:3.13` (not `3.12` — 3.12 no longer
appeared to be a current DHI tag at implementation time; verify before
long-term reliance). **`docker build`/`docker run` succeeded with NO `docker
login dhi.io` at all** — the community tier pulled anonymously. This resolves
the open question in Phase 2 below: the existing PR-time `docker-build` job
likely does **not** need a login step added, including for fork PRs. Confirm
this holds in actual GitHub Actions runners (not just a local dev machine)
before relying on it. All automated checks in this phase's success criteria
ran for real and passed: non-root (uid 65532), `import node_agent.cli`
succeeds (no libc/`cryptography` mismatch), `HOME` prints `/agent`, no shell
in the runtime image, `pytest -q` still green (46 passed).

Docker made the full DHI catalog free (Apache-2.0) in Dec 2025; the community
tier is pulled from `dhi.io/<image>:<tag>` after `docker login dhi.io`. DHI
images run as non-root **by default** (no `USER` directive needed), and ship
a `-dev` variant (shells/pip/compilers) for the build stage plus a minimal
variant (no shell, no package manager) for runtime — so dependencies must be
installed in the `-dev` stage and copied into the minimal runtime stage.

### Changes

#### File: `Dockerfile`
- **What**: Replace the single-stage `python:3.12-slim` build with a two-stage
  build: `dhi.io/python:3.12-dev` (or the current DHI dev tag — pin exactly,
  see below) for `pip install --target`, then `dhi.io/python:3.12` (minimal,
  non-root by default) as the runtime stage, copying only the installed
  packages + `node_agent/`.
- **Where**: whole file.
- **Rationale**: Matches Docker's documented DHI Python pattern; keeps the
  existing "outbound-only, no published ports" comment and adds the DHI
  provenance/signing story the README already promises.
- **Code sketch**:
  ```dockerfile
  # syntax=docker/dockerfile:1

  # Sandboxed volunteer classifier. Outbound-only by design: the agent code
  # only ever talks to the configured edge URL (see node_agent/egress.py). Run
  # this container with no inbound ports published and, ideally, an egress
  # firewall that allowlists only the edge host as defence-in-depth.

  FROM dhi.io/python:3.12-dev AS build
  WORKDIR /agent
  COPY requirements.txt .
  RUN pip install --no-cache-dir --target=/agent/deps -r requirements.txt

  FROM dhi.io/python:3.12
  WORKDIR /agent
  ENV PYTHONPATH=/agent/deps
  # Fixed, writable HOME so Path.home() (node_agent/keys.py, cli.py) resolves
  # to a known, host-mountable path regardless of what /etc/passwd the DHI
  # runtime image ships for its default non-root user.
  ENV HOME=/agent
  COPY --from=build /agent/deps /agent/deps
  COPY node_agent/ ./node_agent/

  # DHI runtime images already run as a non-root user by default — no USER
  # directive needed.
  ENTRYPOINT ["python", "-m", "node_agent.cli"]
  CMD ["run"]
  ```
- **Note (tag pinning)**: verify the exact current DHI Python tag (`3.12-dev` /
  `3.12-alpine3.22-dev` / etc.) at build time — Docker updates these tags
  frequently and does not use `latest`. Pin the exact tag observed in
  `hub.docker.com/hardened-images/catalog/dhi/python` at implementation time,
  and pin by digest (`@sha256:...`) once the release process is stable, for
  reproducibility.
- **Note (variant match)**: the build and runtime `FROM` lines MUST reference
  the same variant (same libc — alpine vs. debian — and same Python minor
  version). `cryptography` installs a libc-specific compiled wheel in the
  `-dev` stage; copying `/agent/deps` into a runtime stage on a different libc
  produces an image that fails at import time (`import cryptography` inside
  `cli.py`'s import chain), not at `pip install` time — this would only
  surface when someone actually runs the container, not at `docker build`.

### Success Criteria

#### Automated Verification
- [ ] `docker build -t node-agent .` succeeds locally after `docker login dhi.io`
- [ ] Non-root check runs as non-root: `docker run --rm --entrypoint python node-agent -c "import os; assert os.getuid() != 0"`
- [ ] Import sanity (catches a build/runtime variant mismatch): `docker run --rm --entrypoint python node-agent -c "import node_agent.cli"`
- [ ] `HOME` resolves as expected: `docker run --rm --entrypoint python node-agent -c "import pathlib; print(pathlib.Path.home())"` prints `/agent`
- [ ] CI `docker-build` job passes with the new base image (see Phase 2 for the login fix this requires)

#### Manual Verification
- [ ] Image has no shell/package manager reachable at runtime (DHI minimal variant property) — spot check `docker run --rm --entrypoint sh node-agent -c 'echo hi'` fails
- [ ] README's Dockerfile-adjacent comments still match reality

### Dependencies
- Requires: nothing
- Blocks: Phase 2 (CI needs the new Dockerfile to build/push, and the existing PR-time `docker-build` job needs a `dhi.io` login added or it will start failing on every PR — see Phase 2)

## Phase 2: CI — publish + cosign-sign the image (closes existing README gap)

`README.md` already instructs volunteers to `cosign verify` a
`ghcr.io/lustro/node-agent:<tag>` image, but `.github/workflows/ci.yml`'s
`docker-build` job only runs `docker build`, never pushes or signs anything.
This phase makes that instruction true — and, critically, must also fix the
existing `docker-build` job, which breaks the moment Phase 1's `Dockerfile`
starts referencing `dhi.io` (that registry needs an authenticated pull even
on the free/community tier; the current job runs bare `docker build` with no
login at all).

### Changes

#### File: `.github/workflows/ci.yml`
- **What, part A (fix the now-broken PR-time job)**: Add a `dhi.io` login
  step to the existing `docker-build` job so plain `docker build` keeps
  working post-Phase-1. Repo secrets aren't available to `pull_request` runs
  from forks, so external-contributor PRs need an explicit story: either (a)
  confirm `dhi.io`'s community tier allows anonymous/unauthenticated pulls for
  public images and drop the login requirement for `docker-build` entirely, or
  (b) if login is mandatory, restrict `docker-build`'s DHI-dependent step to
  same-repo pushes/PRs (`if: github.event.pull_request.head.repo.full_name == github.repository || github.event_name == 'push'`)
  and accept that fork PRs skip the Docker smoke build (call this out in
  `CONTRIBUTING.md`). **Confirm which of (a)/(b) applies before implementing**
  — this is a blocking prerequisite for Phase 1 to be mergeable, not an
  afterthought.
- **What, part B (new publish job)**: Add a `docker-publish` job, gated on
  `push` to `main` **and on `v*` tags** (the trigger list itself must be
  extended — see below), that: logs into `dhi.io` (DHI base image) and
  `ghcr.io` (publish target) using repo secrets, builds via
  `docker/build-push-action`, pushes both `:<sha>` and the release tag(s) to
  `ghcr.io/<org>/node-agent`, then signs each pushed digest with
  `sigstore/cosign-installer` + keyless `cosign sign`.
- **Where**: extend the workflow's `on:` block (`ci.yml` top) to also trigger
  on tag pushes — today it's `push: branches: [main]` only, so a `v1.0.0` tag
  push never fires the workflow at all, regardless of any `if:` inside a job.
  Add a `docker-publish` job alongside `test` and `docker-build`.
- **Rationale**: The existing `docker-build` job stays as the fast PR-time
  smoke check (build-only, no push); the new job is the release path.
- **Code sketch**:
  ```yaml
  on:
    push:
      branches: [main]
      tags: ['v*']
    pull_request:
      branches: [main]

  jobs:
    # ... existing test / docker-build jobs, docker-build gains a dhi.io
    # login step per part A above ...

    docker-publish:
      needs: [test, docker-build]
      if: github.event_name == 'push'
      runs-on: ubuntu-latest
      permissions:
        contents: read
        packages: write
        id-token: write   # cosign keyless signing
      steps:
        - uses: actions/checkout@v4
        - uses: docker/login-action@v3
          with:
            registry: dhi.io
            username: ${{ secrets.DHI_USERNAME }}
            password: ${{ secrets.DHI_TOKEN }}
        - uses: docker/login-action@v3
          with:
            registry: ghcr.io
            username: ${{ github.actor }}
            password: ${{ secrets.GITHUB_TOKEN }}
        - id: meta
          uses: docker/metadata-action@v5
          with:
            images: ghcr.io/${{ github.repository_owner }}/node-agent
            tags: |
              type=sha
              type=ref,event=tag
        - uses: docker/build-push-action@v6
          id: build
          with:
            push: true
            tags: ${{ steps.meta.outputs.tags }}
        - uses: sigstore/cosign-installer@v3
        - run: cosign sign --yes ghcr.io/${{ github.repository_owner }}/node-agent@${{ steps.build.outputs.digest }}
  ```
  `github.repository_owner` must be lowercase for GHCR (GitHub org/user names
  can contain uppercase; GHCR image paths cannot) — use
  `${{ github.repository_owner_id && github.repository_owner || 'lustro' }}`-style
  lowercasing or hardcode the known-lowercase org name rather than
  interpolating the raw context value if the real org name has mixed case.
- **New repo secrets required** (cannot be created by this plan — a human
  action item): `DHI_USERNAME` / `DHI_TOKEN` (or a Docker PAT) for `docker
  login dhi.io` in CI. GHCR push uses the built-in `GITHUB_TOKEN`.

### Success Criteria

#### Automated Verification
- [ ] Existing `docker-build` job still passes on every PR after Phase 1's `Dockerfile` change (part A above) — this is the regression the adversarial review flagged; do not skip it
- [ ] CI green on a test push/tag: image appears at `ghcr.io/<org>/node-agent:<sha>` **and** at the `v*` tag on an actual tag push
- [ ] `cosign verify --certificate-identity-regexp 'https://github.com/<org>/node-agent/\.github/workflows/ci\.yml@refs/tags/v.*' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' ghcr.io/<org>/node-agent:<tag>` succeeds — pin the identity regexp to *this repo's* release workflow, not `https://github.com/<org>/.*` (which would accept a signature from any workflow in any repo under the org)

#### Manual Verification
- [ ] `DHI_USERNAME`/`DHI_TOKEN` secrets added to the repo by a maintainer with access (cannot be done from a PR)
- [ ] `README.md` `cosign verify` snippet's placeholder identity/issuer swapped for the real `<org>` (Rule #1: same PR)

### Dependencies
- Requires: Phase 1 (new Dockerfile)
- Blocks: Phase 3 (3-step instructions reference the published image)

## Phase 3: README — 3-step run instructions + honest guard framing

### Changes

#### File: `README.md`
- **What**: Replace the current "Usage" section (source-checkout `python -m
  node_agent.cli run` invocation) with a 3-step Docker-based flow, and add a
  short, honest paragraph on the current authorization model: enrollment
  (getting pointed at a real edge URL) is by-invitation via projektlustro.eu,
  but agent registration on the wire (`register-agent`) is intentionally open
  by design today — cryptographic gating (mTLS / signed JWT, tracked as N3 in
  the monorepo roadmap) is planned post-go-live, not yet built. Do not
  document a token flag that doesn't exist.
- **Where**: `## Usage` section (currently lines 74-87).
- **Rationale**: CLAUDE.md Rule #1 requires docs to reflect the *actual* trust
  model; overstating a guard that isn't enforced would be worse than
  documenting today's real (intentionally open, vetting-layered-on-top) state.
- **Code sketch**:
  ```markdown
  ## Getting authorized

  This repo is public — anyone can read the code and verify the guarantees
  below. Running it against a **real** edge, however, means joining the
  volunteer program: sign up at [projektlustro.eu](https://projektlustro.eu)
  to be pointed at the current edge URL. Wire-level agent authorization
  (beyond knowing the edge URL) is on the LUSTRO roadmap — see the "Why this
  is NOT a botnet" section above for what's enforced today.

  ## Run it (3 steps)

  ```bash
  # 1. Verify the release image before running it
  cosign verify \
    --certificate-identity-regexp 'https://github.com/<org>/node-agent/\.github/workflows/ci\.yml@refs/tags/v.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    ghcr.io/<org>/node-agent:<tag>

  # 2. Process one work unit, with the edge URL from projektlustro.eu and
  #    persistent local state (your key + job log survive between runs)
  mkdir -p ~/.lustro-node-agent
  docker run --rm \
    -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
    -e LUSTRO_NODE_EDGE_URL=https://edge.lustro.example \
    ghcr.io/<org>/node-agent:<tag>
  # `node-agent run` is one-shot (pulls + processes a single work unit then
  # exits) — schedule this on a cron/timer to keep contributing continuously.

  # 3. Inspect every job you've processed (radical inspectability)
  docker run --rm -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
    ghcr.io/<org>/node-agent:<tag> dump-log
  ```
  ```
  Note: `HOME=/agent` is fixed by the Phase 1 Dockerfile, so
  `~/.lustro-node-agent:/agent/.lustro-node-agent` is a stable mount target —
  no need to probe the image for it. What still needs a manual check on a
  real Linux host: the bind-mounted directory is created by the *host* user
  (or root, via `mkdir -p` above, if Docker auto-creates it), while the DHI
  non-root user has a different, fixed UID inside the container — `keys.py`'s
  `os.chmod(p.parent, 0o700)` on first run will raise `PermissionError` if
  that UID doesn't own the mounted directory. Confirm the DHI runtime user's
  UID once Phase 1's base image is pinned and document either
  `docker run --user "$(id -u):$(id -g)"` or a `chown` step for the host
  directory before first run.

#### File: `AGENTS.md` / LUSTRO docs-site pointer
- **What**: No content change needed here (Rule #1 mirror file is generic),
  but this PR's description must note the docs-site update is owed separately
  in the monorepo (`docs-site/docs/` — how-to/run-node-agent, security/trust-model)
  since that site isn't in this repo.

### Success Criteria

#### Automated Verification
- [ ] `pytest -q` still green (no code touched in this phase)
- [ ] Markdown renders correctly (spot-check, no linter configured in this repo)

#### Manual Verification
- [ ] A volunteer unfamiliar with the repo can go from "nothing" to "processed one work unit" in the 3 documented steps (one-shot per run, not a long-running loop — wording must not imply otherwise)
- [ ] `<org>`/`<tag>` placeholders replaced with real values before merge
- [ ] On a real Linux host, step 2's volume mount doesn't fail with `PermissionError` on first run (UID ownership check, see note above)
- [ ] LUSTRO docs-site (monorepo) updated in a companion PR per Rule #1

### Dependencies
- Requires: Phase 1 (real base image / home-dir path), Phase 2 (published+signed image reference)
- Blocks: nothing

## Out of scope (tracked elsewhere, not invented here)
- **N3 (node-agent mTLS or signed JWT, 14-day grandfathering)** — the actual
  future mechanism for cryptographically gating "authorized volunteers only."
  Owned by the monorepo (`thoughts/shared/plans/2026-07-06-mvp-v2-post-review.md`,
  Phase C.1), scheduled post-go-live. This plan deliberately does not
  pre-implement a competing client-side credential; when N3 lands, this repo
  will need a follow-up PR (new CLI flag/cert mount + README update).

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Existing PR-time `docker-build` job breaks the moment Phase 1's `Dockerfile` switches to `dhi.io` (no login today; fork PRs get no secrets either way) | High (day 1 of Phase 1) | High | Explicit Phase 1→2 dependency + Phase 2 part A resolves this before Phase 1 can be considered mergeable; must confirm anonymous-pull vs. mandatory-login for `dhi.io` first |
| DHI tag drifts / build breaks CI (no `latest` tag, frequent updates) | Medium | Low | Pin an exact tag (and later a digest) rather than a moving alias; CI failure is loud and safe (build-only job fails, no bad image published) |
| Build-stage and runtime-stage DHI variants mismatch (different libc/Python minor), producing an image that builds fine but fails at import time | Medium | High | Phase 1's variant-match note + the new `import node_agent.cli` smoke check catches this before merge, not after a volunteer hits it |
| `DHI_USERNAME`/`DHI_TOKEN` secrets missing until a maintainer adds them | High (day 1) | Low | `docker-publish` job simply fails to log in — doesn't block `test`, does block `docker-build`/publish (see first row) |
| Tag push (`v*`) never triggers the workflow because the `on:` block only lists branch pushes | High (until fixed) | High | Phase 2 explicitly extends `on.push.tags` — called out as a required change, not left implicit in the job's `if:` |
| Volume-mount UID mismatch: host-created `~/.lustro-node-agent` isn't owned by the DHI container's non-root UID, so `keys.py`'s `chmod` raises on first run | Medium | High (blocks step 2 of the documented flow entirely) | Phase 3 note flags `--user "$(id -u):$(id -g)"` / chown as required manual verification before merge |
| README's "getting authorized" framing reads as stronger than what the protocol enforces, if worded carelessly | Low | Medium | Phase 3 wording is deliberately explicit that wire-level gating (N3) is not yet built — avoid implying a guarantee that isn't real |

## Rollback Strategy
Each phase is an independent, revertable commit: Phase 1 (Dockerfile) reverts to the prior single-stage `python:3.12-slim` Dockerfile (already known-good, in git history); Phase 2 (CI publish job) is additive and can be disabled by removing the job without touching `test`/`docker-build`; Phase 3 (README) is docs-only.

## File Ownership Summary
| File | Phase | Change Type |
|------|-------|-------------|
| `Dockerfile` | 1 | Modify |
| `.github/workflows/ci.yml` | 2 | Modify |
| `README.md` | 3 | Modify |
