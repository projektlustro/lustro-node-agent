# CLAUDE.md

Guidance for Claude Code (and other agents) working in the `lustro-node-agent`
repository — the canonical, public, volunteer-run classifier for LUSTRO. The
monorepo consumes this repo as a git submodule (see ADR-0005 in the LUSTRO docs).

## ⚠️ CRITICAL RULE #1: Keep docs and issues in sync with the code

Any change to this agent's behavior, trust guarantees, or security posture must be
reflected in the same PR:

- Update this repo's `README.md` (the canonical run/verify instructions) and, when the
  change affects architecture or the trust model, note it for the LUSTRO documentation
  site (`docs-site/docs/` in the monorepo — architecture, security/trust-model,
  how-to/run-node-agent).
- If the change introduces or fixes a security issue, file/update it in the **private**
  LUSTRO monorepo tracker (`projektlustro/lustro`, labels `security` + `priority:*`).
  **This repo is public — never open a public issue describing an unfixed
  vulnerability.** Report privately per `SECURITY.md`.

## Trust invariants (do not regress)

Egress allowlist (single host), pinned core key with fail-closed verification,
anti-replay, local-only Ed25519 key generation, and the one-command `leave`. Every
test is named after an invariant — keep them green.

## Tests

`pytest` must be fully green before any change is considered done.
