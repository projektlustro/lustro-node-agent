# AGENTS.md

Agent-facing instructions for `lustro-node-agent`. See `CLAUDE.md` for the full
guidance; this file mirrors the load-bearing rule for non-Claude agents.

## ⚠️ CRITICAL RULE #1: Keep docs and issues in sync with the code

Any change to this agent's behavior, trust guarantees, or security posture must update
the docs in the same PR (this repo's `README.md`, and the LUSTRO documentation site
under `docs-site/docs/` in the monorepo). Security findings go to the **private**
LUSTRO tracker (`projektlustro/lustro`, `security` + `priority:*`) — this repo is
public, so never file a public issue describing an unfixed vulnerability. Report
privately per `SECURITY.md`.
