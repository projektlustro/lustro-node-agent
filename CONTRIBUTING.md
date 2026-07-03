# Contributing to node-agent

Thank you for your interest in contributing. The node-agent is a defensive,
volunteer-run classifier for LUSTRO; contributions that strengthen its trust
guarantees are welcome.

This repo is the canonical home of the node-agent; the LUSTRO monorepo consumes
it as a git submodule (see ADR-0005 in the LUSTRO docs).

## Local quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

## Pull request conventions

- **Conventional commits.** Use `feat:`, `fix:`, `docs:`, `chore:`, etc. for
  commit messages and PR titles.
- **All tests must be green.** The test suite is expected to be fully green
  before any work is considered done. There are **no acceptable "pre-existing
  failure" excuses** — if `pytest` reports a failure, even one you did not
  introduce, it must be fixed before the PR is merged.

## Coordinate with the LUSTRO docs

Architecture, security, and deployment changes should be reflected in the LUSTRO
documentation site (access-gated while the project is in its pre-launch phase).
Because the monorepo vendors this repository as a submodule, changes here that
affect the trust model or the work-unit contract must stay consistent with the
documented design.
