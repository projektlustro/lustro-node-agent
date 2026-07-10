---
date: 2026-07-10
commit: 28f7bb4011fc6249c6bb4d855e563512be504a16
branch: feat/live-log-wall
ticket: null
status: draft
---
# Plan: Fix `serve-log --host ::1` crash and correct the false "fixed" claim in the plan doc

## Summary
`node-agent serve-log --host ::1` (or any IPv6 literal, or a hostname that
doesn't resolve, or a port already in use) crashes with an uncaught
`OSError`/`socket.gaierror` traceback and exit code 1, because
`ThreadingHTTPServer.__init__` performs the actual socket bind and
`LogWallServer.__init__` doesn't catch its failure. The existing plan doc
(`thoughts/shared/plans/2026-07-10-live-log-wall.md`) claims `--host ::1` was
fixed during the "Final pre-commit adversarial review" round; in reality only
an unrelated warning-suppression allowlist entry was edited, and `/verify`
caught the crash still live on the branch.

**Root-cause framing** (per an adversarial review of the first draft of this
plan): the bug is not "IPv6 literals aren't handled" — it's "nothing catches
a bind failure at construction time." A first draft of this plan pre-checked
only for IPv6 literals via `ipaddress.ip_address()`, which (a) still let the
bracketed form `[::1]` through uncaught — `ip_address("[::1]")` itself raises
`ValueError` and falls through as "not IPv6" — and (b) left every other
unresolvable-host or port-in-use case crashing identically. This revised plan
instead wraps the one call that actually fails (`LogWallServer(...)`
construction) in `try/except OSError`, which is a smaller diff (no new
import, no separate detection logic) and closes the entire crash class at
once: `::1`, `[::1]`, a typo'd hostname, and `EADDRINUSE` all become the same
clean `error: ...` + exit 2, consistent with how `LUSTRO_LOGWALL_PORT` garbage
is already handled two lines above.

**Decision** (confirmed with user): reject IPv6 literals cleanly, do not add
IPv6 bind support. `ThreadingHTTPServer` staying IPv4-only was never a real
requirement — `::1` acceptance was a NIT-level side effect of the second
adversarial review's allowlist edit, not a feature anyone asked for. Adding
real `AF_INET6` support would be new, untested surface (no CI guarantee IPv6
loopback is even available in sandboxed/CI environments) for a capability
nobody needs.

## Research References
- [thoughts/shared/plans/2026-07-10-live-log-wall.md](2026-07-10-live-log-wall.md) — the plan whose "Final pre-commit adversarial review" section contains the false claim being corrected here.

## Implementation deltas (what shipped vs. the sketches below)
Recorded here so this doc doesn't repeat the code/doc-drift it exists to fix.
The sketches further down are the original design; the shipped code differs in
three small, deliberate ways (all confirmed by live runs + `pytest -q` = 65):
1. **`except (OSError, OverflowError)`**, not `except OSError`. An out-of-range
   port (e.g. `--port 99999`) raises `OverflowError` at bind time, not
   `OSError` — it's part of the same "construction-time bind failed" class the
   plan set out to close, so the catch was widened. `node_agent/cli.py:113`.
2. **5 new tests, not 4 → 65 passed, not 64.** A third test,
   `test_cli_serve_log_rejects_out_of_range_port`, covers the `OverflowError`
   arm above. All CLI-invoking tests pass `--no-open` so a should-fail case
   that ever unexpectedly binds can't open a browser / block in
   `serve_forever()` (fails loud, not hangs).
3. **Port-in-use test cleanup uses `busy._httpd.server_close()`**, not
   `busy.shutdown()`. `shutdown()` deadlocks when `serve_forever()` was never
   started (it blocks on an event only that loop sets); `server_close()`
   releases the listening socket directly. `tests/test_e2e_smoke.py`.
The non-localhost warning allowlist was deliberately **kept** at
`("127.0.0.1", "localhost")` — an interim agent added `::1`/`[::1]` to it, but
that suppresses an accurate reachability warning for a host that then fails to
bind anyway, so it was reverted.

## Phase 1: Catch server-construction failures cleanly in `cmd_serve_log`

### Changes

#### File: `node_agent/cli.py`
- **What**: Wrap the `LogWallServer(...)` construction call in
  `try/except OSError`, printing a clean `error: ...` to stderr and returning
  2 instead of letting the bind failure propagate as an uncaught traceback.
  `socket.gaierror` (unresolvable/unsupported host, e.g. an IPv6 literal) and
  a plain `OSError` (e.g. `EADDRINUSE` — port already in use) are both
  `OSError` subclasses, so one `except` clause covers the whole
  "construction-time bind failed" class, not just the IPv6 shape `/verify`
  happened to hit first.
- **Where**: `cmd_serve_log()`, `cli.py:89-115`, wrapping the
  `LogWallServer(DEFAULT_JOBLOG_PATH, host=host, port=port)` call at
  `cli.py:111`. The existing non-localhost warning (`cli.py:106-110`) stays
  where it is — it fires before the bind is attempted, same as today, since a
  warning about reachability is still accurate information even when the
  bind then fails for an unrelated reason (e.g. port in use).
- **Rationale**: Matches the existing error-handling convention in the same
  function (the `LUSTRO_LOGWALL_PORT` garbage-value handler two lines above
  already does `try/except` + `error:` + `return 2`). Catching at the actual
  failure point, rather than pre-validating one input shape, is both the
  smaller diff (no new import, no separate IPv6-detection branch to keep in
  sync with the real failure condition) and the complete fix — it can't miss
  a host-value shape the way an `ipaddress`-based pre-check missed the
  bracketed `[::1]` form. `node_agent/logwall.py` itself is left unchanged —
  `LogWallServer` stays a thin IPv4-only wrapper; the guard belongs in the
  CLI layer where all other input-validation error handling for this command
  already lives.
- **Code sketch**:
  ```python
  def cmd_serve_log(args: argparse.Namespace) -> int:
      """Start the local log-wall dashboard."""
      from node_agent.logwall import LogWallServer, DEFAULT_HOST, DEFAULT_PORT

      host = (
          args.host
          if args.host is not None
          else os.environ.get("LUSTRO_LOGWALL_HOST", DEFAULT_HOST)
      )
      if args.port is not None:
          port = args.port
      else:
          try:
              port = int(os.environ.get("LUSTRO_LOGWALL_PORT", DEFAULT_PORT))
          except ValueError:
              print("error: LUSTRO_LOGWALL_PORT must be an integer", file=sys.stderr)
              return 2
      if host not in ("127.0.0.1", "localhost"):
          print(
              f"warning: binding to {host}; dashboard reachable beyond this machine",
              file=sys.stderr,
          )
      try:
          server = LogWallServer(DEFAULT_JOBLOG_PATH, host=host, port=port)
      except OSError as exc:
          print(f"error: cannot bind {host}:{port}: {exc}", file=sys.stderr)
          return 2
      try:
          server.start(open_browser=not args.no_open)
      except KeyboardInterrupt:
          pass
      return 0
  ```
  No import changes. This covers, verified against the actual failure mode
  each produces: `--host ::1`, `--host [::1]`, `--host ::`, a typo'd/dead
  hostname, and a port already bound by another process — all become the
  same one-line `error:` + exit 2 instead of a traceback. It does **not**
  change behavior for any value that already worked (`127.0.0.1`,
  `localhost`, `0.0.0.0`, any other valid IPv4 literal) — those still bind
  successfully and `except OSError` is never entered.

### Success Criteria

#### Automated Verification
- [ ] `pytest -q` fully green (existing suite; no existing test currently
      exercises a construction-time bind failure on `serve-log`, add one
      below).
- [ ] New unit test asserts `cli.main(["serve-log", "--host", "::1", "--port", "0"])`
      returns `2` and prints an `error:` line to stderr containing `::1`, not
      a traceback (see Phase 2).
- [ ] New unit test (or a parametrized case of the same test) covers the
      bracketed form `--host [::1]` identically, proving the fix isn't
      shape-specific.
- [ ] `python -m node_agent.cli serve-log --host ::1 --port 0` exits 2 with a
      one-line `error:` message, no Python traceback (manual double-check of
      the automated case above, run for real).
- [ ] `python -m node_agent.cli serve-log --host [::1] --port 0` exits 2 with
      a one-line `error:` message, no Python traceback.

#### Manual Verification
- [ ] Run `node-agent serve-log --host ::1` from a real terminal (not piped)
      and confirm the output is the clean one-line error; process exits
      immediately, no Ctrl-C needed.
- [ ] Start `node-agent serve-log --no-open --port <N>` once, then start a
      second `node-agent serve-log --no-open --port <N>` on the same port
      while the first is still running — confirm the second exits 2 with a
      clean `error:` message (`EADDRINUSE`) instead of a traceback. This is
      not IPv6-specific but is the other real construction-time failure this
      fix closes; worth confirming live since the automated suite can't
      easily hold a background bind open across a test.

### Dependencies
- Requires: nothing
- Blocks: Phase 2 (test), Phase 3 (docs correction references this fix)

## Phase 2: Regression test

### Changes

#### File: `tests/test_e2e_smoke.py`
- **What**: Add CLI-level tests alongside the existing `cmd_run`-focused tests
  (`test_cli_run_requires_edge` at `tests/test_e2e_smoke.py:190` is the
  closest existing pattern: call `cli.main([...])`, assert the return code
  and a `capsys`-captured stderr message), covering both the bare and
  bracketed IPv6-literal forms so the fix is proven to work at the
  construction-failure level rather than for one specific string shape, plus
  a same-port-twice test proving the fix also covers `EADDRINUSE` (the other
  real construction-time failure, not just IPv6).
- **Where**: new test functions near `test_cli_run_requires_edge`
  (`tests/test_e2e_smoke.py:190-193`).
- **Rationale**: This exact regression — "claimed fixed, still crashes" — is
  what `/verify` caught precisely because no automated test exercised it. A
  first draft of this plan's test only covered `--host ::1`; an adversarial
  review pointed out that a detection scheme keyed on one string shape (the
  original `ipaddress`-based pre-check) could pass that test while still
  crashing on `[::1]`. Testing against the actual fix (a catch-all
  `except OSError` at construction) means any input that reaches that
  `except` block is covered by construction, but the parametrized/bracketed
  case and the `EADDRINUSE` case are kept as explicit tests anyway — they're
  what makes this a regression test for "the whole failure class," not just
  for whichever single repro `/verify` happened to use.
- **Code sketch**:
  ```python
  import pytest

  @pytest.mark.parametrize("host", ["::1", "[::1]", "::"])
  def test_cli_serve_log_rejects_unbindable_host(host, capsys):
      """serve-log only supports IPv4 binds; an unresolvable/IPv6 host must
      exit 2 with a clear error, not crash with an uncaught OSError."""
      assert cli.main(["serve-log", "--host", host, "--port", "0"]) == 2
      err = capsys.readouterr().err
      assert "error:" in err


  def test_cli_serve_log_rejects_port_already_in_use(tmp_path, capsys):
      """A second serve-log on an already-bound port must exit 2 cleanly,
      not crash with an uncaught OSError (EADDRINUSE) -- the fix catches the
      construction failure generally, not just the IPv6 case /verify found."""
      from node_agent.logwall import LogWallServer

      busy = LogWallServer(tmp_path / "joblog.jsonl", host="127.0.0.1", port=0)
      try:
          assert cli.main(
              ["serve-log", "--host", "127.0.0.1", "--port", str(busy.port)]
          ) == 2
          err = capsys.readouterr().err
          assert "error:" in err
      finally:
          busy.shutdown()
  ```
  Note: `tmp_path`, not a hardcoded `/tmp` path — `JobLog.__init__` calls
  `os.chmod` on the joblog's parent directory, which fails with
  `PermissionError` if that parent is `/tmp` itself under a sandboxed
  environment (hit live earlier in this session). Every other test in this
  suite already uses `tmp_path` for exactly this reason; this test sketch
  must not be the one exception.
  Uses `pytest`'s built-in exception propagation implicitly: if the fix in
  Phase 1 is missing, `LogWallServer.__init__` raises an uncaught `OSError`
  subclass, which is an uncaught exception in `cli.main()` — either test
  fails with that traceback surfacing directly, no need for an explicit
  `pytest.raises` assertion to prove the crash is gone.

### Success Criteria

#### Automated Verification
- [ ] `pytest tests/test_e2e_smoke.py -k "serve_log" -q` passes (3 new test
      cases: 3 parametrized IPv6/wildcard hosts + 1 port-in-use case, run as
      4 collected tests).
- [ ] `pytest -q` fully green (64 passed: 60 existing + 4 new).

#### Manual Verification
- [ ] None required.

### Dependencies
- Requires: Phase 1
- Blocks: nothing

## Phase 3: Correct the false claim in the existing plan doc

### Changes

#### File: `thoughts/shared/plans/2026-07-10-live-log-wall.md`
- **What**: Replace the inaccurate closing sentence of the "Final pre-commit
  adversarial review" section, which currently reads as though the crash
  itself was fixed. Correct it to state what actually happened (an allowlist
  edit, not a fix) and point to this plan for the real fix.
- **Where**: `thoughts/shared/plans/2026-07-10-live-log-wall.md:497-499`.
- **Rationale**: `/verify` explicitly flagged this as a claim/diff mismatch —
  "the documentation asserts something the running code contradicts." Plans
  in this repo are treated as durable review artifacts (per `/dev:create-plan`
  conventions); leaving a false "fixed" claim in place after it's been
  disproven live would let the same mismatch resurface in a future session
  that trusts the doc without re-verifying.
- **Code sketch**:
  ```markdown
  Also fixed: `--host ::1` was advertised as accepted (CLI + README) but crashed
  with `socket.gaierror` at startup (`ThreadingHTTPServer` is IPv4-only) —
  dropped from both the CLI's non-localhost-warning allowlist and the README.
  ```
  becomes:
  ```markdown
  **Correction (caught by `/verify` on 2026-07-10, not actually fixed here):**
  this section originally claimed `--host ::1` was fixed by dropping it from
  the CLI's non-localhost-warning allowlist and the README. That edit was
  made, but it did not address the underlying crash — `LogWallServer` still
  raised an uncaught `OSError`/`socket.gaierror` for any IPv6 literal, since
  `ThreadingHTTPServer` binds IPv4 only. Live verification on a real running
  process reproduced the traceback after this plan's own "fixed" claim was
  written. See
  [2026-07-10-fix-serve-log-host-ipv6-crash.md](2026-07-10-fix-serve-log-host-ipv6-crash.md)
  for the actual fix: a `try/except OSError` around server construction that
  catches the whole class of construction-time bind failures (unresolvable
  host, IPv6 literal in any form, port already in use), not only the one
  input shape this session happened to test. IPv6 bind support itself is
  intentionally not added.
  ```

### Success Criteria

#### Automated Verification
- [ ] None (docs-only phase); `pytest -q` unaffected.

#### Manual Verification
- [ ] The corrected section no longer claims the crash was fixed before it
      actually was.
- [ ] The cross-reference link resolves to this plan file.

### Dependencies
- Requires: Phase 1, Phase 2 (so the correction can link to a real, verified fix rather than another unverified claim)
- Blocks: nothing

## Out of Scope
- Adding real IPv6 bind support (`AF_INET6`) — explicitly declined; see
  Summary.
- Re-verifying the `panel/clusters` badge change in the `lustro` monorepo —
  flagged by `/verify` as unexercised in a browser, but that's a separate
  repo/change not touched by this plan. Address separately if wanted.
- Any other findings from the two adversarial-review rounds — `/verify`
  confirmed those (no-replay, heartbeat, read-only-on-leave, `0.0.0.0`
  Host-guard, corrupt-line survival) are correctly fixed on live processes;
  only `--host ::1` was a false claim.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `except OSError` in `cmd_serve_log` accidentally swallows a bind failure that should surface differently (e.g. a permissions error from binding a privileged port) | Low | Low | The `except` block still prints the underlying exception text (`{exc}`) and exits non-zero — nothing is silently discarded, it's reformatted from a traceback into a one-line message with the same information |
| A construction-time failure mode exists that this catch doesn't cover (something raising outside `OSError`, e.g. a `ValueError` from a malformed port already handled earlier, or something in `make_handler`) | Low | Medium | Phase 1's manual verification explicitly exercises two independent real failure modes (IPv6 literal, port-in-use) rather than relying on the automated test's synthetic case alone; if a third shape is found later, the same `except OSError` block is the single place to extend |
| Future contributor reintroduces IPv6 host support (or any host-input change) without preserving this catch | Low | Medium | Regression tests in Phase 2 fail loudly (crash resurfaces as an uncaught exception in the test itself) rather than needing a human to notice; the parametrized IPv6 cases plus the port-in-use case together prove the fix is at the failure point, not tied to one input shape |

## Rollback Strategy
Each phase is independently revertable:
- Phase 1: revert the `try/except OSError` wrapping around `LogWallServer(...)` construction in `cmd_serve_log()`.
- Phase 2: delete the new test functions.
- Phase 3: revert the plan-doc correction (docs-only, no runtime effect either way).

## File Ownership Summary
| File | Phase | Change Type |
|------|-------|-------------|
| `node_agent/cli.py` | 1 | Modify |
| `tests/test_e2e_smoke.py` | 2 | Modify |
| `thoughts/shared/plans/2026-07-10-live-log-wall.md` | 3 | Modify |

## Review Questions — resolved
All open questions were put to the user directly and confirmed the plan as
written; no further changes needed before implementation:
1. Reject IPv6 cleanly rather than add real support (see Summary) — confirmed.
2. Catch at the `LogWallServer(...)` construction site (`except OSError`)
   rather than pre-validate one input shape — confirmed; supersedes the first
   draft's `ipaddress.ip_address()` pre-check.
3. Test location: `tests/test_e2e_smoke.py` (as planned), not
   `tests/test_logwall.py` — confirmed.
4. Port-in-use test: an in-process second `LogWallServer` occupying the port
   is an acceptable proxy for `EADDRINUSE`, no subprocess needed — confirmed.
5. Error message: stay generic (`error: cannot bind {host}:{port}: {exc}`),
   no IPv6-specific wording — confirmed.
