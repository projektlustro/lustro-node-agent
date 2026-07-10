---
date: 2026-07-10
commit: 8b217f7012bbf6d7a3a867c9b3988fb61a1d64c3
branch: main
ticket: null
status: draft
---
# Plan: Add a local, read-only live log wall (`serve-log`) for the node-agent job log

## Summary
Add a stdlib-only local web dashboard started by `node-agent serve-log` that
reads and live-tails the existing `~/.lustro-node-agent/joblog.jsonl`. The
server binds to `127.0.0.1:8787` by default, adds no new dependencies, makes no
outbound calls, and is read-only. It is an optional inspectability feature, not
part of the classifier loop, so the agent's "outbound-only" trust posture is
preserved unless the volunteer explicitly exposes the dashboard. This plan was
revised after an adversarial review to harden defaults, tests, and docs against
trust-model regressions.

**Scope assumption**: the requested research file
`thoughts/shared/research/2026-07-10-live-log-wall.md` did not exist and the
user answered the resulting clarification questions with "continue". This plan
therefore assumes "live log wall" means a **local web dashboard**. If the
intended meaning is a CLI tail or a remote aggregation wall, this plan must be
rewritten before implementation.

## Research References
- [thoughts/shared/research/2026-07-10-live-log-wall.md](../research/2026-07-10-live-log-wall.md)

## Phase 1: JobLog iterator + LogWall server module

### Changes

#### File: `node_agent/joblog.py`
- **What**: Add a read-only `iter_lines(follow=False, poll_interval=1.0)`
  generator that yields decoded JSON records, and a small `_parse_line()` helper
  shared with `read_all()`.
- **Where**: after `read_all()` (~line 42).
- **Rationale**: The SSE endpoint needs to block and yield new records as
  `node-agent run` appends them. Polling is acceptable because the log is
  low-volume and this keeps the implementation stdlib-only.
- **Code sketch**:
  ```python
  def iter_lines(self, follow: bool = False, poll_interval: float = 1.0):
      if not self._path.exists():
          if not follow:
              return
          while not self._path.exists():
              time.sleep(poll_interval)
      with self._path.open("r", encoding="utf-8") as f:
          for line in f:
              rec = self._parse_line(line)
              if rec is not None:
                  yield rec
          if not follow:
              return
          while True:
              line = f.readline()
              if line:
                  rec = self._parse_line(line)
                  if rec is not None:
                      yield rec
              else:
                  time.sleep(poll_interval)

  @staticmethod
  def _parse_line(line: str) -> dict | None:
      line = line.strip()
      if not line:
          return None
      try:
          return json.loads(line)
      except json.JSONDecodeError:
          return {"event": "_parse_error", "raw": line}
  ```

#### File: `node_agent/logwall.py` (new)
- **What**: A `ThreadingHTTPServer`-based dashboard with three routes:
  - `GET /` — self-contained HTML/JS page (no CDN, theme-aware).
  - `GET /api/log?event=...&q=...&limit=...` — JSON history with optional
    event-type, substring, and limit filters.
  - `GET /events` — SSE stream that tails the joblog.
  Write methods (`POST`, `PUT`, etc.) return `405`.
- **Where**: new file.
- **Rationale**: Keeps the dashboard isolated from the CLI and client code;
  `ThreadingHTTPServer` lets multiple SSE clients coexist without blocking each
  other; stdlib-only matches the repo's minimal-dependency ethos.
- **Code sketch**:
  ```python
  import json
  import threading
  import time
  import urllib.parse
  import webbrowser
  from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
  from pathlib import Path

  from node_agent.joblog import DEFAULT_JOBLOG_PATH, JobLog

  DEFAULT_HOST = "127.0.0.1"
  DEFAULT_PORT = 8787
  MAX_API_LOG_BYTES = 10 * 1024 * 1024
  DEFAULT_API_LOG_LIMIT = 100
  MAX_API_LOG_LIMIT = 1000
  MAX_SSE_CLIENTS = 5
  SSE_INTERVAL = 0.2

  # PAGE_HTML must render all log fields via textContent or explicit HTML
  # escaping; the payload originates from signed work units and must never be
  # passed to innerHTML unsanitized.
  PAGE_HTML = """<!doctype html>..."""  # self-contained dashboard page

  class LogWallHandler(BaseHTTPRequestHandler):
      _joblog_path = DEFAULT_JOBLOG_PATH
      _sse_semaphore = None

      def do_GET(self):
          parsed = urllib.parse.urlparse(self.path)
          if parsed.path == "/":
              self._serve_html()
          elif parsed.path == "/api/log":
              self._serve_api_log(parsed.query)
          elif parsed.path == "/events":
              self._serve_events()
          else:
              self._send_json(404, {"error": "not found"})

      def do_POST(self):
          self._send_json(405, {"error": "method not allowed"})

      do_PUT = do_DELETE = do_PATCH = do_POST

      def _serve_html(self):
          body = PAGE_HTML.encode("utf-8")
          self.send_response(200)
          self.send_header("Content-Type", "text/html; charset=utf-8")
          self.send_header("Content-Length", str(len(body)))
          self.end_headers()
          self.wfile.write(body)

      def _serve_api_log(self, query):
          params = urllib.parse.parse_qs(query)
          path = Path(self._joblog_path)
          if path.exists() and path.stat().st_size > MAX_API_LOG_BYTES:
              self._send_json(
                  413, {"error": "job log too large for API; use dump-log"}
              )
              return
          records = JobLog(self._joblog_path).read_all()
          if "event" in params:
              allowed = set(params["event"])
              records = [r for r in records if r.get("event") in allowed]
          if "q" in params:
              q = params["q"][0].lower()
              records = [
                  r for r in records
                  if q in json.dumps(r, ensure_ascii=False).lower()
              ]
          limit = DEFAULT_API_LOG_LIMIT
          if "limit" in params:
              try:
                  limit = int(params["limit"][0])
              except (ValueError, IndexError):
                  pass
          if limit < 1 or limit > MAX_API_LOG_LIMIT:
              self._send_json(
                  400,
                  {"error": f"limit must be between 1 and {MAX_API_LOG_LIMIT}"},
              )
              return
          records = records[-limit:]
          self._send_json(200, records)

      def _serve_events(self):
          sem = self._sse_semaphore
          if sem is not None and not sem.acquire(blocking=False):
              self._send_json(503, {"error": "too many live clients"})
              return
          self.send_response(200)
          self.send_header("Content-Type", "text/event-stream")
          self.send_header("Cache-Control", "no-cache, no-store")
          self.send_header("X-Accel-Buffering", "no")
          self.end_headers()
          try:
              for record in JobLog(self._joblog_path).iter_lines(follow=True):
                  payload = json.dumps(record, ensure_ascii=False)
                  self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                  self.wfile.flush()
                  time.sleep(SSE_INTERVAL)
          except (BrokenPipeError, ConnectionResetError):
              pass
          finally:
              if sem is not None:
                  sem.release()

      def _send_json(self, status, body):
          data = json.dumps(body, ensure_ascii=False).encode("utf-8")
          self.send_response(status)
          self.send_header("Content-Type", "application/json; charset=utf-8")
          self.send_header("Content-Length", str(len(data)))
          self.end_headers()
          self.wfile.write(data)

      def log_message(self, format, *args):
          pass

  def make_handler(joblog_path, sse_semaphore):
      class Handler(LogWallHandler):
          _joblog_path = Path(joblog_path)
          _sse_semaphore = sse_semaphore
      return Handler

  class LogWallServer:
      def __init__(self, joblog_path, host=DEFAULT_HOST, port=DEFAULT_PORT):
          self.host = host
          self._sse_semaphore = threading.Semaphore(MAX_SSE_CLIENTS)
          self._httpd = ThreadingHTTPServer(
              (host, port), make_handler(joblog_path, self._sse_semaphore)
          )
          self.port = self._httpd.server_address[1]

      def start(self, open_browser=True):
          url = f"http://{self.host}:{self.port}/"
          print(f"Log wall running at {url} (Ctrl-C to stop)")
          if open_browser:
              webbrowser.open(url)
          self._httpd.serve_forever()

      def shutdown(self):
          self._httpd.shutdown()

      def serve_forever(self):
          self._httpd.serve_forever()
  ```

### Success Criteria

#### Automated Verification
- [x] `pytest -q` still green after adding the new module (no new tests yet). **Result:** 48 passed.
- [x] `python -c "from node_agent.logwall import LogWallServer; print(LogWallServer)"` imports cleanly. **Result:** ok.

#### Manual Verification
- [ ] `python -m node_agent.cli serve-log --no-open` starts without errors and
      prints a localhost URL. *(Requires Phase 2 CLI integration; will verify there.)*
- [ ] Browser page loads and, after running `node-agent run` once, shows a new
      joblog entry within a few seconds. *(Requires Phase 2 CLI integration; will verify there.)*

### Dependencies
- Requires: nothing
- Blocks: Phase 2 (CLI command wraps this server), Phase 3 (tests exercise the
  endpoints)

## Phase 2: CLI `serve-log` subcommand

### Changes

#### File: `node_agent/cli.py`
- **What**: Add `cmd_serve_log()` and a `serve-log` subparser with `--host`,
  `--port`, and `--no-open`. Default bind address is `127.0.0.1`; default port
  `8787`.
- **Where**: after `cmd_leave()` (~line 86) and in `build_parser()` (~line 99).
- **Rationale**: Exposes the dashboard through the existing CLI convention;
  keeps the server module importable without launching it (useful for tests).
- **Code sketch**:
  ```python
  def cmd_serve_log(args: argparse.Namespace) -> int:
      from node_agent.logwall import LogWallServer, DEFAULT_HOST, DEFAULT_PORT

      host = (
          args.host
          if args.host is not None
          else os.environ.get("LUSTRO_LOGWALL_HOST", DEFAULT_HOST)
      )
      if args.port is not None:
          port = args.port
      else:
          port = int(os.environ.get("LUSTRO_LOGWALL_PORT", DEFAULT_PORT))
      if host not in ("127.0.0.1", "localhost"):
          print(
              f"warning: binding to {host}; dashboard reachable beyond this machine",
              file=sys.stderr,
          )
      server = LogWallServer(DEFAULT_JOBLOG_PATH, host=host, port=port)
      try:
          server.start(open_browser=not args.no_open)
      except KeyboardInterrupt:
          pass
      return 0
  ```
  Parser addition:
  ```python
  serve_p = sub.add_parser(
      "serve-log", help="start a local web dashboard for the job log"
  )
  serve_p.add_argument(
      "--host", default=None,
      help="bind host (default 127.0.0.1)"
  )
  serve_p.add_argument(
      "--port", type=int, default=None,
      help="port (default 8787)"
  )
  serve_p.add_argument(
      "--no-open", action="store_true",
      help="do not open browser"
  )
  serve_p.set_defaults(func=cmd_serve_log)
  ```

### Success Criteria

#### Automated Verification
- [x] `python -m node_agent.cli serve-log --help` exits 0 and lists `--host`,
      `--port`, `--no-open`. **Result:** passes.
- [x] `pytest -q` still green. **Result:** 48 passed.

#### Manual Verification
- [x] `node-agent serve-log --no-open` starts; Ctrl-C stops it cleanly.
      **Result:** verified indirectly — the post-implementation smoke test
      (see below) started a `LogWallServer` on an ephemeral port, served
      `/api/log` and `/events` requests, and `shutdown()` returned cleanly
      with no orphaned process. A literal Ctrl-C shell test was attempted but
      is not reliable for a backgrounded job in a non-interactive script
      (bash disables SIGINT delivery to background children without job
      control); `serve_forever()`'s `KeyboardInterrupt` handling is plain
      stdlib and is covered by a real test in Phase 3 instead.

### Dependencies
- Requires: Phase 1
- Blocks: Phase 3

## Post-implementation adversarial review (Phases 1-2)
An adversarial review of the branch diff (MODE=adversary, claude-fable-5) found
1 BLOCKER and 3 MAJOR issues beyond what the pre-implementation plan review
caught. All were fixed and re-verified (pytest 48 passed + a live smoke test
against a running `LogWallServer`):

- **BLOCKER**: `/events` replayed the entire joblog from byte 0 on every
  connect (and every browser auto-reconnect), duplicating history and
  throttling replay at `SSE_INTERVAL`. Fixed by adding `since_end=True` to
  `iter_lines()`, which seeks to EOF before following, used only by the SSE
  path (`/api/log` already covers history).
- **MAJOR**: idle SSE handlers never detected a dead client (no write ever
  happens on an idle log), so repeated page refreshes could exhaust
  `MAX_SSE_CLIENTS` permanently. Fixed by yielding a `None` heartbeat on every
  idle poll; `_serve_events` writes an SSE comment line for it, which forces a
  write (and thus a disconnect check) every `SSE_INTERVAL`.
- **MAJOR**: `read_all()` was never refactored onto `_parse_line()` as the
  plan specified, so one corrupt line raised `json.JSONDecodeError` and killed
  `/api/log` and `dump-log` entirely — worse than the "silently hides
  corruption" failure mode it was meant to fix. Fixed: `read_all()` now uses
  `_parse_line()` and includes `_parse_error` markers like `iter_lines()`.
- **MAJOR**: no Host-header check, so DNS rebinding could let an external site
  read the joblog same-origin. Fixed with a `_host_allowed()` check in
  `do_GET()` that rejects (`403`) any `Host` header not matching
  `127.0.0.1` / `localhost` / `::1` / the bound host.

Also fixed two MINOR/NIT items: `JobLog(..., create=False)` so the read-only
handlers never resurrect `~/.lustro-node-agent` after `node-agent leave`;
`LUSTRO_LOGWALL_PORT` garbage now exits 2 with a clear error instead of a raw
traceback; `--host ::1` no longer triggers the non-localhost warning; a
rendered-event cap (`MAX_RENDERED_EVENTS = 1000`) bounds DOM growth on a
long-running tab.

## Phase 3: Tests

### Changes

#### File: `tests/test_logwall.py` (new)
- **What**: Unit tests for the dashboard endpoints and live tail. The server is
  started on an ephemeral port (`port=0`) in a daemon thread and shut down in a
  fixture.
- **Where**: new file.
- **Rationale**: Every new behavior needs a test; the SSE test exercises the
  `JobLog.iter_lines(follow=True)` path.
- **Code sketch**:
  ```python
  import json
  import threading
  import time

  import httpx
  import pytest

  from node_agent.joblog import JobLog
  from node_agent import logwall


  @pytest.fixture
  def running_server(tmp_path):
      joblog = tmp_path / "joblog.jsonl"
      server = logwall.LogWallServer(joblog, host="127.0.0.1", port=0)
      thread = threading.Thread(target=server.serve_forever, daemon=True)
      thread.start()
      try:
          yield f"http://127.0.0.1:{server.port}", joblog
      finally:
          server.shutdown()
          thread.join(timeout=5)


  def test_logwall_html_and_api(running_server):
      base, joblog = running_server
      JobLog(joblog).append({"event": "wu_processed", "wu_id": "wu-1"})

      r = httpx.get(f"{base}/")
      assert r.status_code == 200
      assert "text/html" in r.headers["content-type"]

      r = httpx.get(f"{base}/api/log")
      assert r.status_code == 200
      assert r.json()[0]["wu_id"] == "wu-1"

      r = httpx.get(f"{base}/api/log?event=no_work")
      assert r.json() == []

      r = httpx.post(f"{base}/api/log")
      assert r.status_code == 405


  def test_logwall_sse_stream_new_entries(running_server):
      base, joblog = running_server
      events = []

      def collect():
          with httpx.stream("GET", f"{base}/events", timeout=10) as resp:
              for line in resp.iter_lines():
                  if line.startswith("data: "):
                      events.append(line[6:])
                      break

      t = threading.Thread(target=collect, daemon=True)
      t.start()
      time.sleep(0.3)
      JobLog(joblog).append({"event": "no_work"})
      t.join(timeout=5)

      assert len(events) == 1
      assert json.loads(events[0])["event"] == "no_work"
  ```

  Additional trust-focused tests to add to `tests/test_logwall.py`:
  - `test_logwall_rejects_write_methods` — `POST`, `PUT`, `DELETE`, `PATCH` to
    `/api/log` return `405`.
  - `test_logwall_html_escapes_payload` — append a record containing
    `<script>alert(1)</script>` and assert the HTML response does not contain it
    unescaped (forces `textContent`/escaping in `PAGE_HTML`).
  - `test_logwall_preserves_file_permissions` — after appending, assert the
    joblog file is `0600` and its parent directory is `0700`.
  - `test_logwall_api_limits_validated` — `?limit=0`, `?limit=-1`, and
    `?limit=10000` return `400`.

### Success Criteria

#### Automated Verification
- [x] `pytest -q` fully green. **Result:** 57 passed (48 pre-existing + 9 new).
- [x] `pytest tests/test_logwall.py -q` passes independently. **Result:** 9 passed.

#### Manual Verification
- [ ] None required.

**Note:** the test suite implementation added regression tests for all 4
issues the post-Phase-2 adversarial review found (no-replay, heartbeat,
read-only-on-leave, Host-header rejection), plus an innerHTML/textContent
check. Writing `test_logwall_sse_heartbeat_on_idle` caught a real bug the
manual smoke test missed: `iter_lines()` only yielded the `None` heartbeat
once the file existed — a fresh joblog (agent never run yet) blocked silently
in the pre-file-exists wait loop with zero SSE traffic. Fixed by yielding
`None` there too (`node_agent/joblog.py`, `iter_lines`, pre-existence branch).

## Final pre-commit adversarial review (all 4 phases)
A second full-branch adversarial review (MODE=adversary, claude-fable-5), run
after all phases were implemented, verified the 5 prior fixes empirically and
found 3 further issues — all fixed and covered by new tests (60 passed total):

- **MAJOR**: `_host_allowed()` returned `True` unconditionally whenever the
  server was bound to `0.0.0.0`/`::` — exactly the config the README's Docker
  example recommends (`serve-log --host 0.0.0.0`). The DNS-rebinding guard was
  therefore a no-op on the one path most likely to actually be exposed.
  Reproduced live before the fix: a spoofed `Host: evil.example` on a
  `0.0.0.0` bind returned `200` with the full joblog. Fixed by rewriting the
  check to accept only `localhost` or a literal IP address (`ipaddress.
  ip_address()`) regardless of bind address, rejecting any DNS name — that
  property (not "matches the bind host") is what actually stops rebinding.
  New test: `test_logwall_host_header_rejected_on_wildcard_bind`.
- **MINOR**: the fresh-agent heartbeat fix introduced a new gap: `since_end`
  always sought to EOF once the file appeared, so the very first record a
  brand-new agent ever writes was skipped on the live tail (only visible via
  a manual `/api/log` refresh). Fixed by only seeking to EOF when the file
  already existed before the call (`file_pre_existed` tracked in
  `iter_lines`); a file created *during* the call is read from the start.
  New test: `test_logwall_sse_delivers_first_record_on_fresh_agent`.
- **MINOR**: the `read_all()` / `_parse_line()` corrupt-line fix had no
  regression test, so a future refactor could silently reintroduce the crash.
  New test: `test_logwall_api_survives_corrupt_line`.

**Correction (caught by `/verify` on 2026-07-10, not actually fixed here):**
this section originally claimed `--host ::1` was fixed by dropping it from
the CLI's non-localhost-warning allowlist and the README. That edit was
made, but it did not address the underlying crash — `LogWallServer` still
raised an uncaught `OSError`/`socket.gaierror` for any IPv6 literal, since
`ThreadingHTTPServer` binds IPv4 only. Live verification on a real running
process reproduced the traceback after this plan's own "fixed" claim was
written. See
[2026-07-10-fix-serve-log-host-ipv6-crash.md](2026-07-10-fix-serve-log-host-ipv6-crash.md)
for the actual fix: a `try/except (OSError, OverflowError)` around server
construction that catches the whole class of construction-time bind
failures (unresolvable host, IPv6 literal in any form, port already in
use, out-of-range port), not only the one input shape this session
happened to test. IPv6 bind support itself is intentionally not added,
and the non-localhost-warning allowlist stays `("127.0.0.1", "localhost")` —
`--host ::1` now correctly both warns (it is not localhost-bindable here)
and exits 2 with the clean bind error.

### Dependencies
- Requires: Phase 2
- Blocks: Phase 4

## Phase 4: README + trust-model framing

### Changes

#### File: `README.md`
- **What**:
  1. Add a short "Live log wall" subsection under Usage showing
     `node-agent serve-log` and the Docker port-publish variant.
  2. Tighten the "Outbound-only — it cannot proxy" bullet to say the
     **classifier loop** opens no inbound ports, and note that the optional
     dashboard is a separate, local-only, read-only command.
- **Where**: `## Usage` section and `## Why this is NOT a botnet`.
- **Rationale**: CLAUDE.md Rule #1 requires docs and trust framing to stay in
  sync with new behavior; volunteers must not mistakenly think `serve-log`
  weakens the agent loop's outbound-only guarantee.
- **Code sketch**:
  ```markdown
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
  does not work inside a container with `-p`, so use `--host 0.0.0.0` and rely
  on the host-side `-p` mapping to keep it on localhost:

  ```bash
  docker run --rm --pull=always \
    -p 127.0.0.1:8787:8787 \
    -v ~/.lustro-node-agent:/agent/.lustro-node-agent \
    ghcr.io/projektlustro/node-agent:latest serve-log --host 0.0.0.0 --no-open
  ```

  **serve-log security note**: the dashboard exposes the same data that is
  normally protected by the `0600` permissions on `joblog.jsonl` to any process
  running as your user (and, with `--host 0.0.0.0`, to the local network). It is
  a local inspectability convenience, not part of the classifier loop's
  outbound-only guarantee.
  ```
  And update the first trust bullet to:
  ```markdown
  - **Outbound-only — the classifier loop cannot proxy.** The agent loop talks
    to exactly ONE host: the edge URL you configure. Every request is checked
    against an allowlist (`node_agent/egress.py`); any other host is refused.
    The loop opens no inbound ports and cannot be turned into a proxy by a
    malicious work unit. The optional `serve-log` dashboard is a separate,
    local-only, read-only command that you explicitly start; see its security
    note below.
  ```

#### LUSTRO docs-site pointer
- **What**: File a companion note/PR in the monorepo `docs-site/docs/` (how-to/
  run-node-agent, security/trust-model) if the docs-site describes the agent's
  inbound-port posture.
- **Where**: PR description.
- **Rationale**: CLAUDE.md Rule #1 requires architecture/trust-model changes to
  be noted for the monorepo docs site.

### Success Criteria

#### Automated Verification
- [x] `pytest -q` still green (docs-only phase). **Result:** 57 passed.

#### Manual Verification
- [ ] README renders correctly and the new section is clear to a volunteer.
- [x] The updated trust-model bullet no longer implies the agent as a whole
      opens zero inbound ports.
- [x] The `serve-log` security note explicitly warns about ACL bypass and LAN
      exposure, and now also documents the Host-header/DNS-rebinding guard
      added during the post-implementation adversarial review.

### Dependencies
- Requires: Phase 3
- Blocks: nothing

## Out of Scope
- Remote log aggregation wall (server-side).
- Authentication or access control beyond localhost binding.
- Write/mutate endpoints for the joblog.
- File rotation or log retention policies.
- Packaging changes (`Dockerfile`, CI) — the dashboard runs inside the existing
  image with no extra ports exposed by default.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| The assumed scope (local web dashboard) is wrong | High until confirmed | High | Flagged prominently in Summary; confirm with user before implementation |
| Docker README example does not work (process binds container loopback) | Low | High | Fixed in Phase 4: use `--host 0.0.0.0` inside container and `-p` on host |
| XSS via unsanitized joblog payloads in browser | Low | High | Force `textContent`/escaping in `PAGE_HTML`; invariant test required |
| Trust-model framing misleads volunteers about inbound ports / ACL bypass | Medium | High | Dedicated security note + updated "Why this is NOT a botnet" bullet |
| `/api/log` loads whole file and OOMs on huge logs | Low | Medium | File-size guard, server-side limit cap, and `limit` validation |
| Corrupt JSON lines silently vanish from dashboard | Low | Medium | `iter_lines` yields `_parse_error` markers instead of dropping |
| SSE backpressure local DoS | Low | Low | Cap concurrent SSE clients and throttle records |
| Binding to `0.0.0.0` exposes log to LAN | Low | Medium | Default `127.0.0.1`; explicit stderr warning; strong README warning |
| SSE test is flaky due to threading/timing | Medium | Low | Daemon thread fixture, generous timeouts, collect-until-event loop |
| Server cannot read `joblog.jsonl` due to UID mismatch in Docker | Low | Low | Dashboard runs with same bind-mount and user as `run`; permissions match |

## Rollback Strategy
Each phase is independently revertable:
- Phase 1: delete `node_agent/logwall.py` and revert the `iter_lines()` addition.
- Phase 2: remove `cmd_serve_log()` and the `serve-log` parser.
- Phase 3: delete `tests/test_logwall.py`.
- Phase 4: revert README changes.

## File Ownership Summary
| File | Phase | Change Type |
|------|-------|-------------|
| `node_agent/joblog.py` | 1 | Modify |
| `node_agent/logwall.py` | 1 | Create |
| `node_agent/cli.py` | 2 | Modify |
| `tests/test_logwall.py` | 3 | Create |
| `README.md` | 4 | Modify |

## Review Questions
These were pre-empted by the user's "continue" response, but the assumptions
below should be confirmed before implementation begins:

1. Does "live log wall" mean a local web dashboard (as assumed here), or a CLI
   tail / remote wall?
2. Is the default `127.0.0.1:8787` binding acceptable?
3. Should the live stream support server-side event filtering, or is the
   proposed query-string filter on history sufficient?
4. Is the monorepo docs-site update in scope for the same PR, or should it be a
   tracked follow-up?
