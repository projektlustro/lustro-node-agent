---
date: 2026-07-10
commit: 8b217f7012bbf6d7a3a867c9b3988fb61a1d64c3
branch: main
tags: [joblog, inspectability, local-ui, sse]
status: draft
---
# Research: Local live log wall for the node-agent job log

## Summary
The agent already records every processed work unit to a local append-only JSONL
file (`node_agent/joblog.py`). Volunteers can dump it with `node-agent dump-log`.
"Live log wall" is interpreted as a **local, read-only web dashboard** that
visualizes the same log in real time, started by a new `node-agent serve-log`
subcommand. It adds no new network egress, no new dependencies, and binds to
`127.0.0.1` by default so it does not change the agent loop's "outbound-only"
posture unless the volunteer explicitly opts in to exposing it.

## Files Involved

| File | Layer | Purpose |
|------|-------|---------|
| `node_agent/joblog.py` | Log store | Append-only JSONL; needs a blocking `iter_lines(follow=True)` generator for SSE |
| `node_agent/logwall.py` | New server | `ThreadingHTTPServer`, routes `/` (HTML), `/api/log` (JSON history), `/events` (SSE tail) |
| `node_agent/cli.py` | CLI | Add `serve-log` subcommand with `--host`, `--port`, `--no-open` |
| `README.md` | Docs | Document the new command and update the "Why this is NOT a botnet" framing |
| `tests/test_logwall.py` | Tests | Unit tests for endpoints, SSE tail, filtering, write rejection, localhost binding |
| `Dockerfile` | Container | No change needed; image still exposes no ports by default |

## Data Flow

1. `node-agent run --edge <url>` (`cli.py:cmd_run`) appends a record to
   `~/.lustro-node-agent/joblog.jsonl` via `JobLog.append()`.
2. `node-agent serve-log` starts `LogWallServer` bound to `127.0.0.1:8787`.
3. Browser loads `/` and receives a self-contained HTML/JS page.
4. JS fetches `/api/log?limit=100` for recent history and opens an `EventSource`
   to `/events`.
5. `LogWallHandler._serve_events()` calls `JobLog.iter_lines(follow=True)`,
   which polls the file and yields new records as SSE `data:` lines.
6. JS renders each record into the wall. No data leaves the volunteer's machine.

## Existing Patterns

- **JobLog**: append-only JSONL, `0600` file / `0700` dir permissions. Adding a
  read-only iterator does not change its security properties.
- **CLI subcommands**: `cli.py` already registers `run`, `dump-log`, `leave`
  with argparse; `serve-log` follows the same pattern.
- **Fail-closed / local-only**: `keys.py` generates keys locally; `egress.py`
  restricts outbound traffic. The log wall must not make outbound calls.
- **No-dependency ethos**: `requirements.txt` only contains `cryptography`,
  `httpx`, `pytest`. The dashboard must stay stdlib-only.

## External Dependencies

None. The dashboard uses `http.server`, `socketserver`, `threading`,
`webbrowser`, and `urllib.parse` from the Python standard library. The browser
page is self-contained (no CDN).

## Open Questions / Assumptions

1. **"Live log wall" scope**: assumed to mean a local web dashboard, not a CLI
   tail or remote aggregation wall. If the intended scope differs, the plan must
   be rewritten.
2. **Authorization**: assumed none required because the server is local-only
   (`127.0.0.1`) and read-only. A future hardening item could be a
   host-header/HMAC check, but that is out of scope.
3. **Bind address**: default `127.0.0.1`; `--host` allows override. Binding to
   `0.0.0.0` is allowed but documented as a user risk.
4. **Filtering**: simple query-string filter on `/api/log` (`?event=...`,
   `?q=...`, `?limit=...`). Client-side filtering for the live stream.
