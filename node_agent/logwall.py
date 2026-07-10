"""Local, read-only live dashboard for the node-agent job log.

Serves a self-contained HTML/JS page on localhost and tails the JSONL joblog
via Server-Sent Events. No new dependencies beyond the Python standard library.
"""

import ipaddress
import json
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from node_agent.joblog import DEFAULT_JOBLOG_PATH, JobLog

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
MAX_API_LOG_BYTES = 10 * 1024 * 1024
DEFAULT_API_LOG_LIMIT = 100
MAX_API_LOG_LIMIT = 1000
MAX_SSE_CLIENTS = 5
SSE_INTERVAL = 0.2

PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LUSTRO node-agent log wall</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #f7f7f7;
  --fg: #111;
  --card: #fff;
  --muted: #666;
  --accent: #2563eb;
  --border: #ddd;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b0c0f;
    --fg: #e5e7eb;
    --card: #15171d;
    --muted: #9ca3af;
    --accent: #60a5fa;
    --border: #2d3139;
  }
}
* { box-sizing: border-box; }
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  margin: 0;
  padding: 1rem;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.5;
}
header { max-width: 960px; margin: 0 auto 1rem; }
h1 { margin: 0 0 0.25rem; font-size: 1.5rem; }
#status { margin: 0 0 1rem; color: var(--muted); font-size: 0.9rem; }
#status.live { color: #16a34a; }
#status.reconnecting { color: #dc2626; }
.controls {
  max-width: 960px;
  margin: 0 auto 1rem;
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  align-items: center;
}
.controls label { font-size: 0.9rem; color: var(--muted); }
.controls input, .controls select {
  padding: 0.35rem 0.5rem;
  border: 1px solid var(--border);
  border-radius: 0.35rem;
  background: var(--card);
  color: var(--fg);
}
#events {
  max-width: 960px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.event {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 0.75rem 1rem;
}
.event.hidden { display: none; }
.event header {
  display: flex;
  gap: 0.75rem;
  align-items: baseline;
  margin: 0 0 0.5rem;
  max-width: none;
}
.event time { font-size: 0.8rem; color: var(--muted); }
.event .kind { font-weight: 600; color: var(--accent); }
.event .wu-id { font-family: monospace; font-size: 0.85rem; }
.event pre {
  margin: 0.5rem 0 0;
  padding: 0.5rem;
  background: rgba(127,127,127,0.08);
  border-radius: 0.35rem;
  overflow-x: auto;
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
</head>
<body>
<header>
  <h1>LUSTRO node-agent log wall</h1>
  <p id="status">connecting…</p>
</header>
<div class="controls">
  <label>Event
    <select id="eventFilter"><option value="">all</option></select>
  </label>
  <label>Search
    <input id="searchFilter" type="search" placeholder="wu_id, label, payload…">
  </label>
  <label>Limit
    <input id="limitInput" type="number" value="100" min="1" max="1000">
  </label>
  <button id="refreshBtn">Refresh</button>
</div>
<main id="events"></main>
<script>
const statusEl = document.getElementById('status');
const eventsEl = document.getElementById('events');
const eventFilter = document.getElementById('eventFilter');
const searchFilter = document.getElementById('searchFilter');
const limitInput = document.getElementById('limitInput');
const refreshBtn = document.getElementById('refreshBtn');

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = cls || '';
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

function clearChildren(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

function createEventEl(rec) {
  const article = document.createElement('article');
  article.className = 'event';
  article.dataset.event = rec.event || '';
  article.dataset.search = JSON.stringify(rec).toLowerCase();

  const header = document.createElement('header');

  const time = document.createElement('time');
  time.textContent = rec.ts ? fmtTime(rec.ts) : '';
  header.appendChild(time);

  const kind = document.createElement('span');
  kind.className = 'kind';
  kind.textContent = rec.event || '';
  header.appendChild(kind);

  if (rec.wu_id) {
    const wu = document.createElement('span');
    wu.className = 'wu-id';
    wu.textContent = rec.wu_id;
    header.appendChild(wu);
  }

  article.appendChild(header);

  const pre = document.createElement('pre');
  pre.textContent = JSON.stringify(rec, null, 2);
  article.appendChild(pre);

  return article;
}

function applyFilter() {
  const ev = eventFilter.value;
  const q = searchFilter.value.trim().toLowerCase();
  for (const el of eventsEl.querySelectorAll('.event')) {
    let visible = true;
    if (ev && el.dataset.event !== ev) visible = false;
    if (q && !el.dataset.search.includes(q)) visible = false;
    el.classList.toggle('hidden', !visible);
  }
}

const MAX_RENDERED_EVENTS = 1000;

function addEvent(rec) {
  eventsEl.prepend(createEventEl(rec));
  while (eventsEl.children.length > MAX_RENDERED_EVENTS) {
    eventsEl.removeChild(eventsEl.lastChild);
  }
  applyFilter();
  populateEventOptions();
}

function populateEventOptions() {
  const seen = new Set();
  for (const el of eventsEl.querySelectorAll('.event')) {
    if (el.dataset.event) seen.add(el.dataset.event);
  }
  const current = eventFilter.value;
  clearChildren(eventFilter);
  const all = document.createElement('option');
  all.value = '';
  all.textContent = 'all';
  eventFilter.appendChild(all);
  for (const e of Array.from(seen).sort()) {
    const opt = document.createElement('option');
    opt.value = e;
    opt.textContent = e;
    eventFilter.appendChild(opt);
  }
  eventFilter.value = current;
}

async function loadHistory() {
  const limit = Math.min(Math.max(parseInt(limitInput.value, 10) || 100, 1), 1000);
  try {
    const resp = await fetch(`/api/log?limit=${limit}`);
    if (!resp.ok) throw new Error(resp.statusText);
    const rows = await resp.json();
    clearChildren(eventsEl);
    rows.slice().reverse().forEach(addEvent);
  } catch (err) {
    statusEl.textContent = 'history load failed: ' + err.message;
  }
}

function connect() {
  setStatus('connecting…');
  const es = new EventSource('/events');
  es.onopen = () => setStatus('live', 'live');
  es.onerror = () => setStatus('reconnecting…', 'reconnecting');
  es.onmessage = (e) => {
    try {
      addEvent(JSON.parse(e.data));
    } catch (err) {
      // ignore malformed SSE data
    }
  };
}

eventFilter.addEventListener('change', applyFilter);
searchFilter.addEventListener('input', applyFilter);
limitInput.addEventListener('change', loadHistory);
refreshBtn.addEventListener('click', loadHistory);

loadHistory();
connect();
</script>
</body>
</html>
"""


class LogWallHandler(BaseHTTPRequestHandler):
    _joblog_path = DEFAULT_JOBLOG_PATH
    _sse_semaphore = None

    def _host_allowed(self):
        """Reject Host headers that are DNS names (the DNS-rebinding vector).

        A literal IP address or ``localhost`` is always accepted regardless of
        the bind address — including on a wildcard (``0.0.0.0``) bind, which is
        what the documented Docker `-p 127.0.0.1:8787:8787` path sends as its
        Host header, and what genuine LAN access by IP relies on. What this
        blocks is an attacker-controlled DNS name that resolves to this host
        (DNS rebinding), which a literal IP can never do.
        """
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]")
        if not host:
            return False
        if host == "localhost":
            return True
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def do_GET(self):
        if not self._host_allowed():
            self._send_json(403, {"error": "host not allowed"})
            return
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
        records = JobLog(self._joblog_path, create=False).read_all()
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
                limit = -1
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
            joblog = JobLog(self._joblog_path, create=False)
            for record in joblog.iter_lines(follow=True, since_end=True):
                if record is None:
                    self.wfile.write(b": keep-alive\n\n")
                else:
                    payload = json.dumps(record, ensure_ascii=False)
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                time.sleep(SSE_INTERVAL)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
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
