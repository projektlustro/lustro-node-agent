"""Regression tests for the WASM fetch transport (browser backend).

Bugs caught by the live in-browser gate (apps/public-site/scripts/
sim-live-wasm-node.mjs) against the production edge — the fakes in
test_node_agent.py never exercised the REAL FetchBackend code paths:

1. ``except js.JSError`` — that attribute does not exist under Pyodide 0.27
   (it is ``pyodide.ffi.JsException``), so evaluating the except clause raised
   AttributeError and masked the real network error.
2. ``resp.body.getReader()`` locks the body stream synchronously in JS, so the
   ``resp.text()`` fallback died with "body stream is locked" — and the reader
   path needed ``js._read_chunk``/``js._close_reader`` helpers nothing defines.
3. ``client.pull_and_process`` uses ``with client.stream(...) as resp:`` but
   ``_FetchResponse`` had no context-manager protocol.
4. The client calls ``resp.iter_bytes(chunk_size=...)`` (httpx signature) but
   ``_FetchResponse.iter_bytes`` took no kwargs -> TypeError on the first
   non-204 work unit.
"""

import json
from pathlib import Path

import pytest

from node_agent.transport import (
    MAX_WU_RESPONSE_BYTES,
    FetchBackend,
    TransportError,
    _FetchResponse,
)

SRC = Path(__file__).resolve().parent.parent / "node_agent" / "transport.py"


def test_fetch_backend_never_uses_nonexistent_js_JSError():
    src = SRC.read_text()
    assert "except js.JSError" not in src
    assert "from pyodide.ffi import JsException" in src


def test_fetch_backend_does_not_lock_the_body_stream():
    # getReader() locks the ReadableStream synchronously; under syncify there is
    # no way to pump it, and it breaks the resp.text() fallback.
    src = SRC.read_text()
    fetch_body = src.split("def _fetch", 1)[1]
    assert "_syncify(resp.body.getReader())" not in fetch_body
    assert "reader = resp.body.getReader()" not in fetch_body


def test_fetch_response_supports_the_context_manager_protocol():
    resp = _FetchResponse(status=200, text='{"ok": true}')
    with resp as r:
        assert r is resp
        assert r.json() == {"ok": True}
    assert resp._closed is True


def test_iter_bytes_accepts_httpx_chunk_size_kwarg():
    resp = _FetchResponse(status=200, text="hello world")
    chunks = list(resp.iter_bytes(chunk_size=64 * 1024))
    assert chunks == [b"hello world"]


def test_iter_bytes_enforces_the_size_limit():
    resp = _FetchResponse(status=200, text="x" * (MAX_WU_RESPONSE_BYTES + 1))
    with pytest.raises(TransportError, match="too large"):
        list(resp.iter_bytes(chunk_size=1024))


def test_raise_for_status_includes_body_excerpt():
    resp = _FetchResponse(status=500, text="boom")
    with pytest.raises(TransportError, match="HTTP 500: boom"):
        resp.raise_for_status()


def test_json_roundtrip():
    resp = _FetchResponse(status=200, text=json.dumps({"wu_id": "abc"}))
    assert resp.json() == {"wu_id": "abc"}


def test_stream_method_exists_on_fetch_backend():
    # client.pull_and_process requires a stream() method on the backend.
    assert hasattr(FetchBackend, "stream")
