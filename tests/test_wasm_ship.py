"""Pyodide-simulation tests for the WASM _BrowserNode log-ship path.

The WASM modules (browser storage, transport, pure crypto) import JS globals
(``js._idbGet``/``_idbSet``/``_idbClear`` and Pyodide's ``run_sync``) that are
only present under Pyodide. These tests install lightweight fakes for those
globals so the ship logic runs in plain CPython, exercising the real
``_BrowserNode._ship_logs`` against a stubbed IndexedDB and ``fetch``.
"""

import json
import sys
import types

import pytest

from node_agent import _ed25519_pure as ed
from node_agent.crypto import PureKeyring
from node_agent import wasm


class FakeIDB:
    """In-memory stand-in for the IndexedDB object store ``js._idb*`` helpers."""

    def __init__(self):
        self._data = {}

    def _idbGet(self, store, key):
        return self._data.get(key)

    def _idbSet(self, store, key, value):
        self._data[key] = value

    def _idbClear(self, store):
        self._data.clear()


class FakeFetch:
    """Records ship requests; caller sets ``status`` to script responses."""

    def __init__(self):
        self.posts = []
        self.status = 200

    def post(self, url, json):
        self.posts.append((url, json))
        return FakeResponse(self.status)

    def get(self, url):
        return FakeResponse(404)

    def close(self):
        pass


class FakeResponse:
    def __init__(self, status):
        self.status_code = status

    def raise_for_status(self):
        pass

    def json(self):
        return {}

    def close(self):
        pass


@pytest.fixture
def wasm_env(tmp_path, monkeypatch):
    """Install fake js / pyodide.ffi globals and a fake fetch backend."""
    idb = FakeIDB()
    js_mod = types.ModuleType("js")
    js_mod._idbGet = idb._idbGet
    js_mod._idbSet = idb._idbSet
    js_mod._idbClear = idb._idbClear
    monkeypatch.setitem(sys.modules, "js", js_mod)

    ffi = types.ModuleType("pyodide")
    ffi_mod = types.ModuleType("pyodide.ffi")
    ffi_mod.run_sync = lambda p: p
    monkeypatch.setitem(sys.modules, "pyodide", ffi)
    monkeypatch.setitem(sys.modules, "pyodide.ffi", ffi_mod)

    fetch = FakeFetch()
    monkeypatch.setattr(wasm, "FetchBackend", lambda **kw: fetch)
    return idb, fetch


def _make_node(env):
    idb, _fetch = env
    node = wasm._BrowserNode("https://projektlustro.eu", lambda m: None, wasm.BrowserStore())
    # Seed a keyring so sign() works.
    seed = ed.generate_seed()
    node._seed = seed
    node._ring = PureKeyring(seed)
    return node


def test_ship_logs_signs_and_post_advances_cursor(wasm_env):
    idb, fetch = wasm_env
    node = _make_node(wasm_env)
    # Seed joblog rows with scraper content that must be stripped.
    idb._data["joblog"] = json.dumps([
        {"ts": 1700000000.0, "event": "wu_processed", "wu_id": "w1", "text_preview": "SECRET", "raw": "RAW"},
        {"ts": 1700000001.0, "event": "no_work"},
    ])
    fetch.status = 200

    node._ship_logs()

    assert len(fetch.posts) == 1
    url, body = fetch.posts[0]
    assert url.endswith("/v1/wu/node-logs")
    assert body["agent_pubkey"] == node.pubkey()
    # batch_bytes must have text_preview AND raw stripped.
    batch = json.loads(_b64(body["batch_bytes"]))
    assert "text_preview" not in batch[0]
    assert "raw" not in batch[0]
    # Signature must verify over the exact batch_bytes.
    ring = PureKeyring(node._seed)
    assert ring.sign(_b64(body["batch_bytes"])) == _b64(body["agent_sig"])
    # Cursor advanced past both rows.
    assert idb._data["ship_cursor"] == 2


@pytest.mark.parametrize("status", [400, 403, 429, 500, 503])
def test_ship_logs_gaps_cursor_on_any_non_2xx(wasm_env, status):
    idb, fetch = wasm_env
    node = _make_node(wasm_env)
    idb._data["joblog"] = json.dumps([{"ts": 1.0, "event": "bad"}])
    fetch.status = status

    node._ship_logs()

    # Any non-2xx rejection gaps the cursor (skips the bad row permanently),
    # mirroring the docker client.
    assert idb._data["ship_cursor"] == 1


def test_ship_logs_does_not_advance_on_transport_error(wasm_env):
    idb, fetch = wasm_env
    node = _make_node(wasm_env)
    idb._data["joblog"] = json.dumps([{"ts": 1.0, "event": "x"}])
    from node_agent.transport import TransportError

    def boom(*a, **k):
        raise TransportError("network down")

    fetch.post = boom
    node._ship_logs()

    # Transport error: cursor must NOT advance (retry next time).
    assert idb._data.get("ship_cursor") is None


def test_ship_logs_no_new_rows_is_noop(wasm_env):
    idb, fetch = wasm_env
    node = _make_node(wasm_env)
    idb._data["joblog"] = json.dumps([{"ts": 1.0, "event": "already_shipped"}])
    idb._data["ship_cursor"] = 1

    node._ship_logs()

    assert fetch.posts == []


def test_ship_logs_best_effort_on_unexpected_error(wasm_env):
    idb, fetch = wasm_env
    node = _make_node(wasm_env)
    idb._data["joblog"] = "not valid json"  # read_all returns [] -> no-op, safe
    node._ship_logs()  # must not raise
    # A node with no rows simply does nothing.
    assert fetch.posts == []


def _b64(s):
    import base64

    return base64.b64decode(s)