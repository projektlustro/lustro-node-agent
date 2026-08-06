"""HTTP transport backends.

``NodeAgentClient`` touches the network through a tiny surface: ``GET`` a work
unit, ``POST`` a result, and ``raise_for_status`` on the response. This module
abstracts it so the same client loop runs over ``httpx`` (CLI) or the browser
``fetch`` (WASM), with the egress guard still the single chokepoint in both.

The fetch backend uses Pyodide's syncify to await the JS ``fetch`` promise
synchronously, so the client stays a plain sync API. It is only importable under
Pyodide; importing it elsewhere is a no-op so the CLI never pulls in ``js``.
"""

from __future__ import annotations

import json
from typing import Any, Protocol


class TransportError(Exception):
    """Raised by a backend on a non-2xx HTTP response (fetch backend)."""


class _Response(Protocol):
    status_code: int

    def json(self) -> Any: ...
    def raise_for_status(self) -> None: ...
    def close(self) -> None: ...


class HttpClient(Protocol):
    def get(self, url: str) -> _Response: ...
    def post(self, url: str, json: Any) -> _Response: ...
    def close(self) -> None: ...


class HttpxBackend:
    """httpx-backed client (CLI). Wraps the existing behaviour 1:1."""

    def __init__(self, timeout: float = 30) -> None:
        import httpx

        self._client = httpx.Client(timeout=timeout)

    def get(self, url: str) -> _Response:
        return self._client.get(url)

    def post(self, url: str, json: Any) -> _Response:
        return self._client.post(url, json=json)

    def close(self) -> None:
        self._client.close()


def _syncify(promise: Any) -> Any:
    """Await a JS Promise synchronously under Pyodide."""
    from pyodide.ffi import run_sync

    return run_sync(promise)


class _FetchResponse:
    """Response shape from a browser ``fetch`` (status_code/json/raise_for_status)."""

    def __init__(self, status: int, text: str) -> None:
        self.status_code = status
        self._text = text

    def json(self) -> Any:
        return json.loads(self._text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise TransportError(f"HTTP {self.status_code}: {self._text[:200]}")

    def close(self) -> None:
        pass


class FetchBackend:
    """Browser fetch-backed client (WASM). Uses ``fetch`` via syncify.

    Pyodide only. The egress guard in ``NodeAgentClient`` already restricts the
    URL to the allowlisted edge before any fetch happens, so this never reaches
    an off-host destination.
    """

    def __init__(self, timeout: float = 30) -> None:
        self._timeout = timeout

    def _fetch(self, url: str, *, method: str, body: str | None) -> _FetchResponse:
        import js

        # Enforce the timeout: a hanging edge would otherwise block the main
        # thread indefinitely (syncify is synchronous). AbortController fires
        # after self._timeout seconds and rejects the fetch promise.
        controller = js.AbortController.new()
        js.setTimeout(lambda: controller.abort(), int(self._timeout * 1000))
        opts = {"method": method, "signal": controller.signal}
        if body is not None:
            opts["body"] = body
            opts["headers"] = {"Content-Type": "application/json"}
        opts_js = _to_js_object(opts)
        try:
            resp = _syncify(js.fetch(url, opts_js))
            text = _syncify(resp.text())
        except Exception as e:  # AbortError or network failure
            raise TransportError(f"fetch {method} {url} failed/aborted: {e}") from e
        return _FetchResponse(status=int(resp.status), text=text)

    def get(self, url: str) -> _FetchResponse:
        return self._fetch(url, method="GET", body=None)

    def post(self, url: str, json: Any) -> _FetchResponse:
        return self._fetch(url, method="POST", body=js_dumps(json))

    def close(self) -> None:
        pass


def js_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)


def _to_js_object(py_dict: dict) -> Any:
    """Convert a Python dict to a JS Object (not a Map) for fetch() options.

    Pyodide's to_js defaults to Map; fetch needs a plain Object. Pyodide-FFI
    values already in the dict (an AbortSignal) pass through untouched.
    """
    import js
    from pyodide.ffi import to_js

    return to_js(py_dict, dict_converter=js.Object.fromEntries)
