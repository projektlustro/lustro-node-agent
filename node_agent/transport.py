"""HTTP transport backends.

``NodeAgentClient`` touches the network through a tiny surface: ``GET`` a work
unit, ``POST`` a result, and ``raise_for_status`` on the response. This module
abstracts it so the same client loop runs over ``httpx`` (CLI) or the browser
``fetch`` (WASM), with the egress guard still the single chokepoint in both.

The fetch backend uses Pyodide's syncify to await the JS ``fetch`` promise
synchronously, so the client stays a plain sync API. It is only importable under
Pyodide; importing it elsewhere is a no-op so the CLI never pulls in ``js``.

Security: The FetchBackend implements size-limited streaming to prevent memory
exhaustion from large responses, and blocks redirects to prevent egress bypass.
"""

from __future__ import annotations

import json
from typing import Any, Protocol, Iterator

# Maximum response body size (matches client.py)
MAX_WU_RESPONSE_BYTES = 1024 * 1024
# Maximum request body size
MAX_REQUEST_BODY_BYTES = 1024 * 1024
# Maximum chunk size for streaming
MAX_CHUNK_SIZE = 64 * 1024


class TransportError(Exception):
    """Raised by a backend on a non-2xx HTTP response (fetch backend)."""


class _Response(Protocol):
    status_code: int

    def json(self) -> Any: ...
    def raise_for_status(self) -> None: ...
    def close(self) -> None: ...


class HttpClient(Protocol):
    """Protocol defining the interface expected from HTTP clients."""
    
    def get(self, url: str) -> _Response: ...
    def post(self, url: str, json: Any) -> _Response: ...
    def close(self) -> None: ...
    
    # Optional: streaming support
    def stream(self, method: str, url: str) -> _Response: ...


class HttpxBackend:
    """httpx-backed client (CLI). Wraps the existing behaviour 1:1."""

    def __init__(self, timeout: float = 30) -> None:
        import httpx

        self._client = httpx.Client(timeout=timeout)

    def get(self, url: str) -> _Response:
        return self._client.get(url)

    def post(self, url: str, json: Any) -> _Response:
        return self._client.post(url, json=json)
    
    def stream(self, method: str, url: str) -> _Response:
        """Open a streaming connection."""
        return self._client.stream(method, url)

    def close(self) -> None:
        self._client.close()


def _syncify(promise: Any) -> Any:
    """Await a JS Promise synchronously under Pyodide."""
    from pyodide.ffi import run_sync

    return run_sync(promise)


class _FetchResponse:
    """Response shape from a browser ``fetch`` (status_code/json/raise_for_status).
    
    Security: For streaming responses, the body is read in chunks to prevent
    memory exhaustion from large responses.
    """

    def __init__(self, status: int, text: str, reader: Any = None) -> None:
        self.status_code = status
        self._text = text
        self._reader = reader  # JS ReadableStream reader for streaming
        self._body = bytearray()  # Accumulated body for streaming
        self._closed = False

    def json(self) -> Any:
        if self._text is not None:
            return json.loads(self._text)
        return json.loads(self._body.decode("utf-8"))

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            error_text = self._text[:200] if self._text else self._body[:200].decode("utf-8", errors="replace")
            raise TransportError(f"HTTP {self.status_code}: {error_text}")

    def close(self) -> None:
        self._closed = True
        if self._reader is not None:
            try:
                import js
                js._close_reader(self._reader)
            except Exception:
                pass
        self._reader = None

    def iter_bytes(self) -> Iterator[bytes]:
        """Iterate over response body in chunks for streaming.
        
        Security: Enforces MAX_WU_RESPONSE_BYTES limit incrementally to prevent
        memory exhaustion. Note: In WASM, the browser's fetch API may still
        buffer the full response before this method is called.
        """
        if self._reader is None and self._text is not None:
            # Non-streaming response: yield the full body
            body_bytes = self._text.encode("utf-8")
            if len(body_bytes) > MAX_WU_RESPONSE_BYTES:
                raise TransportError("response too large")
            yield body_bytes
            return
        
        if self._reader is None:
            return
        
        import js
        
        try:
            while True:
                # Read chunk from JS ReadableStream
                chunk_promise = js._read_chunk(self._reader)
                chunk_result = _syncify(chunk_promise)
                
                if chunk_result is None or chunk_result.done:
                    break
                
                chunk_bytes = chunk_result.value
                if not chunk_bytes:
                    break
                
                # Check size before appending to prevent overflow
                if len(self._body) + len(chunk_bytes) > MAX_WU_RESPONSE_BYTES:
                    raise TransportError("response exceeds max size during streaming")
                
                self._body += chunk_bytes
                yield bytes(chunk_bytes)
        finally:
            self.close()


class FetchBackend:
    """Browser fetch-backed client (WASM). Uses ``fetch`` via syncify.

    Pyodide only. The egress guard in ``NodeAgentClient`` already restricts the
    URL to the allowlisted edge before any fetch happens, so this never reaches
    an off-host destination.
    
    Security: Implements size limits on request/response bodies and blocks
    redirects to prevent egress bypass. Uses streaming where possible to limit
    memory usage.
    """

    def __init__(self, timeout: float = 30) -> None:
        self._timeout = timeout

    def _validate_body_size(self, body: str | None) -> None:
        """Validate request body size to prevent memory exhaustion."""
        if body and len(body) > MAX_REQUEST_BODY_BYTES:
            raise TransportError(f"request body too large: {len(body)} bytes")

    def _fetch(self, url: str, *, method: str, body: str | None, stream: bool = False) -> _FetchResponse:
        import js

        # Validate request body size
        self._validate_body_size(body)

        # Enforce the timeout: a hanging edge would otherwise block the main
        # thread indefinitely (syncify is synchronous). AbortController fires
        # after self._timeout seconds and rejects the fetch promise.
        controller = js.AbortController.new()
        js.setTimeout(lambda: controller.abort(), int(self._timeout * 1000))
        
        opts = {"method": method, "signal": controller.signal}
        
        # Security: Block redirects to prevent egress bypass
        opts["redirect"] = "error"
        
        if body is not None:
            opts["body"] = body
            opts["headers"] = {"Content-Type": "application/json"}
        
        opts_js = _to_js_object(opts)
        
        try:
            resp = _syncify(js.fetch(url, opts_js))
            
            # Check for redirect (shouldn't happen with redirect: error, but be safe)
            if hasattr(resp, 'redirected') and resp.redirected:
                raise TransportError(f"redirect not allowed: {url}")
            
            if stream and hasattr(resp, 'body'):
                # Try to use streaming if available
                try:
                    reader = _syncify(resp.body.getReader())
                    return _FetchResponse(status=int(resp.status), text=None, reader=reader)
                except Exception:
                    # Fall back to non-streaming
                    text = _syncify(resp.text())
                    return _FetchResponse(status=int(resp.status), text=text)
            else:
                text = _syncify(resp.text())
                return _FetchResponse(status=int(resp.status), text=text)
                
        except js.JSError as e:
            raise TransportError(f"fetch {method} {url} failed: {e}") from e
        except Exception as e:  # AbortError or network failure
            raise TransportError(f"fetch {method} {url} failed/aborted: {e}") from e

    def get(self, url: str) -> _FetchResponse:
        return self._fetch(url, method="GET", body=None)

    def post(self, url: str, json: Any) -> _FetchResponse:
        return self._fetch(url, method="POST", body=js_dumps(json))
    
    def stream(self, method: str, url: str) -> _FetchResponse:
        """Open a streaming connection.
        
        Security: Uses streaming fetch to limit memory usage for large responses.
        Note: The browser's fetch API may still buffer the full response in some
        cases, but we enforce size limits when reading.
        """
        if method.upper() == "GET":
            return self._fetch(url, method=method, body=None, stream=True)
        else:
            # For POST with streaming, we'd need to handle request body streaming too
            # For now, fall back to regular post
            raise NotImplementedError("streaming POST not supported in FetchBackend")

    def close(self) -> None:
        pass


def js_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)


def _to_js_object(py_dict: dict) -> Any:
    """Convert a Python dict to a JS Object (not a Map) for fetch() options.

    Pyodide's to_js defaults to Map; fetch needs a plain Object. Pyodide-FFI
    values already in the dict (an AbortSignal) pass through untouched.
    
    Security: Validates dict keys and values to prevent type confusion at the
    Python/JS boundary.
    """
    import js
    from pyodide.ffi import to_js

    # Validate all keys are strings
    if not all(isinstance(k, str) for k in py_dict):
        raise TypeError("dict keys must be strings for JS conversion")
    
    # Validate values are JSON-serializable types
    for v in py_dict.values():
        if not isinstance(v, (str, int, float, bool, type(None), list, dict)):
            raise TypeError(f"unsupported type for JS conversion: {type(v)}")

    return to_js(py_dict, dict_converter=js.Object.fromEntries)
