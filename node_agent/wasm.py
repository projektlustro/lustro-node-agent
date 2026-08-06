"""Pyodide entry point for the in-browser WASM node.

Wires the pure-Python crypto/transport/storage backends into the SAME
NodeAgentClient loop the CLI uses, so the browser node does byte-identical work
against the real edge (https://projektlustro.eu/v1/wu): register, pull, verify
the core signature, classify, sign with the local Ed25519 key, POST the result.

Called from JS on the Start button. Fetches are awaited via Pyodide syncify, so
the Python stays a plain sync API. ``httpx`` is imported by client.py but never
instantiated here — every call is handed a ``FetchBackend`` instead.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Callable

from node_agent import _ed25519_pure as ed25519
from node_agent.classifier import StubClassifier
from node_agent.client import NodeAgentClient
from node_agent.crypto import PureKeyring
from node_agent.storage import BrowserStore
from node_agent.transport import FetchBackend, TransportError

# Same origin as the page — the WASM node is served from projektlustro.eu, so
# /v1/wu is same-origin (no CORS, no subdomain, no extra DNS).
DEFAULT_EDGE = "https://projektlustro.eu"

# Ship cursor key in IndexedDB — tracks the index of the last shipped joblog row.
SHIP_CURSOR_KEY = "ship_cursor"


def _syncify(promise: Any) -> Any:
    """Await a JS Promise synchronously under Pyodide."""
    from pyodide.ffi import run_sync

    return run_sync(promise)


def _get_ship_cursor() -> int:
    """Read the ship cursor from IndexedDB. Defaults to 0."""
    import js

    raw = _syncify(js._idbGet(BrowserStore.STORE, SHIP_CURSOR_KEY))
    if raw is None:
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _set_ship_cursor(cursor: int) -> None:
    """Persist the ship cursor to IndexedDB."""
    import js

    _syncify(js._idbSet(BrowserStore.STORE, SHIP_CURSOR_KEY, cursor))


class _BrowserNode:
    def __init__(
        self,
        edge: str,
        on_step: Callable[[str], None],
        store: BrowserStore,
    ) -> None:
        self._edge = edge
        self._on_step = on_step
        self._store = store
        self._seed: bytes | None = None
        self._ring: PureKeyring | None = None
        self._http = FetchBackend()
        self._client: NodeAgentClient | None = None
        self._registered = False

    def _ensure_keyring(self) -> PureKeyring:
        if self._ring is None:
            seed = self._store.load_seed()
            if seed is None:
                seed = ed25519.generate_seed()
                self._store.save_seed(seed)
                self._on_step(f"keygen    -> new local Ed25519 seed (stored in IndexedDB)")
            self._seed = seed
            self._ring = PureKeyring(seed)
        return self._ring

    def _ensure_client(self) -> NodeAgentClient:
        if self._client is None:
            self._client = NodeAgentClient(
                self._edge,
                StubClassifier(),
                self._ensure_keyring(),
                self._store,  # BrowserStore.append is the job-log surface
            )
        return self._client

    def pubkey(self) -> str:
        return self._ensure_keyring().public_key_raw_b64()

    def register(self) -> str:
        self._ensure_client().register_agent(http=self._http)
        self._registered = True
        return self.pubkey()

    def run_once(self) -> dict | None:
        """Register on first call, then pull+process one work unit. Returns the
        posted result, or None when there is no work (204)."""
        client = self._ensure_client()
        if not self._registered:
            client.register_agent(http=self._http)
            self._registered = True
        return client.pull_and_process(http=self._http)

    def leave(self) -> None:
        """One-command leave: wipe the local seed + job log."""
        self._store.clear()
        self._seed = None
        self._ring = None
        self._client = None
        self._registered = False
        self._on_step("leave     -> wiped local seed + job log")

    def _ship_logs(self) -> None:
        """Ship unshipped joblog rows to the central Loki wall via the edge relay.

        Mirrors ``NodeAgentClient._ship_logs`` (docker) but reads the joblog
        from BrowserStore and persists the ship cursor to IndexedDB instead of a
        byte-offset file. Scraped content (``text_preview`` and ``raw``) is
        stripped before the batch leaves the volunteer machine. The exact bytes
        POSTed as ``batch_bytes`` are what ``agent_sig`` signs over, so the core
        verifies without re-serializing.

        Crypto-agnostic: depends only on this node's keyring ``sign(bytes)``
        (PureKeyring). Best-effort: never raises. On a rejected (non-2xx) batch
        the cursor gaps past it so a poisoned batch can't wedge the ship loop; on
        a transport error the cursor is left in place for a later retry.
        """
        try:
            ring = self._ensure_keyring()
            rows = self._store.read_all()
            cursor = _get_ship_cursor()

            if cursor >= len(rows):
                return  # Nothing new to ship

            # Slice unshipped rows (oldest first) and strip scraper content that
            # must never leave the volunteer machine.
            stripped_rows = [
                {k: v for k, v in row.items() if k not in ("text_preview", "raw")}
                for row in rows[cursor:]
            ]

            if not stripped_rows:
                _set_ship_cursor(len(rows))
                return

            batch_bytes = json.dumps(
                stripped_rows,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")

            body = {
                "agent_pubkey": ring.public_key_raw_b64(),
                "agent_sig": base64.b64encode(ring.sign(batch_bytes)).decode(),
                "batch_bytes": base64.b64encode(batch_bytes).decode(),
            }

            resp = self._http.post(f"{self._edge}/v1/wu/node-logs", json=body)

            if resp.status_code // 100 != 2:
                # Rejected: gap the cursor past the batch so it can't wedge us.
                _set_ship_cursor(len(rows))
                self._on_step(
                    f"ship rejected ({resp.status_code}) — skipped {len(stripped_rows)} rows"
                )
                return
        except TransportError as e:
            # Transport error: keep the cursor so the batch is retried.
            self._on_step(f"ship failed (transport) — will retry next time: {e}")
            return
        except Exception as e:
            # Catch-all: best-effort, never crash the node.
            self._on_step(f"ship failed (unexpected) — skipping: {e}")
            return

        _set_ship_cursor(len(rows))
        self._on_step(f"shipped   -> {len(stripped_rows)} rows to Loki wall")


def new_node(
    edge: str = DEFAULT_EDGE,
    on_step: Callable[[str], None] | None = None,
) -> _BrowserNode:
    return _BrowserNode(edge, on_step or (lambda _msg: None), BrowserStore())


def run_once(edge: str = DEFAULT_EDGE, on_step: Callable[[str], None] | None = None) -> Any:
    """Convenience: build a node and process one work unit (registers if needed)."""
    return new_node(edge, on_step).run_once()
