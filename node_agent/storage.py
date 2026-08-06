"""Browser persistence for the WASM node: agent seed + inspectable job log.

The CLI keeps these on the filesystem (``keys.py`` -> ``~/.lustro-node-agent/
agent_ed25519.key`` 0600; ``joblog.py`` -> ``joblog.jsonl``). In the browser
there is no filesystem, so we persist to IndexedDB. Trust model matches the CLI:
the volunteer's own machine/sandbox is the boundary, and the user can wipe all
local state (clears the IndexedDB store) — the "one-command leave" guarantee.

The Python side here is thin: it calls three JS helpers installed by the page
bootstrap (``/node`` in apps/public-site) — ``_idbGet``/``_idbSet``/``_idbClear``
— syncifying their promises. Only importable under Pyodide.
"""

from __future__ import annotations

import json
import time
from typing import Any


def _syncify(promise: Any) -> Any:
    from pyodide.ffi import run_sync

    return run_sync(promise)


class BrowserStore:
    """IndexedDB-backed store for the agent seed and the append-only job log.

    Two logical keys live in one object store (``"lustro-node-agent"``):
      * ``"seed"``  -> base64 of the 32-byte Ed25519 seed,
      * ``"joblog"`` -> a single JSON-encoded array of rows (append-only).
    """

    STORE = "lustro-node-agent"

    def __init__(self) -> None:
        import js  # noqa: F401  — present only under Pyodide

    # --- seed (private, never transmitted) ---
    def load_seed(self) -> bytes | None:
        import js

        raw = _syncify(js._idbGet(self.STORE, "seed"))
        if not raw:
            return None
        import base64

        return base64.b64decode(raw)

    def save_seed(self, seed: bytes) -> None:
        import base64
        import js

        _syncify(js._idbSet(self.STORE, "seed", base64.b64encode(seed).decode()))

    # --- joblog (radical inspectability) ---
    def append(self, entry: dict[str, Any]) -> None:
        import js

        rows = self.read_all()
        rows.append({"ts": time.time(), **entry})
        _syncify(js._idbSet(self.STORE, "joblog", json.dumps(rows)))

    def read_all(self) -> list[dict[str, Any]]:
        import js

        raw = _syncify(js._idbGet(self.STORE, "joblog"))
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return []
        return data if isinstance(data, list) else []

    def clear(self) -> None:
        """One-command leave: wipe the seed and the job log."""
        import js

        _syncify(js._idbClear(self.STORE))
