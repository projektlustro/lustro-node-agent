"""Persistent node-agent runtime (plan §4.1).

`run --once` claims at most one compatible work unit and exits — the bounded
adapter for verified ephemeral/Serverless execution paths. Internal and
volunteer workers share this binary and claim loop; only server-provisioned
trust and plugin allowlists differ.
"""

import json
from pathlib import Path
from types import SimpleNamespace


class LeaseLost(Exception):
    """The lease is expired, superseded, or unknown — fenced (plan §2.4)."""


def _lease_path(state_dir: Path, lease_id: str) -> Path:
    import re

    if not re.fullmatch(r"[A-Za-z0-9_-]+", lease_id or ""):
        raise LeaseLost(f"invalid lease id {lease_id!r}")
    return Path(state_dir) / "leases" / f"{lease_id}.json"


def heartbeat(state_dir, lease_id: str, generation: int) -> None:
    """Refresh a lease heartbeat; raise LeaseLost if the lease is not live."""
    path = _lease_path(state_dir, lease_id)
    if not path.exists():
        raise LeaseLost(f"unknown lease {lease_id}")
    lease = json.loads(path.read_text())
    if lease.get("generation") != generation or lease.get("state") != "live":
        raise LeaseLost(f"lease {lease_id} fenced at generation {generation}")


def run_once(client, state_dir, allow_scraping: bool = False) -> SimpleNamespace:
    """Claim at most one work unit, process it, and exit.

    Scraping-kind work is refused unless the node explicitly opted in with
    --enable-scraping (plan §6.1): default profile stays edge-only.
    """
    wu = client.claim()
    if wu is None:
        return SimpleNamespace(claimed=0, wu_id=None)
    if str(wu.get("kind", "")).startswith("scrape.") and not allow_scraping:
        return SimpleNamespace(claimed=0, wu_id=None, refused="scraping-not-opted-in")
    client.process(wu)
    return SimpleNamespace(claimed=1, wu_id=wu.get("wu_id"))
