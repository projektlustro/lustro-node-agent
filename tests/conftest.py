"""Shared test fixtures.

Isolates every test's on-disk anti-replay store to a per-test tmp path so the
suite never touches (or is contaminated by) the real ~/.lustro-node-agent
state, and so tests that construct a client without an explicit ``seen_path``
still get a clean, isolated store.
"""

import pytest

from node_agent import client as _client


@pytest.fixture(autouse=True)
def _isolated_seen_path(tmp_path, monkeypatch):
    monkeypatch.setattr(
        _client, "DEFAULT_SEEN_PATH", tmp_path / "seen.jsonl", raising=True
    )
    yield
