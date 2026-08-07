"""Regression: the WASM node must run with a pinned core key.

The browser boot (apps/public-site/app/node/page.tsx) calls
``node_agent.wasm.new_node(edge, on_step)`` and then ``run_once()``. Before this
fix ``new_node`` took no pinned key and never seeded
``LUSTRO_NODE_AGENT_PINNED_KEY_B64``, so ``_effective_pinned_key()`` returned ""
and every real (core-signed) work unit was rejected fail-closed with::

    CorePinError: no pinned core public key configured (fail-closed)

even though the page had the correct key in hand. These tests pin the key
through the WASM entry point exactly as the browser does, and verify a
core-signed WU now verifies instead of being rejected.
"""

import base64
import json
import sys
import types

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from node_agent import _ed25519_pure as ed
from node_agent import core_pin
from node_agent.client import canonical_wu_bytes
from node_agent.crypto import PureKeyring
from node_agent import wasm


@pytest.fixture(autouse=True)
def _clean_pin_env(monkeypatch):
    # The WASM node relies solely on os.environ for its pinned key; make sure no
    # ambient dev flag or override leaks in and masks the bug/fix.
    monkeypatch.delenv("LUSTRO_NODE_AGENT_PINNED_KEY_B64", raising=False)
    monkeypatch.delenv("LUSTRO_NODE_AGENT_DEV", raising=False)
    monkeypatch.setattr(
        core_pin, "PINNED_CORE_PUBLIC_KEY_B64", core_pin._default_pinned_key_b64()
    )
    # BrowserStore() (built inside new_node) imports `js`; stub it for CPython.
    js_mod = types.ModuleType("js")
    js_mod._idbGet = lambda *_a, **_k: None
    js_mod._idbSet = lambda *_a, **_k: True
    js_mod._idbClear = lambda *_a, **_k: True
    monkeypatch.setitem(sys.modules, "js", js_mod)
    ffi = types.ModuleType("pyodide")
    ffi_mod = types.ModuleType("pyodide.ffi")
    ffi_mod.run_sync = lambda p: p
    monkeypatch.setitem(sys.modules, "pyodide", ffi)
    monkeypatch.setitem(sys.modules, "pyodide.ffi", ffi_mod)
    yield


def _make_core():
    priv = Ed25519PrivateKey.generate()
    raw_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return priv, raw_b64


def test_new_node_without_pinned_key_still_fails_closed():
    """Guard: omitting the key keeps the fail-closed contract (never trust all)."""
    wasm.new_node("https://projektlustro.eu", lambda _m: None)
    assert core_pin._effective_pinned_key() == ""


def test_new_node_pins_key_into_environment():
    """new_node(pinned_key_b64=...) makes that key the effective pinned key."""
    _priv, raw_b64 = _make_core()
    wasm.new_node("https://projektlustro.eu", lambda _m: None, pinned_key_b64=raw_b64)
    assert core_pin._effective_pinned_key() == raw_b64


def test_pinned_wasm_node_verifies_core_signed_wu(monkeypatch):
    """End-to-end: with the key pinned via new_node, a core-signed WU verifies
    instead of raising CorePinError (the exact browser failure)."""
    priv, raw_b64 = _make_core()
    wasm.new_node("https://projektlustro.eu", lambda _m: None, pinned_key_b64=raw_b64)

    wu = {
        "wu_id": "w1",
        "kind": "text",
        "payload": {"text": "x"},
        "core_pubkey_id": "lustro-core-key-v1",
    }
    sig = priv.sign(canonical_wu_bytes(wu))
    # Falls through to the effective (now pinned) key — must NOT raise.
    core_pin.verify_wu_signature(
        canonical_wu_bytes(wu), sig, "lustro-core-key-v1"
    )
