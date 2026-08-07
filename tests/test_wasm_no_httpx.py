"""WASM node must import without httpx installed.

Pyodide installs only the node-agent wheel (no Requires-Dist), so ``httpx`` is
absent in the browser. Importing ``node_agent.wasm`` — which pulls in
``client.py`` — must not require it, since every WASM call is handed a
FetchBackend and httpx is never instantiated.
"""

import builtins
import importlib
import sys


def test_wasm_imports_without_httpx(monkeypatch):
    for name in list(sys.modules):
        if name == "httpx" or name.startswith("node_agent"):
            monkeypatch.delitem(sys.modules, name, raising=False)

    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "httpx" or name.startswith("httpx."):
            raise ModuleNotFoundError("No module named 'httpx'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    wasm = importlib.import_module("node_agent.wasm")
    assert hasattr(wasm, "new_node")
