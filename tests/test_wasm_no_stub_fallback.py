"""RED: the browser WASM node must never emit a stub `factual, 0` fallback
(plan §4.5). Without a verified signed model artifact, classification must
visibly fail — not return a constant stub result.
"""

import importlib

import pytest


def _wasm():
    return importlib.import_module("node_agent.wasm")


class _FakeStore:
    def load_seed(self):
        return b"\x01" * 32

    def save_seed(self, seed):
        pass

    def append(self, row):
        pass

    def clear(self):
        pass


def _node(wasm, monkeypatch):
    monkeypatch.setattr(wasm, "FetchBackend", lambda: object())
    return wasm._BrowserNode(edge="http://edge.test", on_step=lambda s: None, store=_FakeStore())


def test_classifier_is_not_stub_by_default(monkeypatch):
    wasm = _wasm()
    from node_agent.classifier import StubClassifier

    node = _node(wasm, monkeypatch)
    client = node._ensure_client()
    assert not isinstance(client._classifier, StubClassifier)


def test_classification_without_verified_model_fails_visibly(monkeypatch):
    wasm = _wasm()
    node = _node(wasm, monkeypatch)
    client = node._ensure_client()
    with pytest.raises(wasm.ModelUnavailable):
        client._classifier.classify({"text": "x", "lang": "pl"})
