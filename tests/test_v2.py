import base64
import hashlib
import json
import threading

import httpx
import pytest

from node_agent.cli import build_parser
from node_agent.keys import ensure_keypair


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _input_digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _work_unit(value, digest=None):
    return {
        "wu_id": "wu-test",
        "kind": "nlp.embed.e5",
        "lease_id": "lease-test",
        "generation": 7,
        "lease_seconds": 120,
        "input": value,
        "input_digest": digest or _input_digest(value),
    }


def _client(
    tmp_path,
    response_for,
    *,
    handlers=None,
    heartbeat_interval=30,
    tags=("model:e5-large",),
    role_fallback_seconds=None,
):
    from node_agent.v2 import V2Client

    captured = []

    def handle(request):
        captured.append(request)
        return response_for(request)

    http = httpx.Client(transport=httpx.MockTransport(handle))
    client = V2Client(
        "https://core.example.test",
        ensure_keypair(tmp_path / "agent.key"),
        tags=tags,
        handlers=handlers,
        heartbeat_interval=heartbeat_interval,
        role_fallback_seconds=role_fallback_seconds,
        http_client=http,
    )
    return client, captured


def test_v2_cli_parses_worker_options():
    args = build_parser().parse_args([
        "v2", "run", "--core", "https://core.example.test",
        "--key-file", "/run/agent.key", "--tags", "model:e5-large",
        "--role-fallback-seconds", "900", "--once", "--idle-sleep", "2",
    ])

    assert args.command == "v2"
    assert args.v2_command == "run"
    assert args.core == "https://core.example.test"
    assert args.key_file == "/run/agent.key"
    assert args.tags == ["model:e5-large"]
    assert args.role_fallback_seconds == 900
    assert args.once is True
    assert args.idle_sleep == 2


def test_claim_204_means_no_work_and_request_signature_matches_core_envelope(tmp_path):
    def response_for(request):
        assert request.method == "POST"
        assert request.url.path == "/v2/wu/claim"
        return httpx.Response(204)

    client, captured = _client(tmp_path, response_for, role_fallback_seconds=900)
    try:
        assert client.claim() is None
    finally:
        client.close()

    request = captured[0]
    key_id = request.headers["x-wu-key"]
    timestamp = request.headers["x-wu-timestamp"]
    request_id = request.headers["x-wu-request-id"]
    envelope = {
        "method": request.method,
        "target": request.url.path + (f"?{request.url.query.decode()}" if request.url.query else ""),
        "agent_key_id": key_id,
        "timestamp": timestamp,
        "request_id": request_id,
        "body_digest": "sha256:" + hashlib.sha256(request.content).hexdigest(),
    }
    public_key = ensure_keypair(tmp_path / "agent.key").public_key()
    signature = base64.b64decode(request.headers["x-wu-sig"], validate=True)
    public_key.verify(signature, _canonical(envelope))
    expected_key_id = "ed25519-" + hashlib.sha256(public_key.public_bytes_raw()).hexdigest()[:16]
    assert key_id == expected_key_id
    assert json.loads(request.content) == {
        "tags": ["model:e5-large"],
        "fallback_after_seconds": 900,
    }


def test_signed_target_includes_core_path_prefix(tmp_path):
    from node_agent.v2 import V2Client

    captured = []
    key = ensure_keypair(tmp_path / "agent.key")

    def handle(request):
        captured.append(request)
        return httpx.Response(204)

    http = httpx.Client(transport=httpx.MockTransport(handle))
    client = V2Client(
        "https://core.example.test/proxy/",
        key,
        tags=("model:e5-large",),
        http_client=http,
    )
    try:
        assert client.claim() is None
    finally:
        client.close()

    request = captured[0]
    assert request.url.path == "/proxy/v2/wu/claim"
    envelope = {
        "method": request.method,
        "target": request.url.path,
        "agent_key_id": request.headers["x-wu-key"],
        "timestamp": request.headers["x-wu-timestamp"],
        "request_id": request.headers["x-wu-request-id"],
        "body_digest": "sha256:" + hashlib.sha256(request.content).hexdigest(),
    }
    signature = base64.b64decode(request.headers["x-wu-sig"], validate=True)
    key.public_key().verify(signature, _canonical(envelope))


def test_input_digest_mismatch_refuses_handler_and_result(tmp_path):
    called = []
    unit = _work_unit({"model": "intfloat/multilingual-e5-large", "items": []}, "sha256:wrong")

    def response_for(request):
        if request.url.path == "/v2/wu/claim":
            return httpx.Response(200, json=unit)
        pytest.fail(f"unexpected request: {request.url}")

    class Handler:
        def dispatch(self, kind, value):
            called.append((kind, value))
            return {"vectors": []}

    from node_agent.v2 import InputDigestError

    client, captured = _client(tmp_path, response_for, handlers=Handler())
    try:
        with pytest.raises(InputDigestError):
            client.process_once()
    finally:
        client.close()

    assert called == []
    assert [request.url.path for request in captured] == ["/v2/wu/claim"]


def test_result_includes_lease_generation_and_handler_output(tmp_path):
    value = {"model": "intfloat/multilingual-e5-large", "items": []}
    unit = _work_unit(value)
    posted = []

    def response_for(request):
        if request.url.path == "/v2/wu/claim":
            return httpx.Response(200, json=unit)
        if request.url.path == "/v2/wu/wu-test/result":
            posted.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})
        pytest.fail(f"unexpected request: {request.url}")

    class Handler:
        def dispatch(self, kind, payload):
            assert kind == "nlp.embed.e5"
            assert payload == value
            return {"model": payload["model"], "vectors": []}

    client, _ = _client(tmp_path, response_for, handlers=Handler())
    try:
        assert client.process_once() == unit
    finally:
        client.close()

    assert posted == [{
        "lease_id": "lease-test",
        "generation": 7,
        "output": {"model": value["model"], "vectors": []},
    }]


def test_heartbeat_runs_during_handler_work(tmp_path):
    value = {"model": "intfloat/multilingual-e5-large", "items": []}
    unit = _work_unit(value)
    heartbeat_seen = threading.Event()

    def response_for(request):
        if request.url.path == "/v2/wu/claim":
            return httpx.Response(200, json=unit)
        if request.url.path == "/v2/wu/wu-test/heartbeat":
            heartbeat_seen.set()
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/v2/wu/wu-test/result":
            return httpx.Response(200, json={"ok": True})
        pytest.fail(f"unexpected request: {request.url}")

    class Handler:
        def dispatch(self, kind, payload):
            assert heartbeat_seen.wait(1)
            return {"vectors": []}

    client, captured = _client(tmp_path, response_for, handlers=Handler(), heartbeat_interval=0.01)
    try:
        client.process_once()
    finally:
        client.close()

    assert heartbeat_seen.is_set()
    assert any(request.url.path == "/v2/wu/wu-test/heartbeat" for request in captured)


def test_embedding_handlers_dispatch_by_kind_and_cache_only_enabled_model():
    from node_agent.v2 import EmbeddingHandlers

    calls = {"e5_factory": 0, "pko_factory": 0, "e5_texts": None, "pko_texts": None}

    class FakeEmbedder:
        def __init__(self, name):
            self.name = name

        def embed(self, texts):
            calls[f"{self.name}_texts"] = list(texts)
            return [[0.1, 0.2] for _ in texts]

    def e5_factory(model):
        assert model == "intfloat/multilingual-e5-large"
        calls["e5_factory"] += 1
        return FakeEmbedder("e5")

    def pko_factory(model):
        assert model == "PKOBP/embed-modernbert-395m"
        calls["pko_factory"] += 1
        return FakeEmbedder("pko")

    handlers = EmbeddingHandlers({"model:e5-large"}, e5_factory=e5_factory, pko_factory=pko_factory)
    e5_input = {
        "model": "intfloat/multilingual-e5-large",
        "items": [{"post_id": "post-e5-1", "text": "query: już prefiksowany"}],
    }
    pko_input = {
        "model": "PKOBP/embed-modernbert-395m",
        "items": [{"post_id": "post-pko-1", "text": "[cls]już prefiksowany"}],
    }

    assert handlers.dispatch("nlp.embed.e5", e5_input) == {
        "model": e5_input["model"],
        "vectors": [{"post_id": "post-e5-1", "vector": [0.1, 0.2]}],
    }
    assert handlers.dispatch("nlp.embed.e5", e5_input) == {
        "model": e5_input["model"],
        "vectors": [{"post_id": "post-e5-1", "vector": [0.1, 0.2]}],
    }
    assert calls == {
        "e5_factory": 1,
        "pko_factory": 0,
        "e5_texts": ["query: już prefiksowany"],
        "pko_texts": None,
    }
    pko_handlers = EmbeddingHandlers({"model:pko-395m"}, e5_factory=e5_factory, pko_factory=pko_factory)
    assert pko_handlers.dispatch("nlp.embed.pko", pko_input) == {
        "model": pko_input["model"],
        "vectors": [{"post_id": "post-pko-1", "vector": [0.1, 0.2]}],
    }
    assert calls["pko_factory"] == 1
    assert calls["pko_texts"] == ["[cls]już prefiksowany"]
    with pytest.raises(ValueError, match="not enabled"):
        handlers.dispatch("nlp.embed.pko", pko_input)


def test_e5_embedder_uses_only_cached_model(monkeypatch):
    import sys
    from types import SimpleNamespace

    from node_agent.v2 import _make_e5_embedder

    calls = []

    def text_embedding(**kwargs):
        calls.append(kwargs)
        return object()

    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    monkeypatch.setitem(
        sys.modules,
        "fastembed",
        SimpleNamespace(__version__="0.5.1", TextEmbedding=text_embedding),
    )

    _make_e5_embedder("intfloat/multilingual-e5-large")

    assert calls == [{
        "model_name": "intfloat/multilingual-e5-large",
        "local_files_only": True,
    }]


def test_pko_embedder_uses_only_cached_model(monkeypatch):
    import sys
    from types import SimpleNamespace

    from node_agent.v2 import _PkoEmbedder

    calls = []

    class FakeModel:
        def eval(self):
            return self

    class AutoTokenizer:
        @staticmethod
        def from_pretrained(model, **kwargs):
            calls.append(("tokenizer", model, kwargs))
            return object()

    class AutoModel:
        @staticmethod
        def from_pretrained(model, **kwargs):
            calls.append(("model", model, kwargs))
            return FakeModel()

    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace())
    monkeypatch.setitem(
        sys.modules,
        "transformers",
        SimpleNamespace(AutoModel=AutoModel, AutoTokenizer=AutoTokenizer),
    )

    _PkoEmbedder("PKOBP/embed-modernbert-395m")

    assert calls == [
        ("tokenizer", "PKOBP/embed-modernbert-395m", {"local_files_only": True}),
        ("model", "PKOBP/embed-modernbert-395m", {"local_files_only": True}),
    ]


@pytest.mark.parametrize(
    ("failure", "expected_log"),
    [
        (httpx.ConnectError("connection reset"), "ConnectError"),
        (409, "HTTP 409"),
        (503, "HTTP 503"),
    ],
)
def test_run_retries_transient_core_errors(
    tmp_path, monkeypatch, capsys, failure, expected_log
):
    import node_agent.v2 as v2

    responses = [failure, httpx.Response(204)]
    captured = []

    def response_for(request):
        captured.append(request)
        response = responses.pop(0)
        if isinstance(response, int):
            response = httpx.Response(response)
        if isinstance(response, Exception):
            raise response
        return response

    client, _ = _client(tmp_path, response_for)
    sleeps = []

    class StopLoop(Exception):
        pass

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise StopLoop

    monkeypatch.setattr(v2.time, "sleep", sleep)
    try:
        with pytest.raises(StopLoop):
            client.run(idle_sleep=5)
    finally:
        client.close()

    assert len(captured) == 2
    assert sleeps == [1, 5]
    logs = capsys.readouterr().err.strip().splitlines()
    assert len(logs) == 1
    assert expected_log in logs[0]


def test_run_caps_transient_error_backoff_at_sixty_seconds(tmp_path, monkeypatch, capsys):
    import node_agent.v2 as v2

    responses = [httpx.Response(503) for _ in range(8)] + [httpx.Response(204)]

    def response_for(request):
        return responses.pop(0)

    client, _ = _client(tmp_path, response_for)
    sleeps = []

    class StopLoop(Exception):
        pass

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 9:
            raise StopLoop

    monkeypatch.setattr(v2.time, "sleep", sleep)
    try:
        with pytest.raises(StopLoop):
            client.run(idle_sleep=5)
    finally:
        client.close()

    assert sleeps == [1, 2, 4, 8, 16, 32, 60, 60, 5]
    assert len(capsys.readouterr().err.strip().splitlines()) == 8


def test_run_does_not_swallow_programming_errors(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, lambda request: pytest.fail("unexpected Core request"))

    def fail():
        raise ValueError("handler bug")

    monkeypatch.setattr(client, "process_once", fail)
    try:
        with pytest.raises(ValueError, match="handler bug"):
            client.run()
    finally:
        client.close()
