from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit
from typing import Any, Callable

from node_agent.egress import EgressGuard

E5_MODEL = "intfloat/multilingual-e5-large"
PKO_MODEL = "PKOBP/embed-modernbert-395m"
HEARTBEAT_INTERVAL_SECONDS = 30
MAX_BATCH_SIZE = 32


class InputDigestError(ValueError):
    pass


class HeartbeatError(RuntimeError):
    pass


def _transient_error_label(error: Exception) -> str | None:
    import httpx

    while isinstance(error, HeartbeatError) and error.__cause__ is not None:
        error = error.__cause__
    if isinstance(error, httpx.TransportError):
        return type(error).__name__
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        if status == 409 or 500 <= status < 600:
            return f"HTTP {status}"
    return None


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def agent_key_id(keys: Any) -> str:
    public_key = keys.public_key()
    return "ed25519-" + hashlib.sha256(public_key.public_bytes_raw()).hexdigest()[:16]


def _make_e5_embedder(model_name: str):
    try:
        import fastembed
        from fastembed import TextEmbedding
    except Exception as exc:
        raise RuntimeError(f"fastembed unavailable: {exc}") from exc
    major, minor, *_ = (int(part) for part in fastembed.__version__.split(".")[:2])
    if (major, minor) >= (0, 6):
        raise RuntimeError(
            f"fastembed {fastembed.__version__} uses mean pooling for {model_name}; "
            "persisted embeddings are CLS-pooled. Pin fastembed==0.5.1."
        )
    return TextEmbedding(
        model_name=model_name,
        local_files_only=True,
    )


class _PkoEmbedder:
    def __init__(self, model_name: str) -> None:
        import torch
        from transformers import AutoModel, AutoTokenizer

        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
        self._model = AutoModel.from_pretrained(model_name, local_files_only=True).eval()

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        with self._torch.no_grad():
            for text in texts:
                encoded = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
                hidden = self._model(**encoded).last_hidden_state[0, 0]
                norm = float(hidden.norm()) or 1.0
                vectors.append([float(value) / norm for value in hidden.tolist()])
        return vectors


def _make_pko_embedder(model_name: str):
    return _PkoEmbedder(model_name)


class EmbeddingHandlers:
    def __init__(
        self,
        tags: set[str] | tuple[str, ...] | list[str],
        *,
        e5_factory: Callable[[str], Any] = _make_e5_embedder,
        pko_factory: Callable[[str], Any] = _make_pko_embedder,
    ) -> None:
        configured_tags = set(tags)
        self._models = {
            "nlp.embed.e5": (E5_MODEL, "model:e5-large", e5_factory),
            "nlp.embed.pko": (PKO_MODEL, "model:pko-395m", pko_factory),
        }
        self._enabled = {
            kind: tag in configured_tags for kind, (_, tag, _) in self._models.items()
        }
        self._loaded: dict[str, Any] = {}

    def dispatch(self, kind: str, payload: dict) -> dict:
        config = self._models.get(kind)
        if config is None:
            raise ValueError(f"unsupported work-unit kind: {kind}")
        if not self._enabled[kind]:
            raise ValueError(f"handler for {kind} is not enabled by worker tags")
        model_name, _, factory = config
        if not isinstance(payload, dict) or payload.get("model") != model_name:
            raise ValueError(f"work-unit model does not match {kind}")
        items = payload.get("items")
        if not isinstance(items, list) or len(items) > MAX_BATCH_SIZE:
            raise ValueError("embedding input must contain at most 32 items")
        for item in items:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("post_id"), str)
                or not isinstance(item.get("text"), str)
            ):
                raise ValueError("embedding items require string post_id and text")
        if not items:
            return {"model": model_name, "vectors": []}
        embedder = self._loaded.get(kind)
        if embedder is None:
            embedder = factory(model_name)
            self._loaded[kind] = embedder
        vectors = list(embedder.embed([item["text"] for item in items]))
        if len(vectors) != len(items):
            raise ValueError("embedder returned a different number of vectors")
        return {
            "model": model_name,
            "vectors": [
                {
                    "post_id": item["post_id"],
                    "vector": vector.tolist() if hasattr(vector, "tolist") else [float(value) for value in vector],
                }
                for item, vector in zip(items, vectors)
            ],
        }


class V2Client:
    def __init__(
        self,
        core_url: str,
        keys: Any,
        *,
        tags: list[str] | tuple[str, ...],
        handlers: EmbeddingHandlers | Any | None = None,
        role_fallback_seconds: int | None = None,
        heartbeat_interval: float = HEARTBEAT_INTERVAL_SECONDS,
        http_client: Any | None = None,
    ) -> None:
        parsed = urlsplit(core_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("core URL must include a scheme and host without credentials, query, or fragment")
        if heartbeat_interval <= 0:
            raise ValueError("heartbeat interval must be positive")
        if role_fallback_seconds is not None and type(role_fallback_seconds) is not int:
            raise ValueError("role fallback seconds must be an integer")
        self._core_origin = f"{parsed.scheme}://{parsed.netloc}"
        self._path_prefix = parsed.path.rstrip("/")
        self._egress = EgressGuard(core_url)
        self._keys = keys
        self._key_id = agent_key_id(keys)
        self._tags = tuple(tags)
        self._handlers = handlers
        self._fallback_seconds = role_fallback_seconds
        self._heartbeat_interval = heartbeat_interval
        if http_client is None:
            import httpx

            http_client = httpx.Client(timeout=30, follow_redirects=False)
        self._http = http_client


    def close(self) -> None:
        self._http.close()

    def _signed_post(self, route: str, body: dict):
        target = self._path_prefix + route
        raw_body = canonical_json_bytes(body)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        request_id = uuid.uuid4().hex
        envelope = {
            "method": "POST",
            "target": target,
            "agent_key_id": self._key_id,
            "timestamp": timestamp,
            "request_id": request_id,
            "body_digest": _sha256_digest(raw_body),
        }
        signature = base64.b64encode(self._keys.sign(canonical_json_bytes(envelope))).decode("ascii")
        headers = {
            "content-type": "application/json",
            "x-wu-key": self._key_id,
            "x-wu-timestamp": timestamp,
            "x-wu-request-id": request_id,
            "x-wu-sig": signature,
        }
        url = self._egress.check(self._core_origin + target)
        response = self._http.request("POST", url, content=raw_body, headers=headers)
        response.raise_for_status()
        return response

    def claim(self) -> dict | None:
        body: dict[str, Any] = {"tags": list(self._tags)}
        if self._fallback_seconds is not None:
            body["fallback_after_seconds"] = self._fallback_seconds
        response = self._signed_post("/v2/wu/claim", body)
        if response.status_code == 204:
            return None
        if response.status_code != 200:
            raise RuntimeError(f"unexpected claim status: {response.status_code}")
        unit = response.json()
        if not isinstance(unit, dict):
            raise ValueError("claim response must be an object")
        return unit

    @staticmethod
    def _verify_input_digest(unit: dict) -> dict:
        payload = unit.get("input")
        digest = unit.get("input_digest")
        if not isinstance(digest, str):
            raise InputDigestError("work unit has no input digest")
        actual = _sha256_digest(canonical_json_bytes(payload))
        if not hmac.compare_digest(actual, digest):
            raise InputDigestError("work-unit input digest mismatch")
        return payload

    @staticmethod
    def _lease_fields(unit: dict) -> tuple[str, str, int]:
        wu_id = unit.get("wu_id")
        lease_id = unit.get("lease_id")
        generation = unit.get("generation")
        if not isinstance(wu_id, str) or not wu_id or not isinstance(lease_id, str) or not lease_id:
            raise ValueError("claim response is missing work-unit lease identifiers")
        if type(generation) is not int:
            raise ValueError("claim response generation must be an integer")
        return wu_id, lease_id, generation

    def _heartbeat_loop(self, wu_id: str, lease_id: str, generation: int, stop: threading.Event, errors: list[Exception]) -> None:
        target = f"/v2/wu/{quote(wu_id, safe='')}/heartbeat"
        body = {"lease_id": lease_id, "generation": generation}
        while not stop.wait(self._heartbeat_interval):
            try:
                self._signed_post(target, body)
            except Exception as exc:
                errors.append(exc)
                return

    def process_once(self) -> dict | None:
        unit = self.claim()
        if unit is None:
            return None
        payload = self._verify_input_digest(unit)
        wu_id, lease_id, generation = self._lease_fields(unit)
        if self._handlers is None:
            raise ValueError("no handlers configured for v2 work")
        stop = threading.Event()
        heartbeat_errors: list[Exception] = []
        heartbeat = threading.Thread(
            target=self._heartbeat_loop,
            args=(wu_id, lease_id, generation, stop, heartbeat_errors),
            daemon=True,
        )
        heartbeat.start()
        try:
            output = self._handlers.dispatch(unit.get("kind", ""), payload)
        finally:
            stop.set()
            heartbeat.join()
        if heartbeat_errors:
            raise HeartbeatError("work-unit heartbeat failed") from heartbeat_errors[0]
        if not isinstance(output, dict):
            raise ValueError("work-unit handler output must be an object")
        target = f"/v2/wu/{quote(wu_id, safe='')}/result"
        self._signed_post(target, {
            "lease_id": lease_id,
            "generation": generation,
            "output": output,
        })
        return unit

    def run(self, *, once: bool = False, idle_sleep: float = 5) -> None:
        if idle_sleep < 0:
            raise ValueError("idle sleep must not be negative")
        backoff_seconds = 1
        while True:
            try:
                result = self.process_once()
            except Exception as exc:
                reason = _transient_error_label(exc)
                if reason is None or once:
                    raise
                print(f"v2 transient Core error: {reason}", file=sys.stderr, flush=True)
                time.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2, 60)
                continue
            backoff_seconds = 1
            if once:
                return
            if result is None:
                time.sleep(idle_sleep)
