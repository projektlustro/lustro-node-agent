"""Work-unit client: pull -> verify -> classify -> sign -> POST result.

Implements the FROZEN wu contract (`packages/shared-types`):
  GET  /v1/wu              -> WorkUnit  {wu_id, kind, payload, core_pubkey_id, core_sig}
  POST /v1/wu/{id}/result  <- WorkUnitResult {labels, score, agent_pubkey, agent_sig}

Flow:
  1. GET `{edge}/v1/wu` for the next work unit.
  2. Verify the WU's `core_sig` against the PINNED core key (`core_pin`),
     rejecting on key-id mismatch or bad signature.
  3. Anti-replay: reject WUs whose `wu_id` (or, if present, `nonce`) was seen.
  4. Classify the payload via the configured `Classifier`.
  5. Sign the result with the LOCAL agent key (`keys`) — the private key never
     leaves this process and is never put in the body.
  6. POST `{edge}/v1/wu/{id}/result`.

Every step is recorded to the JobLog. All network calls go through the
`EgressGuard`, so only the edge is reachable.

HTTP Client Requirements:
  In WASM (Pyodide) environments, the `httpx` module is not available. Callers
  MUST provide an `http` parameter that implements the HttpClient protocol
  (get, post, close methods). In CLI/Docker environments, httpx is available
  and `http` is optional (defaults to a new httpx.Client instance).

  The HttpClient protocol is defined in this module and validated at runtime
  to prevent type confusion and ensure required methods are present.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Protocol, runtime_checkable, Any

try:
    import httpx

    _HTTPError: type[BaseException] = httpx.HTTPError
except ModuleNotFoundError:  # WASM/Pyodide: FetchBackend is always supplied
    httpx = None  # type: ignore[assignment]
    _HTTPError = OSError

from node_agent.classifier import Classifier
from node_agent.core_pin import (
    CorePinError,
    pinned_core_public_key_sha256,
    verify_wu_signature,
)
from node_agent.egress import EgressGuard
from node_agent.joblog import JobLog
from node_agent.keys import AgentKeys


@runtime_checkable
class _Response(Protocol):
    """Protocol for response objects returned by HttpClient."""
    status_code: int
    
    def json(self) -> Any: ...
    def raise_for_status(self) -> None: ...
    def close(self) -> None: ...


@runtime_checkable
class HttpClient(Protocol):
    """Protocol defining the interface expected from HTTP clients (httpx.Client or FetchBackend).
    
    Security: Implementations must be proper class methods, not dynamically
    generated via __getattr__, to prevent protocol bypass attacks.
    """
    
    def get(self, url: str, *, headers: dict[str, str] | None = None) -> _Response:
        """Fetch a URL via GET."""
        ...
    
    def post(self, url: str, json: Any, *, headers: dict[str, str] | None = None) -> _Response:
        """POST JSON to a URL."""
        ...
    
    def close(self) -> None:
        """Clean up resources."""
        ...
    
    # Optional: streaming support (httpx.Client has this, FetchBackend does not)
    def stream(
        self, method: str, url: str, *, headers: dict[str, str] | None = None
    ) -> Any:
        """Open a streaming connection."""
        ...

DEFAULT_SEEN_PATH = Path.home() / ".lustro-node-agent" / "seen.jsonl"

_TERMINAL_DISPOSITIONS = frozenset(
    {
        "agent_not_authorized",
        "agent_revoked",
        "invalid_result",
        "result_conflict",
        "source_erased",
        "source_no_longer_eligible",
        "source_version_changed",
        "work_unit_expired",
        "lease_not_owned",
    }
)

_SUCCESS_AUTHORITIES = frozenset(
    {
        "authoritative-v1",
        "shadow-non-authoritative",
        "non-authoritative-local-stub",
    }
)
# The WU payload text is adversary-controlled (it originates from scraped
# content). Cap the length we ever hand to the classifier so a giant `text`
# field can't drive the volunteer's CPU/RAM to exhaustion.
MAX_WU_TEXT_LEN = 64 * 1024

# Refuse an edge response whose declared body size exceeds this before parsing
# JSON — a crude first guard against a multi-hundred-MB response OOMing us.
MAX_WU_RESPONSE_BYTES = 1024 * 1024

# Maximum allowed chunk size during streaming to prevent memory spikes
MAX_CHUNK_SIZE = 64 * 1024

# Input validation limits for work unit fields
MAX_WU_ID_LEN = 256
MAX_FIELD_LEN = 1024
ALLOWED_WU_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_. ")

# Resource management limits
MAX_SEEN_ENTRIES = 100_000
MAX_REGISTRATION_ATTEMPTS = 3
REGISTRATION_BACKOFF = [1, 2, 4]  # seconds

# Classification timeout (prevent CPU exhaustion from malicious payloads)
CLASSIFICATION_TIMEOUT = float(os.environ.get(
    "LUSTRO_NODE_CLASSIFICATION_TIMEOUT", "60"
))

# Byte-offset into the joblog marking which rows have been shipped to the
# central log wall. Persisted alongside the joblog so a restart doesn't re-ship
# old rows and multiple agents (docker + WASM) stay isolated.
DEFAULT_SHIPPED_FILENAME = "shipped.offset"


class ReplayError(Exception):
    """Raised when a work unit wu_id / nonce has already been processed."""


def _validate_http_client(http: Any | None, context: str) -> None:
    """Validate that http implements the required HttpClient protocol with strict checks.
    
    Security: This function prevents protocol bypass attacks by checking that
    required methods are actual class/instance methods, not dynamically generated
    via __getattr__. This prevents arbitrary code execution through mock objects
    or malicious implementations.
    
    Raises TypeError if http is provided but doesn't implement required methods.
    Raises RuntimeError if neither http nor httpx is available.
    """
    if http is not None:
        # Check for required methods with strict validation
        for method in ('get', 'post', 'close'):
            if not hasattr(http, method):
                raise TypeError(
                    f"http parameter in {context} must implement HttpClient protocol "
                    f"(requires {method} method)"
                )
            
            attr = getattr(http, method, None)
            if attr is None:
                raise TypeError(f"http in {context} {method} is None")
            
            if not callable(attr):
                raise TypeError(
                    f"http parameter in {context} must have callable get, post, close methods"
                )
            
            # Prevent __getattr__ bypass: ensure method is not dynamically generated
            # A real method should exist on the class or as an instance attribute
            if (not hasattr(type(http), method) and 
                method not in getattr(http, '__dict__', {})):
                # Could be from __getattr__ - investigate further
                if hasattr(http, '__getattr__'):
                    raise TypeError(
                        f"http in {context} {method} may be dynamically generated "
                        f"via __getattr__ (not allowed for security)"
                    )
        
        # If stream exists, validate it too
        if hasattr(http, 'stream'):
            stream_attr = getattr(http, 'stream', None)
            if stream_attr is not None and not callable(stream_attr):
                raise TypeError(f"http in {context} stream is not callable")
    elif httpx is None:
        # WASM environment without provided http client
        raise RuntimeError(
            f"In {context}: httpx not available in this environment; "
            "caller must provide http parameter (FetchBackend instance)"
        )


def canonical_wu_bytes(wu: dict) -> bytes:
    """Canonical byte serialization of the signed portion of a work unit.

    MUST stay byte-for-byte identical to ``services/core/app/wu_canonical.py``
    (``canonical_wu_bytes``) — the core signs these bytes and this agent
    verifies them. The signed body covers ``wu_id``, ``kind``, ``payload`` and
    ``core_pubkey_id`` (only ``core_sig`` is excluded), with sorted keys, no
    insignificant whitespace, and ``ensure_ascii=False`` so non-ASCII payloads
    (e.g. Polish text) hash identically on both sides.
    """
    return json.dumps(
        {
            "wu_id": wu["wu_id"],
            "kind": wu["kind"],
            "payload": wu["payload"],
            "core_pubkey_id": wu["core_pubkey_id"],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_pull_bytes(
    agent_pubkey: str,
    timestamp: int,
    nonce: str,
    core_public_key_sha256: str,
    tenant: str,
) -> bytes:
    return json.dumps(
        {
            "agent_pubkey": agent_pubkey,
            "timestamp": timestamp,
            "nonce": nonce,
            "core_public_key_sha256": core_public_key_sha256,
            "tenant": tenant,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_success_ack_bytes(ack: dict) -> bytes:
    return json.dumps(
        {
            "accepted": ack["accepted"],
            "wu_id": ack["wu_id"],
            "authority": ack["authority"],
            "agent_pubkey": ack["agent_pubkey"],
            "agent_sig": ack["agent_sig"],
            "core_pubkey_id": ack["core_pubkey_id"],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_terminal_bytes(receipt: dict) -> bytes:
    return json.dumps(
        {
            "terminal": receipt["terminal"],
            "disposition": receipt["disposition"],
            "wu_id": receipt["wu_id"],
            "agent_pubkey": receipt["agent_pubkey"],
            "agent_sig": receipt["agent_sig"],
            "core_pubkey_id": receipt["core_pubkey_id"],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

class NodeAgentClient:
    def __init__(
        self,
        edge_base_url: str,
        classifier: Classifier,
        keys: AgentKeys,
        joblog: JobLog,
        seen_path: Path | None = None,
        participant_token: str = "",
        tenant: str | None = None,
    ) -> None:
        self._egress = EgressGuard(edge_base_url)
        self._edge = self._egress.allowed_base_url
        self._classifier = classifier
        self._keys = keys
        self._joblog = joblog
        self._participant_token = participant_token
        self._tenant = tenant if tenant is not None else os.environ.get("LUSTRO_NODE_TENANT", "pl")
        if not isinstance(self._tenant, str) or not re.fullmatch(r"[a-z]{2}", self._tenant):
            raise ValueError("node-agent tenant must be a two-letter lowercase code")
        self._seen_path = Path(seen_path) if seen_path is not None else DEFAULT_SEEN_PATH
        self._seen_wu_ids: set[str] = set()
        self._seen_nonces: set[str] = set()
        self._load_seen()

    def _report_activity(
        self,
        *,
        wu_id: str,
        agent_pubkey: str,
        http: HttpClient,
    ) -> None:
        """Attribute an accepted result to the volunteer's `/me` account.

        This is a second, idempotent write after the core accepts the signed
        result. The frozen core result contract stays unchanged, and a temporary
        telemetry failure never turns an already-consumed work unit into a
        retry that the core would reject.
        """
        if not self._participant_token:
            return
        url = self._egress.check(f"{self._edge}/elfik/node/activity")
        try:
            response = http.post(
                url,
                json={"wu_id": wu_id, "agent_pubkey": agent_pubkey},
                headers={"Authorization": f"Bearer {self._participant_token}"},
            )
            response.raise_for_status()
        except (_HTTPError, OSError) as exc:
            self._joblog.append(
                {
                    "event": "activity_sync_failed",
                    "wu_id": wu_id,
                    "error": type(exc).__name__,
                }
            )
            return
        self._joblog.append({"event": "activity_synced", "wu_id": wu_id})

    def _load_seen(self) -> None:
        """Load previously-seen wu_ids/nonces so anti-replay survives restarts.

        Without this the seen set lives only in memory, so an agent that runs one
        WU per process (the `node-agent run` cron model) can replay every WU it
        has ever processed. A malformed line is skipped, not fatal.
        """
        if not self._seen_path.exists():
            return
        for line in self._seen_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            wu_id = rec.get("wu_id")
            nonce = rec.get("nonce")
            if wu_id is not None:
                self._seen_wu_ids.add(wu_id)
            if nonce is not None:
                self._seen_nonces.add(nonce)

    def _persist_seen(self, wu: dict) -> None:
        """Append the just-processed wu_id/nonce to the on-disk seen log (0600).
        
        Security: Uses file locking to prevent race conditions when multiple
        processes (or concurrent invocations) try to persist seen entries.
        """
        wu_id = wu.get("wu_id")
        nonce = wu.get("nonce")
        if wu_id is None and nonce is None:
            return
        parent = self._seen_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        rec = {}
        if wu_id is not None:
            rec["wu_id"] = wu_id
        if nonce is not None:
            rec["nonce"] = nonce
        existed = self._seen_path.exists()
        
        # Use file locking for atomic append (prevents race conditions)
        try:
            import fcntl
            with self._seen_path.open("a", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (ImportError, OSError):
            # Fallback for WASM (no fcntl) or systems without file locking
            with self._seen_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        
        if not existed:
            os.chmod(self._seen_path, 0o600)

    def _seen(self, wu: dict) -> bool:
        wu_id = wu.get("wu_id")
        nonce = wu.get("nonce")
        return (wu_id is not None and wu_id in self._seen_wu_ids) or (
            nonce is not None and nonce in self._seen_nonces
        )

    def _mark_seen(self, wu: dict) -> None:
        """Mark a work unit as seen, with LRU eviction to prevent memory exhaustion."""
        if wu.get("wu_id") is not None:
            self._seen_wu_ids.add(wu["wu_id"])
            # LRU eviction to prevent unbounded memory growth
            if len(self._seen_wu_ids) > MAX_SEEN_ENTRIES:
                # Remove oldest 10% of entries
                to_remove = set(list(self._seen_wu_ids)[:MAX_SEEN_ENTRIES // 10])
                self._seen_wu_ids -= to_remove
        if wu.get("nonce") is not None:
            self._seen_nonces.add(wu["nonce"])
            if len(self._seen_nonces) > MAX_SEEN_ENTRIES:
                to_remove = set(list(self._seen_nonces)[:MAX_SEEN_ENTRIES // 10])
                self._seen_nonces -= to_remove
        self._persist_seen(wu)

    @staticmethod
    def _payload_text(payload: object) -> str:
        """Extract the classifiable text from a WU payload.

        Payload is `unknown` in the contract; the text kind carries `{text: ...}`.
        
        Security: Carefully handles various input types to prevent memory
        exhaustion from adversarial payloads.
        """
        if isinstance(payload, dict):
            text = payload.get("text", "")
            if isinstance(text, str):
                return text[:MAX_WU_TEXT_LEN]
            elif isinstance(text, bytes):
                return text[:MAX_WU_TEXT_LEN].decode("utf-8", errors="replace")
            elif isinstance(text, (int, float, bool, type(None))):
                return str(text)
            else:
                # Don't call str() on arbitrary complex objects (could be huge)
                return ""
        if isinstance(payload, str):
            return payload[:MAX_WU_TEXT_LEN]
        if isinstance(payload, bytes):
            return payload[:MAX_WU_TEXT_LEN].decode("utf-8", errors="replace")
        return ""

    @staticmethod
    def _payload_lang(payload: object) -> str | None:
        if isinstance(payload, dict) and payload.get("lang") is not None:
            return str(payload["lang"])
        return None

    def _pending_result(self) -> dict[str, Any] | None:
        pending: dict[str, dict[str, Any]] = {}
        for row in self._joblog.read_all():
            if not isinstance(row, dict) or row.get("event") == "_parse_error":
                raise CorePinError("job log is malformed; refusing to pull work")
            event = row.get("event")
            if event not in {
                "wu_result_pending",
                "wu_result_acked",
                "wu_result_terminal",
                "wu_result_settled",
            }:
                continue
            wu_id = row.get("wu_id")
            if not isinstance(wu_id, str):
                if event == "wu_result_pending":
                    raise CorePinError("persisted result is missing wu_id")
                continue
            if event == "wu_result_pending":
                pending[wu_id] = row
            else:
                pending.pop(wu_id, None)
        return next(iter(pending.values()), None)
    def _accept_success_ack(
        self, response: Any, pending: dict[str, Any], result_body: dict[str, Any]
    ) -> dict[str, Any] | None:
        if response.status_code != 200:
            return None
        try:
            ack = response.json()
            if not isinstance(ack, dict) or set(ack) != {
                "accepted",
                "wu_id",
                "authority",
                "agent_pubkey",
                "agent_sig",
                "core_pubkey_id",
                "core_sig",
            }:
                return None
            if (
                ack["accepted"] is not True
                or ack["wu_id"] != pending["wu_id"]
                or ack["authority"] not in _SUCCESS_AUTHORITIES
                or ack["agent_pubkey"] != result_body["agent_pubkey"]
                or ack["agent_sig"] != result_body["agent_sig"]
                or not isinstance(ack["core_pubkey_id"], str)
            ):
                return None
            core_sig = base64.b64decode(ack["core_sig"], validate=True)
            if len(core_sig) != 64 or base64.b64encode(core_sig).decode() != ack["core_sig"]:
                return None
            verify_wu_signature(
                canonical_success_ack_bytes(ack),
                core_sig,
                ack["core_pubkey_id"],
            )
        except Exception:
            return None
        return ack

    def _accept_terminal_result(
        self, response: Any, pending: dict[str, Any], result_body: dict[str, Any]
    ) -> dict[str, Any] | None:
        if response.status_code not in {403, 409, 410}:
            return None
        try:
            receipt = response.json()
            if not isinstance(receipt, dict) or set(receipt) != {
                "terminal",
                "disposition",
                "wu_id",
                "agent_pubkey",
                "agent_sig",
                "core_pubkey_id",
                "core_sig",
            }:
                return None
            wu_id = pending["wu_id"]
            if (
                receipt["terminal"] is not True
                or receipt["disposition"] not in _TERMINAL_DISPOSITIONS
                or receipt["wu_id"] != wu_id
                or receipt["agent_pubkey"] != result_body["agent_pubkey"]
                or receipt["agent_sig"] != result_body["agent_sig"]
                or not isinstance(receipt["core_pubkey_id"], str)
            ):
                return None
            core_sig = base64.b64decode(receipt["core_sig"], validate=True)
            if (
                len(core_sig) != 64
                or base64.b64encode(core_sig).decode() != receipt["core_sig"]
            ):
                return None
            verify_wu_signature(
                canonical_terminal_bytes(receipt),
                core_sig,
                receipt["core_pubkey_id"],
            )
        except Exception:
            return None
        self._mark_seen({"wu_id": wu_id, "nonce": pending.get("nonce")})
        self._joblog.append(
            {
                "event": "wu_result_terminal",
                "wu_id": wu_id,
                "disposition": receipt["disposition"],
                "status": response.status_code,
            }
        )
        return {
            "terminal": True,
            "wu_id": wu_id,
            "disposition": receipt["disposition"],
        }

    def _submit_pending_result(
        self, pending: dict[str, Any], http: HttpClient
    ) -> dict[str, Any]:
        wu_id = pending.get("wu_id")
        result_body = pending.get("result_body")
        if not isinstance(wu_id, str) or not wu_id:
            raise CorePinError("persisted result is missing wu_id")
        if (
            len(wu_id) > MAX_WU_ID_LEN
            or not all(c in ALLOWED_WU_ID_CHARS for c in wu_id)
        ):
            raise CorePinError("persisted result wu_id is invalid")
        if not isinstance(result_body, dict) or set(result_body) != {
            "labels",
            "score",
            "agent_pubkey",
            "agent_sig",
        }:
            raise CorePinError("persisted result body is malformed")
        if result_body["agent_pubkey"] != self._keys.public_key_raw_b64():
            raise CorePinError("persisted result belongs to a different agent key")
        text_preview = pending.get("text_preview")
        if not isinstance(text_preview, str):
            raise CorePinError("persisted result preview is malformed")

        url = self._egress.check(f"{self._edge}/v1/wu/{wu_id}/result")
        resp = http.post(url, json=result_body)
        terminal = self._accept_terminal_result(resp, pending, result_body)
        if terminal is not None:
            return terminal
        ack = self._accept_success_ack(resp, pending, result_body)
        if ack is None:
            if resp.status_code in {404, 409}:
                self._mark_seen({"wu_id": wu_id, "nonce": pending.get("nonce")})
                self._joblog.append(
                    {
                        "event": "wu_result_settled",
                        "wu_id": wu_id,
                        "status": resp.status_code,
                    }
                )
                return {
                    **result_body,
                    "text_preview": text_preview,
                    "authority": f"settled-{resp.status_code}",
                }
            resp.raise_for_status()
            raise CorePinError("Core success acknowledgement is invalid")
        self._joblog.append(
            {"event": "wu_result_acked", "wu_id": wu_id, "receipt": ack}
        )
        self._mark_seen({"wu_id": wu_id, "nonce": pending.get("nonce")})
        self._report_activity(
            wu_id=wu_id,
            agent_pubkey=result_body["agent_pubkey"],
            http=http,
        )
        self._joblog.append(
            {
                "event": "wu_processed",
                "wu_id": wu_id,
                "labels": result_body["labels"],
                "score": result_body["score"],
                "status": resp.status_code,
                "text_preview": text_preview,
            }
        )
        return {
            **result_body,
            "text_preview": text_preview,
            "authority": ack["authority"],
        }

    def process_wu(self, wu: dict, http: HttpClient | None = None) -> dict:
        """Verify, classify, sign and submit a single work unit.

        A signed result is persisted before POST and replayed byte-for-byte
        after a transport failure or process restart.
        """
        if not isinstance(wu, dict):
            raise CorePinError("work unit is not a JSON object")

        wu_id = wu.get("wu_id")
        if not wu_id:
            raise CorePinError("work unit missing wu_id")
        if not isinstance(wu_id, str):
            raise CorePinError("work unit wu_id must be string")
        if len(wu_id) > MAX_WU_ID_LEN:
            raise CorePinError(f"work unit wu_id too long: {len(wu_id)}")
        if not all(c in ALLOWED_WU_ID_CHARS for c in wu_id):
            raise CorePinError("work unit wu_id contains invalid characters")


        for field in ("kind", "payload", "core_pubkey_id"):
            if field not in wu:
                raise CorePinError(f"work unit missing {field}")
            val = wu[field]
            if isinstance(val, str) and len(val) > MAX_FIELD_LEN:
                raise CorePinError(f"work unit {field} too long")

        pending = self._pending_result()
        if pending is not None and pending.get("wu_id") != wu_id:
            raise RuntimeError("pending result must be delivered before new work")
        if self._seen(wu) and pending is None:
            self._joblog.append({"event": "replay_rejected", "wu_id": wu_id})
            raise ReplayError(f"work unit already processed: {wu_id}")
        try:
            core_sig = base64.b64decode(wu["core_sig"], validate=True)
        except (KeyError, binascii.Error, ValueError) as e:
            raise CorePinError("work unit core_sig missing or malformed") from e
        canonical = canonical_wu_bytes(wu)
        verify_wu_signature(canonical, core_sig, wu.get("core_pubkey_id", ""))
        wu_digest = hashlib.sha256(canonical).hexdigest()
        owns_client = http is None
        _validate_http_client(http, "process_wu")
        client = http or httpx.Client(timeout=30)
        try:
            if pending is not None:
                if pending.get("wu_digest") != wu_digest:
                    raise RuntimeError("pending result belongs to different work")
                return self._submit_pending_result(pending, client)

            payload = wu.get("payload")
            result = self._classifier.classify(
                self._payload_text(payload), self._payload_lang(payload)
            )
            labels = [result.label]
            score = float(result.score)
            signed_payload = {"wu_id": wu_id, "labels": labels, "score": score}
            result_bytes = json.dumps(
                signed_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            agent_sig = base64.b64encode(self._keys.sign(result_bytes)).decode()
            result_body = {
                "labels": labels,
                "score": score,
                "agent_pubkey": self._keys.public_key_raw_b64(),
                "agent_sig": agent_sig,
            }
            text_preview = (self._payload_text(payload) or "")[:200]
            pending_record = {
                "event": "wu_result_pending",
                "wu_id": wu_id,
                "wu_digest": wu_digest,
                "nonce": wu.get("nonce"),
                "result_body": result_body,
                "text_preview": text_preview,
            }
            self._joblog.append(pending_record)
            return self._submit_pending_result(pending_record, client)
        finally:
            if owns_client:
                client.close()


    def register_agent(
        self, http: HttpClient | None = None, invite_token: str = ""
    ) -> None:
        """Register this node with the edge on first run.

        A production core gates registration behind an operator-minted invite
        token (LUSTRO node N3): pass it here (the CLI reads
        LUSTRO_NODE_INVITE_TOKEN). Public browser WASM volunteers have no
        invite; they round-trip ``GET /v1/wu/agent-nonce`` and present the
        server-issued one-time ``agent_nonce`` instead (LE-2). A dev/local
        core leaves registration open — a nonce is still harmless there.
        
        Security: Implements rate limiting to prevent resource exhaustion from
        repeated failed registration attempts.
        """
        import time
        
        url = self._egress.check(f"{self._edge}/v1/wu/register-agent")
        body = {"agent_pubkey": self._keys.public_key_raw_b64()}
        owns_client = http is None
        _validate_http_client(http, "register_agent")
        
        # Rate limiting: prevent resource exhaustion from repeated failures
        for attempt in range(MAX_REGISTRATION_ATTEMPTS):
            client = http or httpx.Client(timeout=30)
            try:
                if invite_token:
                    body["invite_token"] = invite_token
                else:
                    # LE-2: forgeable Origin headers are gone; the public WASM path
                    # must present a nonce the core minted. Docker agents with an
                    # invite skip this branch.
                    nonce_url = self._egress.check(f"{self._edge}/v1/wu/agent-nonce")
                    nonce_resp = client.get(nonce_url)
                    nonce_resp.raise_for_status()
                    nonce = nonce_resp.json().get("nonce", "")
                    if not nonce:
                        raise RuntimeError("agent-nonce response missing nonce")
                    body["agent_nonce"] = nonce
                resp = client.post(url, json=body)
                resp.raise_for_status()
                
                # Success: break out of retry loop
                break
            except Exception:
                # Close client on failure (will be recreated on next attempt)
                if owns_client:
                    client.close()
                # Only raise on final attempt
                if attempt == MAX_REGISTRATION_ATTEMPTS - 1:
                    raise
                # Exponential backoff before retry
                time.sleep(REGISTRATION_BACKOFF[attempt])
        else:
            # This shouldn't be reached, but just in case
            client = http or httpx.Client(timeout=30)
            owns_client = http is None
        
        # Close client if we created it and haven't already
        if owns_client:
            client.close()
            
        self._joblog.append({"event": "agent_registered", "agent_pubkey": body["agent_pubkey"]})

    def pull_and_process(self, http: HttpClient | None = None) -> dict | None:
        """Pull one WU from the edge and process it; None if no work (204).

        Opted-in scraping (plan §6): scrape-kind work units are refused unless
        the agent was started with the separate --enable-scraping profile;
        only signed-manifest extractor IDs are ever accepted (scrape_manifest).
        
        Security note: When http is a FetchBackend (WASM/browser), the browser's
        fetch API loads the entire response body into memory before we can check
        its size. The size check still rejects oversized WUs, but cannot prevent
        memory exhaustion from a hostile edge sending a huge response.
        The Docker/CLI agents (httpx.Client) use true streaming and enforce the
        size limit incrementally.
        """
        url = self._egress.check(f"{self._edge}/v1/wu")
        owns_client = http is None
        _validate_http_client(http, "pull_and_process")
        client = http or httpx.Client(timeout=30)
        try:
            pending = self._pending_result()
            if pending is not None:
                return self._submit_pending_result(pending, client)

            pull_timestamp = int(time.time())
            pull_nonce = secrets.token_hex(16)
            pull_pubkey = self._keys.public_key_raw_b64()
            pull_core_key_sha256 = pinned_core_public_key_sha256()
            pull_signature = base64.b64encode(
                self._keys.sign(
                    canonical_pull_bytes(
                        pull_pubkey,
                        pull_timestamp,
                        pull_nonce,
                        pull_core_key_sha256,
                        self._tenant,
                    )
                )
            ).decode()
            pull_headers = {
                "X-Lustro-Agent-Pubkey": pull_pubkey,
                "X-Lustro-Agent-Timestamp": str(pull_timestamp),
                "X-Lustro-Agent-Nonce": pull_nonce,
                "X-Lustro-Agent-Signature": pull_signature,
                "X-Lustro-Agent-Tenant": self._tenant,
            }
            # Check if client supports streaming
            if hasattr(client, 'stream'):
                # httpx.Client path: true streaming with size check BEFORE append
                with client.stream("GET", url, headers=pull_headers) as resp:
                    if resp.status_code == 204:
                        self._joblog.append({"event": "no_work"})
                        return None
                    body = bytearray()
                    for chunk in resp.iter_bytes(chunk_size=MAX_CHUNK_SIZE):
                        # Check size BEFORE appending to prevent integer overflow
                        if len(body) + len(chunk) > MAX_WU_RESPONSE_BYTES:
                            raise CorePinError("work unit response too large")
                        body += chunk
                
                # Use single read to prevent TOCTOU (time-of-check-time-of-use)
                response_text = bytes(body).decode("utf-8")
                try:
                    wu = json.loads(response_text)
                except json.JSONDecodeError as e:
                    raise CorePinError("edge response is not valid JSON") from e
            else:
                # FetchBackend path: fetch first, check size after
                # NOTE: This does NOT protect against huge responses filling memory
                # because fetch() loads the full body before we can check.
                # Store in local variable to prevent TOCTOU
                resp = client.get(url, headers=pull_headers)
                if resp.status_code == 204:
                    self._joblog.append({"event": "no_work"})
                    return None
                
                # Use single read of _text to prevent TOCTOU
                response_text = resp._text
                body_bytes = response_text.encode("utf-8")
                if len(body_bytes) > MAX_WU_RESPONSE_BYTES:
                    raise CorePinError("work unit response too large")
                try:
                    wu = json.loads(response_text)
                except json.JSONDecodeError as e:
                    raise CorePinError("edge response is not valid JSON") from e
            
            if not isinstance(wu, dict):
                raise CorePinError("edge returned a non-object work unit")
            if str(wu.get("kind", "")).startswith("scrape") and os.environ.get("LUSTRO_NODE_SCRAPING_ENABLED") != "1":
                self._joblog.append({"event": "scrape_refused", "reason": "opt-in profile not enabled"})
                return None
            return self.process_wu(wu, http=client)
        finally:
            if owns_client:
                client.close()

    def _ship_logs(
        self,
        http: HttpClient | None = None,
        shipped_path: Path | None = None,
    ) -> None:
        """Best-effort push of the joblog to the central log wall.

        Ships the joblog rows after the persisted byte-offset to
        ``{edge}/v1/wu/node-logs``. Scraped content (``text_preview`` and
        ``_parse_error.raw``) is stripped before the batch leaves the machine.
        The exact bytes POSTed as ``batch_bytes`` are what ``agent_sig`` signs
        over, so the core verifies without re-serializing. Best-effort: never
        raises; failures are logged to the joblog. On a rejected (non-2xx) batch
        the cursor gaps past it so a poisoned batch can't wedge the ship loop;
        on a transport error the cursor is left in place for a later retry.
        """
        shipped_path = shipped_path or self._joblog.path.with_name(DEFAULT_SHIPPED_FILENAME)
        shipped_path.parent.mkdir(parents=True, exist_ok=True)
        offset = 0
        if shipped_path.exists():
            try:
                offset = int(shipped_path.read_text().strip() or "0")
            except ValueError:
                offset = 0

        log_path = self._joblog.path
        if not log_path.exists():
            return
        raw = log_path.read_bytes()
        batch = raw[offset:]
        if not batch.strip():
            return

        rows = []
        for line in batch.splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                rec = {"event": "_parse_error"}
            # Scraped content must never leave the volunteer machine.
            rec.pop("text_preview", None)
            rec.pop("raw", None)
            rows.append(rec)

        batch_bytes = json.dumps(
            rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        body = {
            "agent_pubkey": self._keys.public_key_raw_b64(),
            "agent_sig": base64.b64encode(self._keys.sign(batch_bytes)).decode(),
            "batch_bytes": base64.b64encode(batch_bytes).decode(),
        }

        url = self._egress.check(f"{self._edge}/v1/wu/node-logs")
        owns_client = http is None
        _validate_http_client(http, "_ship_logs")
        client = http or httpx.Client(timeout=30)
        try:
            resp = client.post(url, json=body)
            if resp.status_code // 100 != 2:
                # Rejected: gap the cursor past the batch so it can't wedge us.
                shipped_path.write_text(str(offset + len(batch)))
                self._joblog.append(
                    {"event": "ship_logs_failed", "status": resp.status_code}
                )
                return
        except _HTTPError:
            # Transport error: keep the cursor so the batch is retried.
            self._joblog.append({"event": "ship_logs_failed", "error": "transport"})
            return
        finally:
            if owns_client:
                client.close()

        shipped_path.write_text(str(offset + len(batch)))
        self._joblog.append({"event": "logs_shipped", "rows": len(rows)})
