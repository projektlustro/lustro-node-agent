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
"""

import base64
import binascii
import json
import os
from pathlib import Path

import httpx

from node_agent.classifier import Classifier
from node_agent.core_pin import CorePinError, verify_wu_signature
from node_agent.egress import EgressGuard
from node_agent.joblog import JobLog
from node_agent.keys import AgentKeys

DEFAULT_SEEN_PATH = Path.home() / ".lustro-node-agent" / "seen.jsonl"

# The WU payload text is adversary-controlled (it originates from scraped
# content). Cap the length we ever hand to the classifier so a giant `text`
# field can't drive the volunteer's CPU/RAM to exhaustion.
MAX_WU_TEXT_LEN = 64 * 1024

# Refuse an edge response whose declared body size exceeds this before parsing
# JSON — a crude first guard against a multi-hundred-MB response OOMing us.
MAX_WU_RESPONSE_BYTES = 1024 * 1024


class ReplayError(Exception):
    """Raised when a work unit wu_id / nonce has already been processed."""


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


class NodeAgentClient:
    def __init__(
        self,
        edge_base_url: str,
        classifier: Classifier,
        keys: AgentKeys,
        joblog: JobLog,
        seen_path: Path | None = None,
    ) -> None:
        self._egress = EgressGuard(edge_base_url)
        self._edge = self._egress.allowed_base_url
        self._classifier = classifier
        self._keys = keys
        self._joblog = joblog
        self._seen_path = Path(seen_path) if seen_path is not None else DEFAULT_SEEN_PATH
        self._seen_wu_ids: set[str] = set()
        self._seen_nonces: set[str] = set()
        self._load_seen()

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
        """Append the just-processed wu_id/nonce to the on-disk seen log (0600)."""
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
        if wu.get("wu_id") is not None:
            self._seen_wu_ids.add(wu["wu_id"])
        if wu.get("nonce") is not None:
            self._seen_nonces.add(wu["nonce"])
        self._persist_seen(wu)

    @staticmethod
    def _payload_text(payload: object) -> str:
        """Extract the classifiable text from a WU payload.

        Payload is `unknown` in the contract; the text kind carries `{text: ...}`.
        """
        if isinstance(payload, dict):
            return str(payload.get("text", ""))[:MAX_WU_TEXT_LEN]
        if isinstance(payload, str):
            return payload[:MAX_WU_TEXT_LEN]
        return ""

    @staticmethod
    def _payload_lang(payload: object) -> str | None:
        if isinstance(payload, dict) and payload.get("lang") is not None:
            return str(payload["lang"])
        return None

    def process_wu(self, wu: dict, http: httpx.Client | None = None) -> dict:
        """Verify, classify, sign and submit a single work unit.

        Returns the posted `WorkUnitResult` body.
        """
        # The WU is adversary-influenced edge JSON; a non-object (e.g. a bare
        # list) or a missing signed field must reject cleanly, never crash with
        # an AttributeError/KeyError.
        if not isinstance(wu, dict):
            raise CorePinError("work unit is not a JSON object")

        wu_id = wu.get("wu_id")

        # The contract makes wu_id required; reject a missing/empty one rather
        # than building a bogus '/v1/wu/None/result' URL or an unkeyed result.
        if not wu_id:
            raise CorePinError("work unit missing wu_id")

        # Every field the canonical signed body covers must be present before we
        # serialize it, or canonical_wu_bytes would KeyError. (kind/payload/
        # core_pubkey_id join wu_id in the signed envelope.)
        for field in ("kind", "payload", "core_pubkey_id"):
            if field not in wu:
                raise CorePinError(f"work unit missing {field}")

        # Anti-replay before doing any work.
        if self._seen(wu):
            self._joblog.append({"event": "replay_rejected", "wu_id": wu_id})
            raise ReplayError(f"work unit already processed: {wu_id}")

        # Verify the core signature against the pinned key. A missing or
        # malformed signature envelope is an unverifiable WU -> CorePinError
        # (never an uncaught crash on adversary-influenced edge JSON). We do NOT
        # mark it seen, so a legitimate retry of a rejected WU is still possible.
        try:
            core_sig = base64.b64decode(wu["core_sig"], validate=True)
        except (KeyError, binascii.Error, ValueError) as e:
            raise CorePinError("work unit core_sig missing or malformed") from e
        verify_wu_signature(
            canonical_wu_bytes(wu),
            core_sig,
            wu.get("core_pubkey_id", ""),
        )

        # Classify the payload.
        payload = wu.get("payload")
        result = self._classifier.classify(
            self._payload_text(payload), self._payload_lang(payload)
        )

        # Sign the result with the LOCAL agent key. The signed bytes bind the
        # labels + score to this wu_id; the private key never enters the body.
        # MUST match services/core/app/wu_canonical.py (canonical_result_bytes):
        # score coerced to float and ensure_ascii=False, so an integer score or
        # a non-ASCII label still verifies on the core.
        labels = [result.label]
        score = float(result.score)
        signed_payload = {"wu_id": wu_id, "labels": labels, "score": score}
        result_bytes = json.dumps(
            signed_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        agent_sig = base64.b64encode(self._keys.sign(result_bytes)).decode()

        # FROZEN WorkUnitResult shape — exactly these four fields. labels/score
        # are reused verbatim from the signed payload so the bytes we signed and
        # the body we POST can never drift apart.
        body = {
            "labels": labels,
            "score": score,
            "agent_pubkey": self._keys.public_key_raw_b64(),
            "agent_sig": agent_sig,
        }

        url = self._egress.check(f"{self._edge}/v1/wu/{wu_id}/result")
        owns_client = http is None
        client = http or httpx.Client(timeout=30)
        try:
            resp = client.post(url, json=body)
        finally:
            if owns_client:
                client.close()

        resp.raise_for_status()
        # Mark seen only AFTER a successful POST: a transient delivery failure
        # raises above and leaves the WU eligible for a later retry, rather than
        # being silently dropped as "already processed".
        self._mark_seen(wu)
        self._joblog.append(
            {"event": "wu_processed", "wu_id": wu_id, "labels": body["labels"], "status": resp.status_code}
        )
        return body

    def register_agent(
        self, http: httpx.Client | None = None, invite_token: str = ""
    ) -> None:
        """Register this node with the edge on first run.

        A production core gates registration behind an operator-minted invite
        token (LUSTRO node N3): pass it here (the CLI reads
        LUSTRO_NODE_INVITE_TOKEN). A dev/local core leaves registration open,
        so an empty token is fine and simply omitted from the request.
        """
        url = self._egress.check(f"{self._edge}/v1/wu/register-agent")
        body = {"agent_pubkey": self._keys.public_key_raw_b64()}
        if invite_token:
            body["invite_token"] = invite_token
        owns_client = http is None
        client = http or httpx.Client(timeout=30)
        try:
            resp = client.post(url, json=body)
            resp.raise_for_status()
        finally:
            if owns_client:
                client.close()
        self._joblog.append({"event": "agent_registered", "agent_pubkey": body["agent_pubkey"]})

    def pull_and_process(self, http: httpx.Client | None = None) -> dict | None:
        """Pull one WU from the edge and process it; None if no work (204)."""
        url = self._egress.check(f"{self._edge}/v1/wu")
        owns_client = http is None
        client = http or httpx.Client(timeout=30)
        try:
            # Stream the response and enforce MAX_WU_RESPONSE_BYTES against the
            # bytes actually received, not the (untrustworthy, optional)
            # declared Content-Length header. A hostile edge can send a
            # Transfer-Encoding: chunked body with no Content-Length at all,
            # which would otherwise skip the size check entirely and let
            # resp.json() buffer an unbounded body into memory.
            with client.stream("GET", url) as resp:
                if resp.status_code == 204:
                    self._joblog.append({"event": "no_work"})
                    return None
                body = bytearray()
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > MAX_WU_RESPONSE_BYTES:
                        raise CorePinError("work unit response too large")
            try:
                wu = json.loads(bytes(body))
            except json.JSONDecodeError as e:
                raise CorePinError("edge response is not valid JSON") from e
            if not isinstance(wu, dict):
                raise CorePinError("edge returned a non-object work unit")
            return self.process_wu(wu, http=client)
        finally:
            if owns_client:
                client.close()
