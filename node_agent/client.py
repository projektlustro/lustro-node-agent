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

import httpx

from node_agent.classifier import Classifier
from node_agent.core_pin import CorePinError, verify_wu_signature
from node_agent.egress import EgressGuard
from node_agent.joblog import JobLog
from node_agent.keys import AgentKeys

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
    ) -> None:
        self._egress = EgressGuard(edge_base_url)
        self._edge = self._egress.allowed_base_url
        self._classifier = classifier
        self._keys = keys
        self._joblog = joblog
        self._seen_wu_ids: set[str] = set()
        self._seen_nonces: set[str] = set()

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

    @staticmethod
    def _payload_text(payload: object) -> str:
        """Extract the classifiable text from a WU payload.

        Payload is `unknown` in the contract; the text kind carries `{text: ...}`.
        """
        if isinstance(payload, dict):
            return str(payload.get("text", ""))
        if isinstance(payload, str):
            return payload
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
        wu_id = wu.get("wu_id")

        # The contract makes wu_id required; reject a missing/empty one rather
        # than building a bogus '/v1/wu/None/result' URL or an unkeyed result.
        if not wu_id:
            raise CorePinError("work unit missing wu_id")

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

    def pull_and_process(self, http: httpx.Client | None = None) -> dict | None:
        """Pull one WU from the edge and process it; None if no work (204)."""
        url = self._egress.check(f"{self._edge}/v1/wu")
        owns_client = http is None
        client = http or httpx.Client(timeout=30)
        try:
            resp = client.get(url)
            if resp.status_code == 204:
                self._joblog.append({"event": "no_work"})
                return None
            wu = resp.json()
            return self.process_wu(wu, http=client)
        finally:
            if owns_client:
                client.close()
