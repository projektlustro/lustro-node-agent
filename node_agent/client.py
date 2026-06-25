"""Work-unit client: pull -> verify -> classify -> sign -> POST result.

Flow:
  1. GET `{edge}/v1/wu` for the next work unit.
  2. Verify the WU's `core_sig` against the PINNED core key (`core_pin`).
  3. Anti-replay: reject WUs whose nonce/wu_id has already been seen.
  4. Classify the content via the configured `Classifier`.
  5. Sign the result with the LOCAL agent key (`keys`).
  6. POST `{edge}/v1/wu/{id}/result`.

Every step is recorded to the JobLog. All network calls go through the
`EgressGuard`, so only the edge is reachable.
"""

import base64
import json

import httpx

from node_agent.classifier import Classifier
from node_agent.core_pin import verify_wu_signature
from node_agent.egress import EgressGuard
from node_agent.joblog import JobLog
from node_agent.keys import AgentKeys


class ReplayError(Exception):
    """Raised when a work unit nonce / wu_id has already been processed."""


def _canonical_wu_bytes(wu: dict) -> bytes:
    """Canonical byte serialization of the signed portion of a work unit.

    The core signs the WU minus its own signature envelope. We reconstruct the
    same bytes deterministically (sorted keys) for verification.
    """
    signed = {k: v for k, v in wu.items() if k not in ("core_sig", "core_key_id")}
    return json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()


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
        self._seen_nonces: set[str] = set()
        self._seen_wu_ids: set[str] = set()

    def _seen(self, wu: dict) -> bool:
        nonce = wu.get("nonce")
        wu_id = wu.get("id")
        return (nonce is not None and nonce in self._seen_nonces) or (
            wu_id is not None and wu_id in self._seen_wu_ids
        )

    def _mark_seen(self, wu: dict) -> None:
        if wu.get("nonce") is not None:
            self._seen_nonces.add(wu["nonce"])
        if wu.get("id") is not None:
            self._seen_wu_ids.add(wu["id"])

    def process_wu(self, wu: dict, http: httpx.Client | None = None) -> dict:
        """Verify, classify, sign and submit a single work unit."""
        wu_id = wu.get("id")

        # Anti-replay before doing any work.
        if self._seen(wu):
            self._joblog.append({"event": "replay_rejected", "wu_id": wu_id})
            raise ReplayError(f"work unit already processed: {wu_id}")

        # Verify the core signature against the pinned key.
        core_sig = base64.b64decode(wu["core_sig"])
        verify_wu_signature(
            _canonical_wu_bytes(wu),
            core_sig,
            wu.get("core_key_id", ""),
        )
        self._mark_seen(wu)

        # Classify.
        result = self._classifier.classify(wu.get("content", ""), wu.get("lang"))

        # Sign the result with the local agent key.
        result_payload = {
            "wu_id": wu_id,
            "label": result.label,
            "score": result.score,
        }
        result_bytes = json.dumps(
            result_payload, sort_keys=True, separators=(",", ":")
        ).encode()
        agent_sig = base64.b64encode(self._keys.sign(result_bytes)).decode()
        body = {
            **result_payload,
            "agent_sig": agent_sig,
            "agent_pubkey": self._keys.public_key_pem().decode(),
        }

        url = self._egress.check(f"{self._edge}/v1/wu/{wu_id}/result")
        owns_client = http is None
        client = http or httpx.Client(timeout=30)
        try:
            client.post(url, json=body)
        finally:
            if owns_client:
                client.close()

        self._joblog.append(
            {"event": "wu_processed", "wu_id": wu_id, "label": result.label}
        )
        return body

    def pull_and_process(self, http: httpx.Client | None = None) -> dict | None:
        """Pull one WU from the edge and process it; None if no work."""
        url = self._egress.check(f"{self._edge}/v1/wu")
        owns_client = http is None
        client = http or httpx.Client(timeout=30)
        try:
            resp = client.get(url)
            if resp.status_code == 204:
                return None
            wu = resp.json()
            return self.process_wu(wu, http=client)
        finally:
            if owns_client:
                client.close()
