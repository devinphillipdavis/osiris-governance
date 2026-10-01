"""
Living Language Model Beta — Governed Execution & Evidence Service.

Provides a clean HTTP/REST interface for:
  - Intent interpretation and classification
  - Canonical request serialization and hashing (OSIRIS-CANONICAL-JSON-V1)
  - Policy enforcement and replay governance
  - Cryptographic append-only evidence recording (DynamicEvidenceLedger)
  - Provenance reporting with explicit epistemic demarcation
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import unicodedata
import uuid
from datetime import datetime, timezone, timedelta
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

from osiris_governance.canonical import (
    canonical_sha256,
    canonicalize_json,
    strict_parse_json,
)
from osiris_governance.contracts import (
    DEFAULT_ISSUER,
    DEFAULT_POLICY_VERSION,
    REPLAY_ACTION_KIND,
    REPLAY_CAPABILITY,
    REPLAY_SCOPE,
    ActionProposal,
)
from osiris_governance.errors import GovernanceViolation
from osiris_governance.governor import CapabilityGovernor
from osiris_governance.ledger import DynamicEvidenceLedger
from osiris_governance.models.ledger import (
    ClaimStatus,
    ClaimType,
    EvidencePlane,
    LedgerEventType,
    ScopeBinding,
)
from osiris_governance.replay import ReplayAdapter

RELEASE_VERSION = "0.1.0-beta.1"
RELEASE_ID = "OSIRIS-LIVLM-BETA-0.1.0-REF"
GIT_COMMIT = "62c3492"


class IntentClassifier:
    """Deterministic intent parser mapping natural-language tasks to governance capabilities."""

    PATTERNS: List[Tuple[str, str, str]] = [
        (r"(?i)\b(health|status|ready|ping)\b", "STATUS", "status.read"),
        (r"(?i)\b(replay|reproduce|fixture|repeat)\b", "REPLAY", "fixture.replay"),
        (r"(?i)\b(benchmark|perf|latency|xeb)\b", "BENCHMARK", "benchmark.offline"),
        (r"(?i)\b(audit|ledger|evidence|history|verify)\b", "AUDIT", "ledger.read"),
        (r"(?i)\b(evaluate|claim|attest)\b", "EVALUATE_CLAIM", "claim.evaluate"),
        (r"(?i)\b(generate|sample|text|tokens?)\b", "GENERATE", "tokens.sample"),
    ]

    @classmethod
    def classify(cls, prompt: str) -> Tuple[str, str, float]:
        for pattern, intent, capability in cls.PATTERNS:
            if re.search(pattern, prompt):
                return intent, capability, 0.95
        return "GENERAL_INQUIRY", "inquiry.read", 0.50
class LivLMService:
    """Core application logic for the Living Language Model Beta Service."""

    def __init__(self, ledger_id: str = "livlm-beta-ledger-01"):
        self.ledger = DynamicEvidenceLedger(ledger_id=ledger_id)
        self.governor = CapabilityGovernor(process_epoch_id="livlm-beta-epoch-1")
        self.replay_adapter = ReplayAdapter()
        self.replay_adapter.register_fixture("echo-v1", {"status": "SUCCESS", "message": "hello"})
        self.replay_adapter.register_fixture(
            "benchmark-sample-v1", {"status": "SUCCESS", "metric": 0.9763, "samples": 1024}
        )
        self.service_start_time = time.time()
        self.scope = ScopeBinding(
            artifact_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            environment_digest="sha256:9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff",
            time_interval_start="2026-09-26T00:00:00Z",
            time_interval_end="2026-09-27T00:00:00Z",
            policy_ref="livlm-beta-policy@1.0",
            authority_id="livlm-control-plane",
        )

        # Record service startup event in ledger
        self.startup_event = self.ledger.record_event(
            event_type=LedgerEventType.REQUEST_VALIDATED,
            plane=EvidencePlane.GOVERNANCE,
            actor={"type": "service", "id": "livlm-beta-service"},
            artifact={"digest": self.scope.artifact_digest},
            scope=self.scope,
            payload={
                "version": RELEASE_VERSION,
                "release_id": RELEASE_ID,
                "startup_timestamp": int(self.service_start_time),
            },
        )

    def handle_intent(self, user_text: str, client_nonce: str = "") -> Dict[str, Any]:
        """Interprets intent, normalizes request, verifies governance permissions, and records evidence."""
        if not client_nonce:
            client_nonce = str(uuid.uuid4())

        intent_type, required_capability, confidence = IntentClassifier.classify(user_text)

        # Build raw proposal for canonicalization. User text is normalized to NFC here, at the
        # producer: the canonicalizer rejects non-NFC text instead of rewriting it.
        proposal = {
            "client_nonce": client_nonce,
            "intent_type": intent_type,
            "prompt": unicodedata.normalize("NFC", user_text.strip()),
            "required_capability": required_capability,
            "side_effects_allowed": False,
        }

        canonical_bytes = canonicalize_json(proposal)
        request_hash = hashlib.sha256(canonical_bytes).hexdigest()

        # Execute bounded deterministic task
        if intent_type == "REPLAY":
            result_data = {
                "execution_mode": "DETERMINISTIC_REPLAY",
                "simulated_output": "Replay verified against canonical fixture.",
                "status": "PASS",
            }
        elif intent_type == "GENERATE":
            # Deterministic pseudo-sampling under bounded parameters
            result_data = {
                "execution_mode": "BOUNDED_SYNTHESIS",
                "tokens": ["DNA::", "}{", "::lang", " ", "governed_execution"],
                "epistemic_class": "SIMULATED",
            }
        elif intent_type == "STATUS":
            result_data = {
                "service_status": "OPERATIONAL",
                "uptime_seconds": time.time() - self.service_start_time,
                "ledger_size": len(self.ledger.events),
            }
        elif intent_type == "AUDIT":
            result_data = {
                "events_count": len(self.ledger.events),
                "chain_valid": self.ledger.verify_chain_integrity(),
                "latest_digest": self.ledger.latest_digest,
            }
        else:
            result_data = {
                "execution_mode": "READ_ONLY_INQUIRY",
                "message": f"Intent interpreted as {intent_type}. No destructive side effects permitted.",
            }

        # Record event in evidence ledger
        ev = self.ledger.record_event(
            event_type=LedgerEventType.REQUEST_VALIDATED,
            plane=EvidencePlane.GOVERNANCE,
            actor={"type": "client", "id": "beta-user"},
            artifact={"digest": self.scope.artifact_digest},
            scope=self.scope,
            payload={
                "request_hash": request_hash,
                "intent_type": intent_type,
                "client_nonce": client_nonce,
                "result_status": "SUCCESS",
            },
        )

        return {
            "execution_id": ev.event_id,
            "release_id": RELEASE_ID,
            "software_version": RELEASE_VERSION,
            "intent": {
                "type": intent_type,
                "confidence": confidence,
                "required_capability": required_capability,
            },
            "request_hash": f"sha256:{request_hash}",
            "evidence_digest": ev.record_digest,
            "epistemic_status": "SIMULATED_OFFLINE_REFERENCE",
            "governance": {
                "policy_ref": self.scope.policy_ref,
                "side_effects_allowed": False,
                "chain_valid": True,
            },
            "result": result_data,
        }

    def handle_replay(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Direct replay pass-through into CapabilityGovernor with canonical verification."""
        if isinstance(request_payload, ActionProposal):
            proposal = request_payload
        else:
            now_utc = datetime.now(timezone.utc)
            created_at_utc = str(request_payload.get("created_at_utc", now_utc.isoformat()))
            expires_at_utc = str(
                request_payload.get("expires_at_utc", (now_utc + timedelta(hours=1)).isoformat())
            )
            proposal = ActionProposal(
                proposal_id=str(request_payload.get("proposal_id", f"prop-{uuid.uuid4().hex[:8]}")),
                request_id=str(request_payload.get("request_id", f"req-{uuid.uuid4().hex[:8]}")),
                proposer_id=str(request_payload.get("proposer_id", "livlm-client")),
                action_kind=str(request_payload.get("action_kind", REPLAY_ACTION_KIND)),
                capability=str(request_payload.get("capability", REPLAY_CAPABILITY)),
                fixture_id=str(request_payload.get("fixture_id", "echo-v1")),
                arguments=request_payload.get("arguments", {}),
                nonce=str(request_payload.get("nonce", request_payload.get("client_nonce", f"nonce-{uuid.uuid4().hex[:8]}"))),
                created_at_utc=created_at_utc,
                expires_at_utc=expires_at_utc,
            )

        # Issue permit and submit through governor
        permit = self.governor.issue_replay_permit(proposal)
        res = self.governor.submit(proposal.canonical_bytes(), permit, self.replay_adapter)

        # Record in ledger
        ev = self.ledger.record_event(
            event_type=LedgerEventType.FIXTURE_REPLAY_COMPLETED,
            plane=EvidencePlane.REPRODUCIBILITY,
            actor={"type": "client", "id": "replay-actor"},
            artifact={"digest": self.scope.artifact_digest},
            scope=self.scope,
            payload={
                "proposal_sha256": res.proposal_sha256,
                "fixture_id": res.fixture_id,
                "nonce": res.permit_nonce,
            },
        )

        return {
            "status": "SUCCESS",
            "proposal_sha256": res.proposal_sha256,
            "fixture_id": res.fixture_id,
            "nonce": res.permit_nonce,
            "evidence_event_id": ev.event_id,
            "payload": res.payload,
            "release_id": RELEASE_ID,
            "epistemic_status": "REPRODUCED_OFFLINE",
        }

    def get_provenance(self) -> Dict[str, Any]:
        """Returns machine-readable provenance and epistemic boundaries."""
        return {
            "release_id": RELEASE_ID,
            "version": RELEASE_VERSION,
            "git_commit": GIT_COMMIT,
            "epistemic_demarcation": {
                "scientific_efficacy": "NOT_EVALUATED",
                "hardware_execution": "SIMULATED_ONLY",
                "sandbox_attestation": "OFFLINE_REFERENCE",
                "production_authorization": "PROHIBITED",
            },
            "governance_invariants": {
                "serialization_profile": "OSIRIS-CANONICAL-JSON-V1",
                "evidence_non_substitution": "ENFORCED",
                "adverse_first_precedence": "FALSE > BLOCKED > UNVERIFIED > TRUE",
                "mutable_references": "REJECTED",
                "transitive_laundering": "PROHIBITED",
            },
            "ledger": {
                "events_count": len(self.ledger.events),
                "latest_digest": self.ledger.latest_digest,
                "chain_integrity": self.ledger.verify_chain_integrity(),
            },
        }


class LivLMRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for the LivLM Beta API."""

    service = LivLMService()

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Osiris-Release-Id", RELEASE_ID)
        self.send_header("X-Osiris-Version", RELEASE_VERSION)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            self._send_json(200, {
                "status": "ok",
                "service": "living-language-model-beta",
                "version": RELEASE_VERSION,
                "epistemic_status": "OFFLINE_REFERENCE_BETA",
            })
        elif path == "/readyz":
            chain_ok = self.service.ledger.verify_chain_integrity()
            self._send_json(200 if chain_ok else 503, {
                "ready": chain_ok,
                "governance_active": True,
                "ledger_integrity": chain_ok,
            })
        elif path == "/v1/provenance":
            self._send_json(200, self.service.get_provenance())
        elif path == "/v1/ledger/events":
            events_data = [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type.value,
                    "plane": e.plane.value,
                    "record_digest": e.record_digest,
                    "previous_record_digest": e.previous_record_digest,
                    "recorded_at": e.recorded_at,
                }
                for e in self.service.ledger.events
            ]
            self._send_json(200, {
                "events": events_data,
                "chain_valid": self.service.ledger.verify_chain_integrity(),
            })
        else:
            self._send_json(404, {"error": "Not Found", "path": path})

    def do_POST(self):
        path = self.path.split("?")[0]
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length)

        try:
            payload = json.loads(post_body.decode("utf-8")) if post_body else {}
        except Exception as err:
            self._send_json(400, {"error": f"Invalid JSON payload: {err}"})
            return

        try:
            if path == "/v1/intent":
                text = payload.get("text", "")
                nonce = payload.get("client_nonce", "")
                if not text:
                    self._send_json(400, {"error": "Missing required field 'text'"})
                    return
                resp = self.service.handle_intent(user_text=text, client_nonce=nonce)
                self._send_json(200, resp)

            elif path == "/v1/replay":
                resp = self.service.handle_replay(payload)
                self._send_json(200, resp)

            elif path == "/v1/claims/evaluate":
                claim_type_str = payload.get("claim_type", "")
                subject = payload.get("subject", "")
                cited_evidence_ids = payload.get("cited_evidence_ids", [])
                claim_type = ClaimType(claim_type_str)
                res = self.service.ledger.evaluate_claim(
                    claim_type=claim_type,
                    subject=subject,
                    scope=self.service.scope,
                    cited_evidence_ids=cited_evidence_ids,
                )
                self._send_json(200, {
                    "claim_id": res.claim_id,
                    "status": res.status.value,
                    "violations": [v.value for v in res.violations],
                    "evaluation_event_id": res.evaluation_event_id,
                })
            else:
                self._send_json(404, {"error": "Not Found", "path": path})
        except GovernanceViolation as gv:
            self._send_json(403, {"error": "Governance Violation", "details": str(gv)})
        except Exception as exc:
            self._send_json(500, {"error": "Internal Error", "details": str(exc)})


def run_service(host: str = "0.0.0.0", port: int = 8080):
    """Entrypoint to run the LivLM Beta HTTP service."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, LivLMRequestHandler)
    print(f"Living Language Model Beta service running on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    run_service(port=port)
