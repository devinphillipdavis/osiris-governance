"""Tests for Living Language Model Beta Service API and Governance Boundary."""

import pytest
from osiris_governance.livlm_service import (
    LivLMService,
    IntentClassifier,
    RELEASE_VERSION,
    RELEASE_ID,
)
from osiris_governance.models.ledger import ClaimStatus, ClaimType, ViolationType


def test_intent_classifier():
    intent, cap, conf = IntentClassifier.classify("Please check the health and status of the service")
    assert intent == "STATUS"
    assert cap == "status.read"
    assert conf > 0.9

    intent, cap, conf = IntentClassifier.classify("Replay fixture test-01")
    assert intent == "REPLAY"
    assert cap == "fixture.replay"

    intent, cap, conf = IntentClassifier.classify("Run benchmark suite on offline simulator")
    assert intent == "BENCHMARK"
    assert cap == "benchmark.offline"

    intent, cap, conf = IntentClassifier.classify("Audit the evidence ledger records")
    assert intent == "AUDIT"
    assert cap == "ledger.read"

    intent, cap, conf = IntentClassifier.classify("Hello, how are you?")
    assert intent == "GENERAL_INQUIRY"


def test_livlm_service_lifecycle_and_provenance():
    service = LivLMService(ledger_id="test-livlm-service")
    assert len(service.ledger.events) == 1
    assert service.ledger.verify_chain_integrity() is True

    prov = service.get_provenance()
    assert prov["version"] == RELEASE_VERSION
    assert prov["release_id"] == RELEASE_ID
    assert prov["epistemic_demarcation"]["scientific_efficacy"] == "NOT_EVALUATED"
    assert prov["epistemic_demarcation"]["production_authorization"] == "PROHIBITED"
    assert prov["governance_invariants"]["evidence_non_substitution"] == "ENFORCED"
    assert prov["ledger"]["chain_integrity"] is True


def test_livlm_service_intent_execution_and_evidence():
    service = LivLMService(ledger_id="test-livlm-intent")

    # Intent 1: Audit
    res = service.handle_intent("Audit the ledger and verify chain integrity", client_nonce="nonce-audit-01")
    assert res["release_id"] == RELEASE_ID
    assert res["software_version"] == RELEASE_VERSION
    assert res["intent"]["type"] == "AUDIT"
    assert res["epistemic_status"] == "SIMULATED_OFFLINE_REFERENCE"
    assert res["governance"]["side_effects_allowed"] is False
    assert res["governance"]["chain_valid"] is True
    assert res["result"]["chain_valid"] is True
    assert res["request_hash"].startswith("sha256:")

    # Intent 2: Status
    status_res = service.handle_intent("Report system status", client_nonce="nonce-status-02")
    assert status_res["intent"]["type"] == "STATUS"
    assert status_res["result"]["service_status"] == "OPERATIONAL"

    # Intent 3: Bounded generation
    gen_res = service.handle_intent("Generate sample DNA tokens", client_nonce="nonce-gen-03")
    assert gen_res["intent"]["type"] == "GENERATE"
    assert gen_res["result"]["epistemic_class"] == "SIMULATED"

    # Verify ledger grew and chain is valid
    assert len(service.ledger.events) == 4
    assert service.ledger.verify_chain_integrity() is True


def test_livlm_service_replay_governor_integration():
    service = LivLMService(ledger_id="test-livlm-replay")

    proposal = {
        "fixture_id": "echo-v1",
        "arguments": {"fixture_id": "echo-v1", "message": "hello"},
        "client_nonce": "nonce-replay-001",
    }

    replay_res = service.handle_replay(proposal)
    assert replay_res["status"] == "SUCCESS"
    assert replay_res["payload"]["message"] == "hello"
    assert replay_res["epistemic_status"] == "REPRODUCED_OFFLINE"
    assert replay_res["proposal_sha256"].startswith("sha256:")

    # Replay with same nonce must be rejected by CapabilityGovernor
    with pytest.raises(Exception):
        service.handle_replay(proposal)


def test_livlm_http_server_endpoints():
    import json
    import threading
    import urllib.request
    from http.server import HTTPServer
    from osiris_governance.livlm_service import LivLMRequestHandler

    server = HTTPServer(("127.0.0.1", 0), LivLMRequestHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. GET /healthz
        req = urllib.request.Request(f"{base_url}/healthz")
        with opener.open(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["status"] == "ok"
            assert data["epistemic_status"] == "OFFLINE_REFERENCE_BETA"

        # 2. GET /readyz
        req = urllib.request.Request(f"{base_url}/readyz")
        with opener.open(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["ready"] is True
            assert data["governance_active"] is True

        # 3. GET /v1/provenance
        req = urllib.request.Request(f"{base_url}/v1/provenance")
        with opener.open(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["version"] == RELEASE_VERSION
            assert data["release_id"] == RELEASE_ID

        # 4. POST /v1/intent
        body = json.dumps({"text": "Check audit ledger state", "client_nonce": "http-test-nonce-1"}).encode()
        req = urllib.request.Request(
            f"{base_url}/v1/intent",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["intent"]["type"] == "AUDIT"
            assert data["request_hash"].startswith("sha256:")

        # 5. GET /v1/ledger/events
        req = urllib.request.Request(f"{base_url}/v1/ledger/events")
        with opener.open(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["chain_valid"] is True
            assert len(data["events"]) >= 1

    finally:
        server.shutdown()
        server.server_close()


def test_decomposed_prompt_is_normalized_by_the_service_not_the_canonicalizer():
    # The canonicalizer rejects non-NFC text; the service, as producer, normalizes user input first.
    decomposed = "Replay fixture caf" + "e\u0301"
    composed = "Replay fixture caf\u00e9"
    first = LivLMService(ledger_id="test-nfc-1").handle_intent(decomposed, client_nonce="n-1")
    second = LivLMService(ledger_id="test-nfc-2").handle_intent(composed, client_nonce="n-1")
    assert first["request_hash"] == second["request_hash"]
