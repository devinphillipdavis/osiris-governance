"""Claim closures (OSIRIS-CLAIM-CLOSURE-V1): schema, policy, signing and stage-B verification.

Synthetic pack only (C-TEST-0001). Nothing here represents a real experiment.
"""

import copy
import hashlib
import json
import os

import pytest

pytest.importorskip("cryptography")

from osiris_governance import signing  # noqa: E402
from osiris_governance.closure import (  # noqa: E402
    CANONICALIZATION_BLOCK,
    CLOSURE_FILE,
    CLOSURE_REPORT_FILE,
    DIGEST_FILE,
    SIGNATURE_FILE,
    SIGNATURE_INPUT,
    SIGNING_PROFILE,
    closure_signing_payload,
    validate_closure,
)
from osiris_governance.closure_verify import verify_closure  # noqa: E402
from osiris_governance.errors import ClosureValidationError  # noqa: E402
from scripts import closure_pack  # noqa: E402

PACK_FILES = {
    "claim.json": '{"claim_id": "C-TEST-0001", "statement": "synthetic"}\n',
    "evidence-manifest.json": '{"files": ["raw/counts.json"]}\n',
    "provenance.json": '{"source": "synthetic fixture"}\n',
    "policy_decision.json": '{"decision": "CLAIM_ALLOWED", "policy": "test"}\n',
    "raw/counts.json": '{"00": 510, "11": 490}\n',
    "analysis/analyze.py": "print('synthetic')\n",
    "verification/pack-verification-report.json": '{"report_type": "SYNTHETIC", "status": "PASS"}\n',
}
CONCLUSION = "In the synthetic test pack, setting A had a higher point estimate of the declared score than setting B."


def build_closure(pack, fingerprint):
    def entry(relative):
        return closure_pack.artifact_entry(pack, relative)

    return {
        "schema_version": "1.0",
        "document_type": "OSIRIS_CLAIM_CLOSURE",
        "closure_id": "C-TEST-0001-CLOSURE-001",
        "claim_id": "C-TEST-0001",
        "experiment_id": "SYNTHETIC_EXPERIMENT_v1",
        "created_at": "2026-10-01T15:00:00Z",
        "closed_at": "2026-10-01T15:00:00Z",
        "canonicalization": dict(CANONICALIZATION_BLOCK),
        "hash_algorithm": "sha256",
        "subject": {
            "claim": entry("claim.json"),
            "evidence_manifest": entry("evidence-manifest.json"),
            "provenance": entry("provenance.json"),
            "policy_decision": entry("policy_decision.json"),
        },
        "artifact_bindings": {
            "pack_verification_report": entry("verification/pack-verification-report.json"),
            "raw_data": entry("raw/counts.json"),
            "analysis_script": entry("analysis/analyze.py"),
        },
        "claim_adjudication": {
            "evidence_status": "EXPLORATORY_EMPIRICAL",
            "claim_ceiling": "BOUNDED_EXPLORATORY_OBSERVATION",
            "decision": "CLAIM_ALLOWED",
            "claim_scope": "internal_bounded_exploratory_observation_only",
            "primary_conclusion": CONCLUSION,
            "null_result_status": "PREFERRED_CANDIDATE_NOT_SUPPORTED_IN_RECORDED_EXPLORATORY_DATA",
            "confirmation_status": "NOT_CONFIRMATORY",
            "independent_replication_status": "NOT_PERFORMED",
        },
        "verification_summary": {
            "pack_verification_status": "PASS_AS_REPORTED",
            "completed_at": "2026-10-01T14:50:00Z",
            "verified_checks": ["claim_schema_valid", "artifact_hashes_match_manifest"],
            "not_verified": ["independent_reproduction"],
        },
        "authority_decisions": {
            "deployment_authority": "INTERNAL_RESEARCH_ONLY",
            "execution_authority": "NONE",
            "customer_claim_allowed": False,
            "external_publication_allowed": False,
            "claim_decision": "CLAIM_ALLOWED",
            "execution_decision": "BLOCK",
            "release_decision": "HOLD",
            "autonomous_execution": "BLOCKED",
            "qpu_execution": "HUMAN_APPROVAL_REQUIRED",
            "release_status": {
                "overall": "HOLD",
                "environment": "INTERNAL_CONTROLLED",
                "customer_release": "BLOCKED",
            },
        },
        "permitted_claim": {
            "claim_text": CONCLUSION,
            "allowed_contexts": ["internal test report"],
            "required_qualifiers": ["synthetic", "exploratory"],
        },
        "prohibited_claims": [
            {"id": "T-PROHIBIT-001", "category": "generalization",
             "prohibited_statement": "Setting A is universally better than setting B."},
            {"id": "T-PROHIBIT-002", "category": "operations",
             "prohibited_statement": "This closure authorizes hardware execution."},
        ],
        "limitations": [{"id": "T-LIM-001", "statement": "Synthetic data; no physical experiment."}],
        "promotion_requirements": {
            "promotion_status": "NOT_ELIGIBLE_FOR_SELF_PROMOTION",
            "requires_new_claim_or_signed_promotion_record": True,
            "required_artifacts": ["signed_preregistered_protocol", "fresh_independent_data"],
            "target_evidence_status": "CONFIRMATORY_EMPIRICAL",
            "target_claim_ceiling": "BOUNDED_CONFIRMATORY_OBSERVATION",
            "current_decision": "DENY_PROMOTION",
        },
        "receipt_chain_binding": {
            "chain_id": "synthetic-chain",
            "experiment_receipt_status": "PARTIAL_OR_HISTORICAL",
            "historical_evidence_limitations": ["Synthetic pack; no lifecycle receipts exist."],
        },
        "signing": {
            "profile": SIGNING_PROFILE,
            "signer_type": "LOCAL_ED25519",
            "key_id": "osiris-local-test-ed25519",
            "public_key_fingerprint_sha256": fingerprint,
            "signature_algorithm": "Ed25519",
            "signature_input": SIGNATURE_INPUT,
            "signature_file": SIGNATURE_FILE,
            "digest_file": DIGEST_FILE,
            "cloud_kms_integration_status": "UNVERIFIED",
            "hsm_protection_status": "UNVERIFIED",
        },
    }


@pytest.fixture
def keys(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    private, public = key_dir / "signer.pem", key_dir / "signer.pub.pem"
    fingerprint = closure_pack.generate_keypair(private, public)
    return private, public, fingerprint


@pytest.fixture
def pack(tmp_path):
    root = tmp_path / "C-TEST-0001"
    for relative, text in PACK_FILES.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


@pytest.fixture
def signed_pack(pack, keys):
    closure_pack.write_closure(pack, build_closure(pack, keys[2]))
    closure_pack.sign_pack(pack, keys[0])
    return pack


def force_sign(pack, doc, private_path):
    """Signs whatever it is given, as a careless or hostile signer would; bypasses all checks."""
    for name in (SIGNATURE_FILE, DIGEST_FILE):
        (pack / name).unlink(missing_ok=True)
    (pack / CLOSURE_FILE).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    payload = closure_signing_payload(doc)
    (pack / DIGEST_FILE).write_text("sha256:" + hashlib.sha256(payload).hexdigest() + "\n")
    signature = signing.sign_bytes(signing.load_private_key_pem(private_path.read_bytes()), payload)
    (pack / SIGNATURE_FILE).write_text(signing.encode_signature(signature) + "\n")


def edit_closure_text(pack, old, new):
    path = pack / CLOSURE_FILE
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, old
    path.write_text(text.replace(old, new), encoding="utf-8")


def set_field(doc, dotted, value):
    *parents, leaf = dotted.split(".")
    target = doc
    for key in parents:
        target = target[int(key)] if isinstance(target, list) else target[key]
    if value is DELETE:
        del target[leaf]
    else:
        target[leaf] = value
    return doc


DELETE = object()


def failed(report):
    return {c.name for c in report.checks if c.status != "PASS"}


# --------------------------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------------------------

def test_valid_synthetic_pack_verifies(signed_pack, keys):
    report = closure_pack.verify_pack(signed_pack, keys[1])
    assert report.status == "PASS", [(c.name, c.details) for c in report.checks]
    assert failed(report) == set()
    assert report.trusted_key_fingerprint == keys[2]
    assert report.authority["execution_decision"] == "BLOCK"
    assert any(item.startswith("truth_of_claim_statements") for item in report.not_verified)


def test_reformatting_closure_json_does_not_break_signature(signed_pack, keys):
    doc = json.loads((signed_pack / CLOSURE_FILE).read_text())
    reordered = dict(reversed(list(doc.items())))
    (signed_pack / CLOSURE_FILE).write_text(json.dumps(reordered, indent=7, ensure_ascii=True))
    assert closure_pack.verify_pack(signed_pack, keys[1]).status == "PASS"


def test_any_rfc8785_implementation_reproduces_the_signed_bytes(signed_pack, keys):
    rfc8785 = pytest.importorskip("rfc8785")
    doc = json.loads((signed_pack / CLOSURE_FILE).read_text())
    independent = rfc8785.dumps(doc)
    assert independent == closure_signing_payload(doc)
    signature = signing.decode_signature((signed_pack / SIGNATURE_FILE).read_text())
    assert signing.verify_signature(signing.load_public_key_pem(keys[1].read_bytes()), signature, independent)
    recorded = (signed_pack / DIGEST_FILE).read_text().strip()
    assert recorded == "sha256:" + hashlib.sha256(independent).hexdigest()


def test_cli_check_sign_verify_round_trip(pack, keys, capsys):
    closure_pack.write_closure(pack, build_closure(pack, keys[2]))
    assert closure_pack.main(["check", str(pack)]) == 0
    assert closure_pack.main(["sign", str(pack), "--private-key", str(keys[0])]) == 0
    assert closure_pack.main(["verify", str(pack), "--public-key", str(keys[1])]) == 0
    report = json.loads((pack / CLOSURE_REPORT_FILE).read_text())
    assert report["status"] == "PASS"
    assert "/" not in report["pack_name"]  # no local filesystem paths leak into the report


# --------------------------------------------------------------------------------------------
# Tampering after signing
# --------------------------------------------------------------------------------------------

def test_elevating_evidence_status_after_signing_fails(signed_pack, keys):
    edit_closure_text(signed_pack, '"evidence_status": "EXPLORATORY_EMPIRICAL"',
                      '"evidence_status": "CONFIRMATORY_EMPIRICAL"')
    report = closure_pack.verify_pack(signed_pack, keys[1])
    assert report.status == "FAIL"
    assert {"closure_digest", "closure_signature", "closure_policy"} <= failed(report)


def test_allowing_execution_after_signing_fails(signed_pack, keys):
    edit_closure_text(signed_pack, '"execution_decision": "BLOCK"', '"execution_decision": "ALLOW"')
    report = closure_pack.verify_pack(signed_pack, keys[1])
    assert {"closure_signature", "closure_policy"} <= failed(report)
    assert any("EXECUTION_NOT_BLOCKED" in d for d in report.check("closure_policy").details)


def test_changing_bound_policy_hash_after_signing_fails(signed_pack, keys):
    doc = json.loads((signed_pack / CLOSURE_FILE).read_text())
    old = doc["subject"]["policy_decision"]["sha256"]
    edit_closure_text(signed_pack, old, "sha256:" + "0" * 64)
    report = closure_pack.verify_pack(signed_pack, keys[1])
    assert {"closure_signature", "artifact_hashes"} <= failed(report)


def test_changing_a_raw_artifact_fails_artifact_check_only(signed_pack, keys):
    (signed_pack / "raw/counts.json").write_text('{"00": 511, "11": 489}\n')
    report = closure_pack.verify_pack(signed_pack, keys[1])
    assert failed(report) == {"artifact_hashes"}
    assert "ARTIFACT_HASH_MISMATCH" in report.check("artifact_hashes").details[0]


def test_missing_artifact_fails(signed_pack, keys):
    (signed_pack / "analysis/analyze.py").unlink()
    report = closure_pack.verify_pack(signed_pack, keys[1])
    assert "ARTIFACT_MISSING" in report.check("artifact_hashes").details[0]


def test_wrong_trusted_key_fails_identity_and_signature(signed_pack, keys, tmp_path):
    other_private, other_public = tmp_path / "other.pem", tmp_path / "other.pub.pem"
    closure_pack.generate_keypair(other_private, other_public)
    report = closure_pack.verify_pack(signed_pack, other_public)
    assert {"signer_identity", "closure_signature"} == failed(report)


def test_missing_signature_and_digest_fail(signed_pack, keys):
    (signed_pack / SIGNATURE_FILE).unlink()
    (signed_pack / DIGEST_FILE).unlink()
    assert {"closure_signature", "closure_digest"} == failed(
        closure_pack.verify_pack(signed_pack, keys[1])
    )


def test_required_binding_enforced(signed_pack, keys):
    report = closure_pack.verify_pack(signed_pack, keys[1], required_bindings=["metric_definition"])
    assert failed(report) == {"required_bindings"}


# --------------------------------------------------------------------------------------------
# Policy violations, caught even when the signature is valid
# --------------------------------------------------------------------------------------------

POLICY_CASES = [
    ("customer-claim", "authority_decisions.customer_claim_allowed", True, "EXPLORATORY_CUSTOMER_CLAIM"),
    ("release-allow", "authority_decisions.release_decision", "ALLOW", "EXPLORATORY_RELEASE"),
    ("production", "authority_decisions.deployment_authority", "PRODUCTION", "EXPLORATORY_PRODUCTION"),
    ("execution-allow", "authority_decisions.execution_decision", "ALLOW", "EXECUTION_NOT_BLOCKED"),
    ("execution-granted", "authority_decisions.execution_authority", "GRANTED", "CLOSURE_GRANTS_EXECUTION"),
    ("autonomous", "authority_decisions.autonomous_execution", "ALLOWED", "AUTONOMOUS_EXECUTION_NOT_BLOCKED"),
    ("qpu", "authority_decisions.qpu_execution", "ALLOWED", "QPU_EXECUTION_ALLOWED"),
    ("release-status", "authority_decisions.release_status.overall", "DENY", "RELEASE_STATUS_MISMATCH"),
    ("customer-release", "authority_decisions.release_status.customer_release", "ALLOWED",
     "CUSTOMER_RELEASE_NOT_BLOCKED"),
    ("claim-decision", "authority_decisions.claim_decision", "CLAIM_DENIED", "CLAIM_DECISION_MISMATCH"),
    ("ceiling", "claim_adjudication.claim_ceiling", "BOUNDED_CONFIRMATORY_OBSERVATION",
     "CEILING_EXCEEDS_EVIDENCE"),
    ("confirmatory-status", "claim_adjudication.evidence_status", "CONFIRMATORY_EMPIRICAL",
     "UNSUPPORTED_EVIDENCE_STATUS"),
    ("exploratory-confirmatory", "claim_adjudication.confirmation_status", "CONFIRMATORY",
     "EXPLORATORY_CONFIRMATORY"),
    ("rejected-language", "claim_adjudication.null_result_status", "HYPOTHESIS_REJECTED",
     "NON_CONFIRMATORY_REJECTION"),
    ("kms-key-id-on-local", "signing.key_id",
     "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "LOCAL_KEY_CLAIMS_KMS"),
    ("kms-verified-on-local", "signing.cloud_kms_integration_status", "VERIFIED", "LOCAL_KEY_CLAIMS_KMS"),
    ("hsm-verified-on-local", "signing.hsm_protection_status", "VERIFIED", "LOCAL_KEY_CLAIMS_KMS"),
    ("self-check", "verification_summary.verified_checks", ["closure_schema_valid"], "SELF_REFERENTIAL_CHECK"),
    ("late-pack-verification", "verification_summary.completed_at", "2026-10-01T16:00:00Z",
     "VERIFICATION_AFTER_CLOSURE"),
    ("closed-before-created", "closed_at", "2026-10-01T14:59:59Z", "CLOSED_BEFORE_CREATED"),
    ("failed-pack", "verification_summary.pack_verification_status", "FAIL",
     "CLAIM_ALLOWED_WITHOUT_PASSING_PACK"),
    ("undisclosed-reproduction", "verification_summary.not_verified", [], "UNDISCLOSED_REPRODUCTION_GAP"),
    ("self-promotion", "promotion_requirements.requires_new_claim_or_signed_promotion_record", False,
     "SELF_PROMOTION"),
    ("promotion-target", "promotion_requirements.target_evidence_status", "EXPLORATORY_EMPIRICAL",
     "PROMOTION_TARGET_UNCHANGED"),
    ("prohibited-in-permitted", "permitted_claim.claim_text",
     CONCLUSION + " Setting A is universally better than setting B.", "PERMITTED_CLAIM_CONTAINS_PROHIBITED"),
    ("undisclosed-receipt-gap", "receipt_chain_binding.historical_evidence_limitations", [],
     "UNDISCLOSED_RECEIPT_GAP"),
    ("complete-chain-unbound", "receipt_chain_binding.experiment_receipt_status", "COMPLETE",
     "UNBOUND_RECEIPT_CHAIN"),
]


@pytest.mark.parametrize("field_path,value,code", [c[1:] for c in POLICY_CASES], ids=[c[0] for c in POLICY_CASES])
def test_policy_rule(pack, keys, field_path, value, code):
    doc = set_field(build_closure(pack, keys[2]), field_path, value)
    violations = validate_closure(doc)
    assert any(v.startswith(code + ":") for v in violations), violations


def test_baseline_closure_has_no_violations(pack, keys):
    assert validate_closure(build_closure(pack, keys[2])) == []


def test_validly_signed_policy_violation_still_fails(pack, keys):
    doc = set_field(build_closure(pack, keys[2]), "authority_decisions.customer_claim_allowed", True)
    force_sign(pack, doc, keys[0])
    report = closure_pack.verify_pack(pack, keys[1])
    assert report.check("closure_signature").status == "PASS"
    assert report.status == "FAIL" and failed(report) == {"closure_policy"}


def test_self_referential_binding_rejected(pack, keys):
    doc = build_closure(pack, keys[2])
    doc["artifact_bindings"]["closure_verification_report"] = {
        "path": CLOSURE_REPORT_FILE, "sha256": "sha256:" + "a" * 64,
    }
    codes = [v.split(":")[0] for v in validate_closure(doc)]
    assert codes.count("SELF_REFERENTIAL_BINDING") == 2  # by name and by path


def test_kms_signer_needs_exact_key_version_and_audit_reference(pack, keys):
    doc = set_field(build_closure(pack, keys[2]), "signing.signer_type", "GOOGLE_CLOUD_KMS")
    codes = {v.split(":")[0] for v in validate_closure(doc)}
    assert {"KMS_KEY_ID", "KMS_UNAUDITED"} <= codes
    doc["signing"]["key_id"] = "projects/p/locations/us-east1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3"
    doc["signing"]["signing_event_audit_reference"] = "sha256:" + "b" * 64
    assert validate_closure(doc) == []


def test_kms_declaration_is_reported_as_not_verified(pack, keys):
    doc = build_closure(pack, keys[2])
    doc["signing"].update(
        signer_type="GOOGLE_CLOUD_KMS",
        key_id="projects/p/locations/us-east1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3",
        signing_event_audit_reference="sha256:" + "b" * 64,
    )
    force_sign(pack, doc, keys[0])
    report = closure_pack.verify_pack(pack, keys[1])
    assert report.status == "PASS"
    assert any(item.startswith("kms_signing_event") for item in report.not_verified)


# --------------------------------------------------------------------------------------------
# Schema, parse and canonical-form violations
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("field_path", ["signing.signature_base64", "signing.closure_sha256"])
def test_embedded_signature_material_rejected(pack, keys, field_path):
    doc = set_field(build_closure(pack, keys[2]), field_path, "x")
    assert any(v.startswith("SCHEMA_UNKNOWN_FIELD:") for v in validate_closure(doc))


@pytest.mark.parametrize("bad_path", ["../outside.json", "/etc/passwd", "a/./b.json", "a\\b.json", ""])
def test_unsafe_binding_paths_rejected(pack, keys, bad_path):
    doc = set_field(build_closure(pack, keys[2]), "artifact_bindings.raw_data.path", bad_path)
    codes = {v.split(":")[0] for v in validate_closure(doc)}
    assert codes & {"UNSAFE_PATH", "SCHEMA_TYPE"}


def test_symlink_escaping_the_pack_is_rejected(pack, keys, tmp_path):
    (tmp_path / "outside.json").write_text("{}")
    os.symlink(tmp_path / "outside.json", pack / "link.json")
    doc = build_closure(pack, keys[2])
    doc["artifact_bindings"]["linked"] = {"path": "link.json", "sha256": "sha256:" + "c" * 64}
    force_sign(pack, doc, keys[0])
    report = closure_pack.verify_pack(pack, keys[1])
    assert any("ARTIFACT_UNSAFE_PATH" in d for d in report.check("artifact_hashes").details)


def test_missing_required_subject_rejected(pack, keys):
    doc = set_field(build_closure(pack, keys[2]), "subject.provenance", DELETE)
    assert "SCHEMA_MISSING: closure.subject.provenance is required" in validate_closure(doc)


@pytest.mark.parametrize(
    "old,new,check",
    [
        ('"claim_id": "C-TEST-0001"', '"claim_id": "C-TEST-0001", "claim_id": "C-TEST-0002"', "closure_parse"),
        ('"hash_algorithm": "sha256"', '"hash_algorithm": "sha256", "weight": NaN', "closure_parse"),
        ('"hash_algorithm": "sha256"', '"hash_algorithm": "sha256", "weight": 0.5', "closure_parse"),
        ('"hash_algorithm": "sha256"', '"hash_algorithm": "sha256", "count": 9007199254740993', "closure_parse"),
        ('"claim_id": "C-TEST-0001"', '"claim_id": "C-TEST-0001-e' + chr(0x301) + '"', "closure_canonical"),
    ],
    ids=["duplicate-key", "nan", "float", "too-large-integer", "non-nfc"],
)
def test_parse_and_canonical_violations(signed_pack, keys, old, new, check):
    edit_closure_text(signed_pack, old, new)
    report = closure_pack.verify_pack(signed_pack, keys[1])
    assert report.status == "FAIL"
    assert report.check(check).status == "FAIL"


# --------------------------------------------------------------------------------------------
# The signer refuses what the verifier would reject
# --------------------------------------------------------------------------------------------

def test_sign_refuses_policy_violation(pack, keys):
    doc = set_field(build_closure(pack, keys[2]), "authority_decisions.release_decision", "ALLOW")
    closure_pack.write_closure(pack, doc)
    with pytest.raises(ClosureValidationError) as excinfo:
        closure_pack.sign_pack(pack, keys[0])
    assert any(v.startswith("EXPLORATORY_RELEASE:") for v in excinfo.value.violations)
    assert not (pack / SIGNATURE_FILE).exists()


def test_sign_refuses_fingerprint_of_another_key(pack, keys):
    closure_pack.write_closure(pack, build_closure(pack, "sha256:" + "d" * 64))
    with pytest.raises(ClosureValidationError, match="SIGNER_MISMATCH"):
        closure_pack.sign_pack(pack, keys[0])


def test_sign_refuses_stale_artifact_hash(pack, keys):
    closure_pack.write_closure(pack, build_closure(pack, keys[2]))
    (pack / "claim.json").write_text('{"changed": true}\n')
    with pytest.raises(ClosureValidationError, match="ARTIFACT_HASH_MISMATCH"):
        closure_pack.sign_pack(pack, keys[0])


def test_signed_closure_is_not_rewritten_or_resigned(signed_pack, keys):
    with pytest.raises(FileExistsError):
        closure_pack.sign_pack(signed_pack, keys[0])
    with pytest.raises(FileExistsError):
        closure_pack.write_closure(signed_pack, build_closure(signed_pack, keys[2]))


def test_keygen_refuses_to_overwrite(keys):
    with pytest.raises(FileExistsError):
        closure_pack.generate_keypair(keys[0], keys[1])
    assert oct(keys[0].stat().st_mode & 0o777) == "0o600"


def test_closure_object_is_not_mutated_by_validation(pack, keys):
    doc = build_closure(pack, keys[2])
    before = copy.deepcopy(doc)
    validate_closure(doc)
    closure_signing_payload(doc)
    assert doc == before


# --------------------------------------------------------------------------------------------
# The pure verifier, without files
# --------------------------------------------------------------------------------------------

def test_pure_verifier_fails_closed_on_missing_closure(keys):
    report = verify_closure(None, None, None, lambda rel: None, keys[1].read_bytes(), "2026-10-01T16:00:00Z")
    assert report.status == "FAIL"
    assert report.check("closure_parse").details == ["closure.json is missing"]
    assert report.check("closure_signature").status == "NOT_RUN"


def test_pure_verifier_fails_closed_on_unusable_trusted_key(signed_pack):
    report = verify_closure(
        (signed_pack / CLOSURE_FILE).read_bytes(),
        (signed_pack / DIGEST_FILE).read_text(),
        (signed_pack / SIGNATURE_FILE).read_text(),
        closure_pack.pack_hasher(signed_pack),
        b"-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n",
        "2026-10-01T16:00:00Z",
    )
    assert report.status == "FAIL"
    assert failed(report) == {"signer_identity", "closure_signature"}
    assert report.check("closure_signature").status == "NOT_RUN"
