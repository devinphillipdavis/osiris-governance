"""Claim closure records: OSIRIS-CLAIM-CLOSURE-V1 schema and policy.

A closure is the final adjudication record of an evidence pack. It binds the digests of the
artifacts behind a decision to that decision, states the one claim that may be made and the
claims that may not, and records release, execution and promotion authority. It does not say
the claim is true. It says: this exact evidence supports only this bounded claim.

Invariants:
1. NO_SELF_REFERENCE: a closure carries no digest or signature of itself and binds no artifact
   that can only exist after it (its own signature, digest file, or verification report). Pack
   verification (stage A) precedes the closure and is bound; closure verification (stage B)
   follows it and is not.
2. EVIDENCE_BOUNDS_AUTHORITY: authority is capped by evidence status. Exploratory evidence never
   allows customer claims, release, or production deployment.
3. CLAIM_IS_NOT_PERMIT: a closure never grants execution. execution_authority is NONE and
   execution is BLOCKED in every closure; execution permits come from the capability governor.
4. NO_SELF_PROMOTION: a closure cannot raise its own evidence status; promotion needs a new record.
5. SIGNER_TRUTH: the signing block names the key that actually signed. A local key may not claim
   Cloud KMS or HSM custody.
6. RFC8785_BYTES: the signed payload is the OSIRIS-CANONICAL-JSON-V1 form of the closure, which is
   byte-identical to RFC 8785 for every input the profile accepts, so any JCS implementation can
   reproduce it.

Policy v1 defines release rules for EXPLORATORY_EMPIRICAL evidence only. Other evidence statuses
are rejected until their rules are decided; that is a policy decision, not a schema gap.

Signing and stage-B verification: closure_verify.py (pure). Reading and writing pack files:
scripts/closure_pack.py, kept outside the package so the package stays free of file I/O (INV-13).
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .canonical import CANONICALIZATION_VERSION, canonicalize_json
from .errors import ClosureValidationError

SCHEMA_VERSION = "1.0"
DOCUMENT_TYPE = "OSIRIS_CLAIM_CLOSURE"
SIGNING_PROFILE = "OSIRIS-CLOSURE-JCS-ED25519-V1"
SIGNATURE_INPUT = "RFC8785_CANONICAL_UTF8_BYTES"
CANONICALIZATION_BLOCK = {
    "profile": CANONICALIZATION_VERSION,
    "base_standard": "RFC8785",
    "encoding": "UTF-8",
}

CLOSURE_FILE = "closure.json"
DIGEST_FILE = "closure.json.sha256"
SIGNATURE_FILE = "closure.sig"
CLOSURE_REPORT_FILE = "verification/closure-verification-report.json"
# Files that exist only after the closure; binding any of them would be circular.
POST_CLOSURE_FILES = frozenset({CLOSURE_FILE, DIGEST_FILE, SIGNATURE_FILE, CLOSURE_REPORT_FILE})

REQUIRED_SUBJECTS = ("claim", "evidence_manifest", "provenance", "policy_decision")
REQUIRED_BINDINGS = ("pack_verification_report",)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_KMS_KEY_RE = re.compile(
    r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/\d+$"
)


class EvidenceStatus(str, Enum):
    EXPLORATORY_EMPIRICAL = "EXPLORATORY_EMPIRICAL"
    CONFIRMATORY_EMPIRICAL = "CONFIRMATORY_EMPIRICAL"


class ClaimCeiling(str, Enum):
    BOUNDED_EXPLORATORY_OBSERVATION = "BOUNDED_EXPLORATORY_OBSERVATION"
    BOUNDED_CONFIRMATORY_OBSERVATION = "BOUNDED_CONFIRMATORY_OBSERVATION"


class SignerType(str, Enum):
    LOCAL_ED25519 = "LOCAL_ED25519"
    GOOGLE_CLOUD_KMS = "GOOGLE_CLOUD_KMS"


# Evidence statuses policy v1 can adjudicate, and the highest claim ceiling each supports.
POLICY_V1_CEILINGS = {
    EvidenceStatus.EXPLORATORY_EMPIRICAL.value: ClaimCeiling.BOUNDED_EXPLORATORY_OBSERVATION.value,
}

_ENUMS: Dict[str, frozenset] = {
    "evidence_status": frozenset(e.value for e in EvidenceStatus),
    "claim_ceiling": frozenset(e.value for e in ClaimCeiling),
    "decision": frozenset({"CLAIM_ALLOWED", "CLAIM_DENIED"}),
    "confirmation_status": frozenset({"NOT_CONFIRMATORY", "CONFIRMATORY"}),
    "independent_replication_status": frozenset(
        {"NOT_PERFORMED", "PERFORMED_CONSISTENT", "PERFORMED_INCONSISTENT"}
    ),
    "pack_verification_status": frozenset({"PASS_AS_REPORTED", "FAIL"}),
    "deployment_authority": frozenset({"NONE", "INTERNAL_RESEARCH_ONLY", "PRODUCTION"}),
    "execution_authority": frozenset({"NONE", "GRANTED"}),
    "execution_decision": frozenset({"BLOCK", "ALLOW"}),
    "release_decision": frozenset({"HOLD", "DENY", "ALLOW"}),
    "autonomous_execution": frozenset({"BLOCKED", "ALLOWED"}),
    "qpu_execution": frozenset({"BLOCKED", "HUMAN_APPROVAL_REQUIRED", "ALLOWED"}),
    "customer_release": frozenset({"BLOCKED", "ALLOWED"}),
    "promotion_status": frozenset({"NOT_ELIGIBLE_FOR_SELF_PROMOTION"}),
    "promotion_decision": frozenset({"DENY_PROMOTION"}),
    "experiment_receipt_status": frozenset({"COMPLETE", "PARTIAL_OR_HISTORICAL", "NONE"}),
    "signer_type": frozenset(e.value for e in SignerType),
    "kms_or_hsm_status": frozenset({"UNVERIFIED", "VERIFIED"}),
}


# --------------------------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------------------------

class _Checker:
    """Accumulates violations so one validation pass reports every problem, not just the first."""

    def __init__(self) -> None:
        self.violations: List[str] = []

    def fail(self, code: str, message: str) -> None:
        self.violations.append(f"{code}: {message}")

    def obj(self, value: Any, path: str, required: Sequence[str], optional: Sequence[str] = ()) -> bool:
        if not isinstance(value, dict):
            self.fail("SCHEMA_TYPE", f"{path} must be an object")
            return False
        for key in required:
            if key not in value:
                self.fail("SCHEMA_MISSING", f"{path}.{key} is required")
        for key in sorted(set(value) - set(required) - set(optional)):
            self.fail("SCHEMA_UNKNOWN_FIELD", f"{path}.{key} is not part of {DOCUMENT_TYPE} v{SCHEMA_VERSION}")
        return True

    def text(self, parent: Mapping[str, Any], key: str, path: str) -> None:
        value = parent.get(key)
        if key in parent and (not isinstance(value, str) or not value.strip()):
            self.fail("SCHEMA_TYPE", f"{path}.{key} must be a non-empty string")

    def const(self, parent: Mapping[str, Any], key: str, path: str, expected: Any) -> None:
        if key in parent and parent[key] != expected:
            self.fail("SCHEMA_VALUE", f"{path}.{key} must be {expected!r}, got {parent[key]!r}")

    def enum(self, parent: Mapping[str, Any], key: str, path: str, vocabulary: str) -> None:
        if key in parent and parent[key] not in _ENUMS[vocabulary]:
            allowed = ", ".join(sorted(_ENUMS[vocabulary]))
            self.fail("SCHEMA_ENUM", f"{path}.{key} must be one of [{allowed}], got {parent[key]!r}")

    def boolean(self, parent: Mapping[str, Any], key: str, path: str) -> None:
        if key in parent and not isinstance(parent[key], bool):
            self.fail("SCHEMA_TYPE", f"{path}.{key} must be a boolean")

    def timestamp(self, parent: Mapping[str, Any], key: str, path: str) -> None:
        value = parent.get(key)
        if key in parent and (not isinstance(value, str) or not _TIMESTAMP_RE.match(value)):
            self.fail("SCHEMA_TIMESTAMP", f"{path}.{key} must be RFC 3339 UTC like 2026-10-01T14:26:00Z")

    def digest(self, parent: Mapping[str, Any], key: str, path: str) -> None:
        value = parent.get(key)
        if key in parent and (not isinstance(value, str) or not _DIGEST_RE.match(value)):
            self.fail("SCHEMA_DIGEST", f"{path}.{key} must be sha256:<64 lowercase hex>")

    def text_list(self, parent: Mapping[str, Any], key: str, path: str, non_empty: bool) -> None:
        value = parent.get(key)
        if key not in parent:
            return
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            self.fail("SCHEMA_TYPE", f"{path}.{key} must be a list of non-empty strings")
        elif non_empty and not value:
            self.fail("SCHEMA_EMPTY", f"{path}.{key} must not be empty")


def _check_relative_path(chk: _Checker, value: Any, path: str) -> None:
    if not isinstance(value, str) or not value:
        chk.fail("SCHEMA_TYPE", f"{path} must be a non-empty relative path")
        return
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or any(p in ("", ".", "..") for p in parts):
        chk.fail("UNSAFE_PATH", f"{path} must be a normalized relative POSIX path inside the pack, got {value!r}")


def _check_artifact_map(chk: _Checker, value: Any, path: str, required: Sequence[str]) -> None:
    if not isinstance(value, dict):
        chk.fail("SCHEMA_TYPE", f"{path} must be an object of name -> {{path, sha256}}")
        return
    for name in required:
        if name not in value:
            chk.fail("SCHEMA_MISSING", f"{path}.{name} is required")
    for name, entry in value.items():
        entry_path = f"{path}.{name}"
        if not _NAME_RE.match(name):
            chk.fail("SCHEMA_NAME", f"{entry_path}: names are lowercase snake_case")
        if chk.obj(entry, entry_path, ("path", "sha256")):
            _check_relative_path(chk, entry.get("path"), f"{entry_path}.path")
            chk.digest(entry, "sha256", entry_path)


def schema_violations(doc: Any) -> List[str]:
    chk = _Checker()
    top_required = (
        "schema_version", "document_type", "closure_id", "claim_id", "experiment_id",
        "created_at", "closed_at", "canonicalization", "hash_algorithm", "subject",
        "artifact_bindings", "claim_adjudication", "verification_summary", "authority_decisions",
        "permitted_claim", "prohibited_claims", "limitations", "promotion_requirements",
        "receipt_chain_binding", "signing",
    )
    if not chk.obj(doc, "closure", top_required):
        return chk.violations
    chk.const(doc, "schema_version", "closure", SCHEMA_VERSION)
    chk.const(doc, "document_type", "closure", DOCUMENT_TYPE)
    for key in ("closure_id", "claim_id", "experiment_id"):
        chk.text(doc, key, "closure")
    chk.timestamp(doc, "created_at", "closure")
    chk.timestamp(doc, "closed_at", "closure")
    chk.const(doc, "canonicalization", "closure", CANONICALIZATION_BLOCK)
    chk.const(doc, "hash_algorithm", "closure", "sha256")

    if "subject" in doc:
        _check_artifact_map(chk, doc["subject"], "closure.subject", REQUIRED_SUBJECTS)
    if "artifact_bindings" in doc:
        _check_artifact_map(chk, doc["artifact_bindings"], "closure.artifact_bindings", REQUIRED_BINDINGS)

    adj = doc.get("claim_adjudication")
    p = "closure.claim_adjudication"
    if "claim_adjudication" in doc and chk.obj(
        adj, p,
        ("evidence_status", "claim_ceiling", "decision", "claim_scope", "primary_conclusion",
         "null_result_status", "confirmation_status", "independent_replication_status"),
        ("secondary_observation",),
    ):
        for key in ("evidence_status", "claim_ceiling", "decision", "confirmation_status",
                    "independent_replication_status"):
            chk.enum(adj, key, p, key)
        for key in ("claim_scope", "primary_conclusion", "null_result_status"):
            chk.text(adj, key, p)
        if "secondary_observation" in adj and chk.obj(
            adj["secondary_observation"], f"{p}.secondary_observation", ("status", "statement")
        ):
            chk.text(adj["secondary_observation"], "status", f"{p}.secondary_observation")
            chk.text(adj["secondary_observation"], "statement", f"{p}.secondary_observation")

    ver = doc.get("verification_summary")
    p = "closure.verification_summary"
    if "verification_summary" in doc and chk.obj(
        ver, p, ("pack_verification_status", "completed_at", "verified_checks", "not_verified")
    ):
        chk.enum(ver, "pack_verification_status", p, "pack_verification_status")
        chk.timestamp(ver, "completed_at", p)
        chk.text_list(ver, "verified_checks", p, non_empty=True)
        chk.text_list(ver, "not_verified", p, non_empty=False)

    auth = doc.get("authority_decisions")
    p = "closure.authority_decisions"
    if "authority_decisions" in doc and chk.obj(
        auth, p,
        ("deployment_authority", "execution_authority", "customer_claim_allowed",
         "external_publication_allowed", "claim_decision", "execution_decision",
         "release_decision", "autonomous_execution", "qpu_execution", "release_status"),
    ):
        for key in ("deployment_authority", "execution_authority", "execution_decision",
                    "release_decision", "autonomous_execution", "qpu_execution"):
            chk.enum(auth, key, p, key)
        chk.enum(auth, "claim_decision", p, "decision")
        chk.boolean(auth, "customer_claim_allowed", p)
        chk.boolean(auth, "external_publication_allowed", p)
        status = auth.get("release_status")
        if "release_status" in auth and chk.obj(
            status, f"{p}.release_status", ("overall", "environment", "customer_release")
        ):
            chk.enum(status, "overall", f"{p}.release_status", "release_decision")
            chk.text(status, "environment", f"{p}.release_status")
            chk.enum(status, "customer_release", f"{p}.release_status", "customer_release")

    permitted = doc.get("permitted_claim")
    p = "closure.permitted_claim"
    if "permitted_claim" in doc and chk.obj(
        permitted, p, ("claim_text", "allowed_contexts", "required_qualifiers")
    ):
        chk.text(permitted, "claim_text", p)
        chk.text_list(permitted, "allowed_contexts", p, non_empty=True)
        chk.text_list(permitted, "required_qualifiers", p, non_empty=False)

    for list_key, fields in (
        ("prohibited_claims", ("id", "category", "prohibited_statement")),
        ("limitations", ("id", "statement")),
    ):
        items = doc.get(list_key)
        if list_key not in doc:
            continue
        if not isinstance(items, list) or not items:
            chk.fail("SCHEMA_EMPTY", f"closure.{list_key} must be a non-empty list")
            continue
        seen = set()
        for index, item in enumerate(items):
            item_path = f"closure.{list_key}[{index}]"
            if chk.obj(item, item_path, fields):
                for field_name in fields:
                    chk.text(item, field_name, item_path)
                if item.get("id") in seen:
                    chk.fail("DUPLICATE_ID", f"{item_path}.id {item.get('id')!r} repeats")
                seen.add(item.get("id"))

    promo = doc.get("promotion_requirements")
    p = "closure.promotion_requirements"
    if "promotion_requirements" in doc and chk.obj(
        promo, p,
        ("promotion_status", "requires_new_claim_or_signed_promotion_record", "required_artifacts",
         "target_evidence_status", "target_claim_ceiling", "current_decision"),
    ):
        chk.enum(promo, "promotion_status", p, "promotion_status")
        chk.boolean(promo, "requires_new_claim_or_signed_promotion_record", p)
        chk.text_list(promo, "required_artifacts", p, non_empty=True)
        chk.enum(promo, "target_evidence_status", p, "evidence_status")
        chk.enum(promo, "target_claim_ceiling", p, "claim_ceiling")
        chk.enum(promo, "current_decision", p, "promotion_decision")

    receipt = doc.get("receipt_chain_binding")
    p = "closure.receipt_chain_binding"
    if "receipt_chain_binding" in doc and chk.obj(
        receipt, p, ("chain_id", "experiment_receipt_status", "historical_evidence_limitations")
    ):
        chk.text(receipt, "chain_id", p)
        chk.enum(receipt, "experiment_receipt_status", p, "experiment_receipt_status")
        chk.text_list(receipt, "historical_evidence_limitations", p, non_empty=False)

    sig = doc.get("signing")
    p = "closure.signing"
    if "signing" in doc and chk.obj(
        sig, p,
        ("profile", "signer_type", "key_id", "public_key_fingerprint_sha256", "signature_algorithm",
         "signature_input", "signature_file", "digest_file", "cloud_kms_integration_status",
         "hsm_protection_status"),
        ("signing_event_audit_reference",),
    ):
        chk.const(sig, "profile", p, SIGNING_PROFILE)
        chk.enum(sig, "signer_type", p, "signer_type")
        chk.text(sig, "key_id", p)
        chk.digest(sig, "public_key_fingerprint_sha256", p)
        chk.const(sig, "signature_algorithm", p, "Ed25519")
        chk.const(sig, "signature_input", p, SIGNATURE_INPUT)
        chk.const(sig, "signature_file", p, SIGNATURE_FILE)
        chk.const(sig, "digest_file", p, DIGEST_FILE)
        chk.enum(sig, "cloud_kms_integration_status", p, "kms_or_hsm_status")
        chk.enum(sig, "hsm_protection_status", p, "kms_or_hsm_status")
        chk.digest(sig, "signing_event_audit_reference", p)
    return chk.violations


# --------------------------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------------------------

def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def policy_violations(doc: Mapping[str, Any]) -> List[str]:
    """Cross-field rules. Assumes the schema already passed."""
    chk = _Checker()
    adj = doc["claim_adjudication"]
    auth = doc["authority_decisions"]
    ver = doc["verification_summary"]
    promo = doc["promotion_requirements"]
    receipt = doc["receipt_chain_binding"]
    sig = doc["signing"]
    status = adj["evidence_status"]

    # EVIDENCE_BOUNDS_AUTHORITY
    if status not in POLICY_V1_CEILINGS:
        chk.fail(
            "UNSUPPORTED_EVIDENCE_STATUS",
            f"policy v1 defines release rules for {sorted(POLICY_V1_CEILINGS)} only, not {status}",
        )
    else:
        if adj["claim_ceiling"] != POLICY_V1_CEILINGS[status]:
            chk.fail("CEILING_EXCEEDS_EVIDENCE",
                     f"{status} supports at most {POLICY_V1_CEILINGS[status]}, not {adj['claim_ceiling']}")
        if status == EvidenceStatus.EXPLORATORY_EMPIRICAL.value:
            if auth["customer_claim_allowed"]:
                chk.fail("EXPLORATORY_CUSTOMER_CLAIM", "exploratory evidence cannot allow customer claims")
            if auth["release_decision"] == "ALLOW":
                chk.fail("EXPLORATORY_RELEASE", "exploratory evidence cannot allow release")
            if auth["deployment_authority"] == "PRODUCTION":
                chk.fail("EXPLORATORY_PRODUCTION", "exploratory evidence cannot carry production deployment authority")
            if adj["confirmation_status"] != "NOT_CONFIRMATORY":
                chk.fail("EXPLORATORY_CONFIRMATORY", "exploratory evidence must be marked NOT_CONFIRMATORY")
    if adj["confirmation_status"] != "CONFIRMATORY" and "REJECT" in adj["null_result_status"].upper():
        chk.fail("NON_CONFIRMATORY_REJECTION",
                 "a hypothesis can only be 'rejected' under a confirmatory protocol; "
                 "say it was not supported in the recorded data")

    # CLAIM_IS_NOT_PERMIT
    if auth["execution_authority"] != "NONE":
        chk.fail("CLOSURE_GRANTS_EXECUTION", "a closure cannot carry execution authority; use a governor permit")
    if auth["execution_decision"] != "BLOCK":
        chk.fail("EXECUTION_NOT_BLOCKED", "execution_decision must be BLOCK")
    if auth["autonomous_execution"] != "BLOCKED":
        chk.fail("AUTONOMOUS_EXECUTION_NOT_BLOCKED", "autonomous_execution must be BLOCKED")
    if auth["qpu_execution"] == "ALLOWED":
        chk.fail("QPU_EXECUTION_ALLOWED", "qpu_execution must be BLOCKED or HUMAN_APPROVAL_REQUIRED")

    # Release metadata must agree with the release decision.
    release = auth["release_status"]
    if release["overall"] != auth["release_decision"]:
        chk.fail("RELEASE_STATUS_MISMATCH",
                 f"release_status.overall {release['overall']} != release_decision {auth['release_decision']}")
    if auth["release_decision"] != "ALLOW" and release["customer_release"] != "BLOCKED":
        chk.fail("CUSTOMER_RELEASE_NOT_BLOCKED", "customer_release must be BLOCKED unless release is ALLOW")
    if auth["claim_decision"] != adj["decision"]:
        chk.fail("CLAIM_DECISION_MISMATCH",
                 f"authority_decisions.claim_decision {auth['claim_decision']} != claim_adjudication.decision {adj['decision']}")

    # NO_SELF_REFERENCE
    for section in ("subject", "artifact_bindings"):
        for name, entry in doc[section].items():
            if "closure" in name or name == "verification_report":
                chk.fail("SELF_REFERENTIAL_BINDING",
                         f"{section}.{name}: a closure cannot bind its own verification; "
                         "bind the stage-A report as pack_verification_report")
            if entry["path"] in POST_CLOSURE_FILES:
                chk.fail("SELF_REFERENTIAL_BINDING",
                         f"{section}.{name} binds {entry['path']}, which exists only after the closure")
    for check in ver["verified_checks"]:
        if check.startswith("closure_"):
            chk.fail("SELF_REFERENTIAL_CHECK",
                     f"verified_checks lists {check!r}; the pack report predates the closure and cannot have checked it")

    # Stage A before the closure; closure created before it is closed.
    if _parse_ts(ver["completed_at"]) > _parse_ts(doc["created_at"]):
        chk.fail("VERIFICATION_AFTER_CLOSURE", "pack verification completed_at is after closure created_at")
    if _parse_ts(doc["created_at"]) > _parse_ts(doc["closed_at"]):
        chk.fail("CLOSED_BEFORE_CREATED", "closed_at precedes created_at")
    if adj["decision"] == "CLAIM_ALLOWED" and ver["pack_verification_status"] != "PASS_AS_REPORTED":
        chk.fail("CLAIM_ALLOWED_WITHOUT_PASSING_PACK", "CLAIM_ALLOWED requires pack_verification_status PASS_AS_REPORTED")
    if (adj["independent_replication_status"] == "NOT_PERFORMED"
            and "independent_reproduction" not in ver["not_verified"]):
        chk.fail("UNDISCLOSED_REPRODUCTION_GAP",
                 "independent replication was not performed; not_verified must list independent_reproduction")

    # NO_SELF_PROMOTION
    if promo["requires_new_claim_or_signed_promotion_record"] is not True:
        chk.fail("SELF_PROMOTION", "promotion must require a new claim or signed promotion record")
    if promo["target_evidence_status"] == status:
        chk.fail("PROMOTION_TARGET_UNCHANGED", "target_evidence_status must differ from the current status")

    # Permitted claim must not contain a prohibited statement verbatim.
    texts = (doc["permitted_claim"]["claim_text"].casefold(), adj["primary_conclusion"].casefold())
    for item in doc["prohibited_claims"]:
        statement = item["prohibited_statement"].casefold()
        if any(statement in text for text in texts):
            chk.fail("PERMITTED_CLAIM_CONTAINS_PROHIBITED", f"prohibited claim {item['id']} appears in the permitted text")

    # Receipt chain: anything short of a complete chain must say what is missing.
    if receipt["experiment_receipt_status"] != "COMPLETE" and not receipt["historical_evidence_limitations"]:
        chk.fail("UNDISCLOSED_RECEIPT_GAP", "an incomplete receipt chain needs historical_evidence_limitations")
    if receipt["experiment_receipt_status"] == "COMPLETE" and "receipt_chain_export" not in doc["artifact_bindings"]:
        chk.fail("UNBOUND_RECEIPT_CHAIN", "a COMPLETE receipt chain must be bound as artifact_bindings.receipt_chain_export")

    # SIGNER_TRUTH
    key_id = sig["key_id"]
    if sig["signer_type"] == SignerType.LOCAL_ED25519.value:
        if key_id.startswith("projects/") or "cryptoKeyVersions" in key_id:
            chk.fail("LOCAL_KEY_CLAIMS_KMS", f"a local key cannot use a Cloud KMS resource name as key_id ({key_id})")
        if sig["cloud_kms_integration_status"] != "UNVERIFIED" or sig["hsm_protection_status"] != "UNVERIFIED":
            chk.fail("LOCAL_KEY_CLAIMS_KMS", "a local key cannot report Cloud KMS or HSM protection as VERIFIED")
        if "signing_event_audit_reference" in sig:
            chk.fail("LOCAL_KEY_CLAIMS_KMS", "signing_event_audit_reference applies to Cloud KMS signing only")
    else:
        if not _KMS_KEY_RE.match(key_id):
            chk.fail("KMS_KEY_ID", "GOOGLE_CLOUD_KMS key_id must name an exact CryptoKeyVersion")
        if "signing_event_audit_reference" not in sig:
            chk.fail("KMS_UNAUDITED", "GOOGLE_CLOUD_KMS signing needs signing_event_audit_reference")
    return chk.violations


# --------------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------------

def validate_closure(doc: Any) -> List[str]:
    """Returns every schema and policy violation ("CODE: message"); an empty list means valid.

    Policy rules run only once the schema passes, since they assume its shape.
    """
    violations = schema_violations(doc)
    if violations:
        return violations
    return policy_violations(doc)


def require_valid_closure(doc: Any) -> None:
    violations = validate_closure(doc)
    if violations:
        raise ClosureValidationError(violations)


def closure_signing_payload(doc: Mapping[str, Any]) -> bytes:
    """The exact bytes that are hashed and signed: the closure's canonical UTF-8 form.

    Nothing is excluded, because nothing self-referential is allowed inside the closure.
    """
    return canonicalize_json(doc)


def iter_bound_artifacts(doc: Mapping[str, Any]) -> Iterable[tuple]:
    """Yields (section, name, relative_path, sha256) for every artifact the closure binds."""
    for section in ("subject", "artifact_bindings"):
        for name, entry in sorted(doc[section].items()):
            yield section, name, entry["path"], entry["sha256"]


def summarize_authority(doc: Mapping[str, Any]) -> Dict[str, Optional[str]]:
    auth = doc.get("authority_decisions")
    adj = doc.get("claim_adjudication")
    auth = auth if isinstance(auth, dict) else {}
    adj = adj if isinstance(adj, dict) else {}
    return {
        "evidence_status": adj.get("evidence_status"),
        "claim_ceiling": adj.get("claim_ceiling"),
        "claim_decision": auth.get("claim_decision"),
        "execution_decision": auth.get("execution_decision"),
        "release_decision": auth.get("release_decision"),
    }
