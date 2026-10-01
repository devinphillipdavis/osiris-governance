"""Signing and stage-B verification of claim closures. Pure: no file, clock or network access.

Callers pass in the bytes of closure.json, the detached digest and signature texts, the trusted
public key, and a hash_artifact callback that returns "sha256:<hex>" for a pack-relative path
(None if the file is missing, ValueError if the path escapes the pack). scripts/closure_pack.py
is the file-backed caller.

The trusted public key always comes from the caller, never from the pack: a pack that supplied
its own trust anchor would verify against whoever forged it.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from . import signing
from .canonical import strict_parse_json
from .closure import (
    SignerType,
    closure_signing_payload,
    iter_bound_artifacts,
    policy_violations,
    require_valid_closure,
    schema_violations,
    summarize_authority,
)
from .errors import ClosureValidationError, SchemaValidationError, SigningUnavailableError

PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT_RUN"

# Returns "sha256:<hex>" for a pack-relative path, None if absent; raises ValueError if unsafe.
ArtifactHasher = Callable[[str], Optional[str]]

# What a passing stage-B report does not establish. Listed in every report.
NOT_VERIFIED = (
    "truth_of_claim_statements: checks cover structure, bindings, policy and signature, not the science",
    "independent_reproduction: unless a separate reproduction record is bound and reviewed",
    "signing_key_custody: a valid signature proves possession of the private key, not KMS or HSM custody",
    "public_key_provenance: the trusted key was supplied by the caller",
    "pack_completeness: files in the pack that the closure does not bind are not examined",
    "retention: nothing here prevents deletion or wholesale replacement of the pack",
)


def artifact_failures(doc: Mapping[str, Any], hash_artifact: ArtifactHasher) -> List[str]:
    """Recomputes every bound artifact's SHA-256 via the caller. Assumes the schema passed."""
    failures = []
    for section, name, relative, declared in iter_bound_artifacts(doc):
        label = f"{section}.{name} ({relative})"
        try:
            actual = hash_artifact(relative)
        except ValueError as exc:
            failures.append(f"ARTIFACT_UNSAFE_PATH: {label}: {exc}")
            continue
        if actual is None:
            failures.append(f"ARTIFACT_MISSING: {label}")
        elif actual != declared:
            failures.append(f"ARTIFACT_HASH_MISMATCH: {label}: declared {declared}, file is {actual}")
    return failures


@dataclass(frozen=True)
class SignedClosure:
    closure_sha256: str
    public_key_fingerprint: str
    digest_text: str
    signature_text: str


def sign_closure(closure_bytes: bytes, hash_artifact: ArtifactHasher, private_key_pem: bytes) -> SignedClosure:
    """Validates a closure and its bindings, then returns the detached digest and signature texts.

    Refuses an invalid closure, a stale artifact hash, a non-local signer declaration, and a
    declared fingerprint that is not this key's.
    """
    doc = strict_parse_json(closure_bytes)
    require_valid_closure(doc)
    failures = artifact_failures(doc, hash_artifact)
    if failures:
        raise ClosureValidationError(failures)

    private_key = signing.load_private_key_pem(private_key_pem)
    fingerprint = signing.public_key_fingerprint(private_key.public_key())
    declared = doc["signing"]
    if declared["signer_type"] != SignerType.LOCAL_ED25519.value:
        raise ClosureValidationError(
            [f"SIGNER_MISMATCH: signing here uses a local key; closure declares {declared['signer_type']}"]
        )
    if declared["public_key_fingerprint_sha256"] != fingerprint:
        raise ClosureValidationError(
            [f"SIGNER_MISMATCH: closure declares {declared['public_key_fingerprint_sha256']}, key is {fingerprint}"]
        )

    payload = closure_signing_payload(doc)
    digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
    signature = signing.encode_signature(signing.sign_bytes(private_key, payload))
    return SignedClosure(digest, fingerprint, digest + "\n", signature + "\n")


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    details: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ClosureVerificationReport:
    """Stage-B report. PASS only if every check ran and passed."""
    status: str
    pack_name: str
    closure_id: Optional[str]
    claim_id: Optional[str]
    closure_sha256: Optional[str]
    trusted_key_fingerprint: Optional[str]
    authority: Dict[str, Optional[str]]
    checks: List[CheckResult]
    not_verified: List[str]
    verified_at: str
    report_type: str = "OSIRIS_CLOSURE_VERIFICATION"
    verifier: str = "osiris_governance.closure_verify/1"

    def check(self, name: str) -> CheckResult:
        return next(c for c in self.checks if c.name == name)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def verify_closure(
    closure_bytes: Optional[bytes],
    digest_text: Optional[str],
    signature_text: Optional[str],
    hash_artifact: ArtifactHasher,
    trusted_public_key_pem: bytes,
    verified_at: str,
    required_bindings: Sequence[str] = (),
    pack_name: str = "",
) -> ClosureVerificationReport:
    """Runs every stage-B check; None for closure_bytes, digest_text or signature_text means missing."""
    checks: List[CheckResult] = []

    def add(name: str, status: str, details: Sequence[str] = ()) -> None:
        checks.append(CheckResult(name, status, list(details)))

    doc: Any = None
    payload: Optional[bytes] = None
    schema_ok = False

    # 1. Strict parse: duplicate keys, floats, NaN, out-of-range integers, BOM, trailing data.
    if closure_bytes is None:
        add("closure_parse", FAIL, ["closure.json is missing"])
    else:
        try:
            doc = strict_parse_json(closure_bytes)
            add("closure_parse", PASS)
        except SchemaValidationError as exc:
            add("closure_parse", FAIL, [str(exc)])

    # 2. Canonical form: NFC strings, ASCII keys, no surrogates or control characters.
    if doc is not None:
        try:
            payload = closure_signing_payload(doc)
            add("closure_canonical", PASS)
        except SchemaValidationError as exc:
            add("closure_canonical", FAIL, [str(exc)])
    else:
        add("closure_canonical", NOT_RUN, ["closure did not parse"])

    # 3-4. Schema, then cross-field policy, required bindings and artifact hashes.
    if doc is not None:
        violations = schema_violations(doc)
        schema_ok = not violations
        add("closure_schema", PASS if schema_ok else FAIL, violations)
    else:
        add("closure_schema", NOT_RUN, ["closure did not parse"])
    if schema_ok:
        violations = policy_violations(doc)
        add("closure_policy", FAIL if violations else PASS, violations)
        missing = [n for n in required_bindings if n not in doc["artifact_bindings"]]
        add("required_bindings", FAIL if missing else PASS,
            [f"BINDING_REQUIRED: artifact_bindings.{n} is missing" for n in missing])
        failures = artifact_failures(doc, hash_artifact)
        add("artifact_hashes", FAIL if failures else PASS, failures)
    else:
        for name in ("closure_policy", "required_bindings", "artifact_hashes"):
            add(name, NOT_RUN, ["closure schema did not pass"])

    # 5. Detached digest of the canonical bytes.
    closure_sha256 = f"sha256:{hashlib.sha256(payload).hexdigest()}" if payload is not None else None
    if closure_sha256 is None:
        add("closure_digest", NOT_RUN, ["no canonical payload"])
    elif digest_text is None:
        add("closure_digest", FAIL, ["closure.json.sha256 is missing"])
    elif digest_text.strip() == closure_sha256:
        add("closure_digest", PASS)
    else:
        add("closure_digest", FAIL, [f"recorded {digest_text.strip()}, canonical bytes hash to {closure_sha256}"])

    # 6-7. Signer identity and signature, against the caller's key only.
    public_key = None
    fingerprint = None
    try:
        public_key = signing.load_public_key_pem(trusted_public_key_pem)
        fingerprint = signing.public_key_fingerprint(public_key)
    except SigningUnavailableError as exc:
        add("signer_identity", NOT_RUN, [str(exc)])
        add("closure_signature", NOT_RUN, [str(exc)])
    except ValueError as exc:
        add("signer_identity", NOT_RUN, [f"trusted public key unusable: {exc}"])
        add("closure_signature", NOT_RUN, [f"trusted public key unusable: {exc}"])
    if public_key is not None:
        if schema_ok:
            declared = doc["signing"]["public_key_fingerprint_sha256"]
            add("signer_identity", PASS if declared == fingerprint else FAIL,
                [] if declared == fingerprint else [f"closure declares {declared}, trusted key is {fingerprint}"])
        else:
            add("signer_identity", NOT_RUN, ["closure schema did not pass"])
        if payload is None:
            add("closure_signature", NOT_RUN, ["no canonical payload"])
        elif signature_text is None:
            add("closure_signature", FAIL, ["closure.sig is missing"])
        else:
            try:
                valid = signing.verify_signature(public_key, signing.decode_signature(signature_text), payload)
                add("closure_signature", PASS if valid else FAIL,
                    [] if valid else ["signature does not verify over the canonical closure bytes with the trusted key"])
            except ValueError as exc:
                add("closure_signature", FAIL, [str(exc)])

    not_verified = list(NOT_VERIFIED)
    if schema_ok and doc["signing"]["signer_type"] == SignerType.GOOGLE_CLOUD_KMS.value:
        not_verified.append("kms_signing_event: the declared Cloud KMS key version and audit reference were not checked")
    is_dict = isinstance(doc, dict)
    return ClosureVerificationReport(
        status=PASS if all(c.status == PASS for c in checks) else FAIL,
        pack_name=pack_name,
        closure_id=doc.get("closure_id") if is_dict else None,
        claim_id=doc.get("claim_id") if is_dict else None,
        closure_sha256=closure_sha256,
        trusted_key_fingerprint=fingerprint,
        authority=summarize_authority(doc) if is_dict else {},
        checks=checks,
        not_verified=not_verified,
        verified_at=verified_at,
    )
