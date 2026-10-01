# OSIRIS Claim Closure Records (OSIRIS-CLAIM-CLOSURE-V1)

**Classification:** Evidence Architecture Standard
**Document ID:** `OSIRIS-CLAIM-CLOSURE-V1`
**Status:** Implemented; tested on synthetic packs only. No closure for a real claim has been signed yet.
**Last Updated:** 2026-10-01

Code: `src/osiris_governance/closure.py` (schema, policy, signed payload),
`src/osiris_governance/closure_verify.py` (signing and stage-B verification, pure),
`src/osiris_governance/signing.py` (Ed25519), `scripts/closure_pack.py` (files and CLI).
Tests: `tests/test_claim_closure.py`, `tests/test_canonical_rfc8785.py`.

---

## 1. What a closure is

A closure is the final adjudication record of an evidence pack. It binds the digests of the
artifacts behind a decision to that decision, states the one claim that may be made and the
claims that may not, and records release, execution and promotion authority.

It does not say the claim is true. It says: this exact signed evidence supports only this
bounded claim, under these limitations, with release and execution held.

## 2. Pack layout and the two verification stages

```text
PACK/
  claim.json, evidence-manifest.json, provenance.json, policy_decision.json, raw/, analysis/ ...
  verification/pack-verification-report.json      stage A: written BEFORE the closure, bound by it
  closure.json                                     the closure (any formatting)
  closure.json.sha256                              "sha256:<hex>" of the canonical bytes
  closure.sig                                      base64 Ed25519 signature over the canonical bytes
  verification/closure-verification-report.json    stage B: written AFTER, by `verify`; never bound
```

Stage A checks the pack's inputs (claim, raw data, analysis, policy). The closure binds that
report's hash as `artifact_bindings.pack_verification_report`.

Stage B checks the closure itself. Its report cannot be bound by the closure, because it does not
exist until the closure is signed. A closure that binds anything named `*closure*` or
`verification_report`, binds a post-closure file, or lists a `closure_*` check among the stage-A
`verified_checks` is rejected (`SELF_REFERENTIAL_BINDING`, `SELF_REFERENTIAL_CHECK`).

## 3. What is signed

```text
payload   = OSIRIS-CANONICAL-JSON-V1(closure)      # identical to RFC 8785 for every accepted input
digest    = "sha256:" + hex(SHA-256(payload))      -> closure.json.sha256
signature = Ed25519Sign(private_key, payload)      -> closure.sig (base64)
```

- The signature covers the canonical bytes directly, not the digest, so there is no
  "bytes or digest?" ambiguity.
- Nothing is excluded from the payload. The closure contains no digest or signature of itself:
  `signing.closure_sha256` and `signing.signature_base64` are unknown fields and are rejected.
- `closure.json` may be reformatted or have its keys reordered; the signature still verifies,
  because only the canonical form is signed.
- Any RFC 8785 implementation reproduces the payload (tested against the `rfc8785` package).
- Public key fingerprint: `"sha256:" + hex(SHA-256(raw 32-byte Ed25519 public key))`.

## 4. Document sections

All are required; unknown fields anywhere are rejected.

| Section | Contents |
|---|---|
| header | `schema_version` "1.0", `document_type` "OSIRIS_CLAIM_CLOSURE", `closure_id`, `claim_id`, `experiment_id`, `created_at`, `closed_at` (RFC 3339 UTC, `Z`), `canonicalization` {profile OSIRIS-CANONICAL-JSON-V1, base_standard RFC8785, encoding UTF-8}, `hash_algorithm` "sha256" |
| `subject` | `{claim, evidence_manifest, provenance, policy_decision}`, each `{path, sha256}` |
| `artifact_bindings` | name -> `{path, sha256}`; `pack_verification_report` required; anything else the decision rests on (raw-data manifest, analysis script and lockfile, metric definition, cost matrix, solver configuration, policy bundle, ...) |
| `claim_adjudication` | evidence status, claim ceiling, decision, scope, primary conclusion, optional secondary observation, null-result status, confirmation and independent-replication status |
| `verification_summary` | stage-A status (`PASS_AS_REPORTED` or `FAIL`), `completed_at`, `verified_checks`, `not_verified` |
| `authority_decisions` | deployment and execution authority, customer-claim and external-publication flags, claim/execution/release decisions, autonomous and QPU execution, `release_status` |
| `permitted_claim` | exact claim text, allowed contexts, required qualifiers |
| `prohibited_claims` | `[{id, category, prohibited_statement}]`, non-empty, unique ids |
| `limitations` | `[{id, statement}]`, non-empty, unique ids |
| `promotion_requirements` | promotion status, new-record requirement, required artifacts, target status and ceiling, current decision |
| `receipt_chain_binding` | `chain_id`, `experiment_receipt_status` (`COMPLETE`, `PARTIAL_OR_HISTORICAL`, `NONE`), `historical_evidence_limitations` |
| `signing` | profile, signer type, key id, public key fingerprint, algorithm, signature input, signature and digest file names, Cloud KMS and HSM status, optional KMS audit reference |

Artifact paths are normalized relative POSIX paths inside the pack: no absolute paths, `..`, `.`,
backslashes, or symlinks that resolve outside the pack. Artifacts are hashed as raw file bytes.

## 5. Policy v1

Policy v1 defines release rules for `EXPLORATORY_EMPIRICAL` evidence only. Any other evidence
status is rejected (`UNSUPPORTED_EVIDENCE_STATUS`) until its rules are decided. That is a policy
decision still to be made, not a gap in the schema.

| Code | Rule |
|---|---|
| `CEILING_EXCEEDS_EVIDENCE` | exploratory evidence supports at most `BOUNDED_EXPLORATORY_OBSERVATION` |
| `EXPLORATORY_CUSTOMER_CLAIM` | exploratory evidence cannot allow customer claims |
| `EXPLORATORY_RELEASE` | exploratory evidence cannot set `release_decision` to `ALLOW` |
| `EXPLORATORY_PRODUCTION` | exploratory evidence cannot carry `PRODUCTION` deployment authority |
| `EXPLORATORY_CONFIRMATORY` | exploratory evidence must be `NOT_CONFIRMATORY` |
| `NON_CONFIRMATORY_REJECTION` | "rejected" language needs a confirmatory protocol; say "not supported in the recorded data" |
| `CLOSURE_GRANTS_EXECUTION` | `execution_authority` must be `NONE`; execution permits come from the capability governor |
| `EXECUTION_NOT_BLOCKED` / `AUTONOMOUS_EXECUTION_NOT_BLOCKED` / `QPU_EXECUTION_ALLOWED` | execution stays blocked; QPU use at most `HUMAN_APPROVAL_REQUIRED` |
| `RELEASE_STATUS_MISMATCH` / `CUSTOMER_RELEASE_NOT_BLOCKED` | release metadata agrees with `release_decision` |
| `CLAIM_DECISION_MISMATCH` | `authority_decisions.claim_decision` equals `claim_adjudication.decision` |
| `VERIFICATION_AFTER_CLOSURE` / `CLOSED_BEFORE_CREATED` | stage A completes no later than `created_at`, which is no later than `closed_at` |
| `CLAIM_ALLOWED_WITHOUT_PASSING_PACK` | `CLAIM_ALLOWED` requires stage A `PASS_AS_REPORTED` |
| `UNDISCLOSED_REPRODUCTION_GAP` | without independent replication, `not_verified` lists `independent_reproduction` |
| `SELF_PROMOTION` / `PROMOTION_TARGET_UNCHANGED` | promotion requires a new record and a different target status |
| `PERMITTED_CLAIM_CONTAINS_PROHIBITED` | no prohibited statement appears verbatim in the permitted text or primary conclusion |
| `UNDISCLOSED_RECEIPT_GAP` / `UNBOUND_RECEIPT_CHAIN` | an incomplete chain lists its limitations; a complete chain is bound as `receipt_chain_export` |
| `LOCAL_KEY_CLAIMS_KMS` | a `LOCAL_ED25519` signer may not use a Cloud KMS resource name, report KMS/HSM as `VERIFIED`, or carry a KMS audit reference |
| `KMS_KEY_ID` / `KMS_UNAUDITED` | a `GOOGLE_CLOUD_KMS` signer names an exact `CryptoKeyVersion` and a signing-event audit reference |

`external_publication_allowed` is recorded but not restricted by v1: publishing a bounded
exploratory observation with its limitations is legitimate. Each pack decides.

## 6. Verification (stage B)

`python scripts/closure_pack.py verify PACK --public-key KEY.pub.pem` runs, in order:
`closure_parse` (strict JSON), `closure_canonical`, `closure_schema`, `closure_policy`,
`required_bindings` (from `--require-binding`), `artifact_hashes`, `closure_digest`,
`signer_identity` (declared fingerprint equals the trusted key's), and `closure_signature`.
The result is PASS only if every check ran and passed; a check that could not run counts as a failure.

The trusted public key always comes from the caller, never from the pack.

A passing report does **not** establish:

- that the claim's statements are true;
- independent reproduction;
- key custody (a signature proves possession of the private key, not KMS or HSM protection);
- the provenance of the trusted public key;
- the integrity of files the closure does not bind;
- retention (nothing prevents deletion or wholesale replacement of the pack).

## 7. Usage

```bash
pip install -e ".[signing]"                    # or ".[dev]" to run the tests
python scripts/closure_pack.py keygen --private signer.pem --public signer.pub.pem   # prints fingerprint
# build closure.json; scripts/closure_pack.py artifact_entry() and write_closure() help
python scripts/closure_pack.py check  PACK       # schema, policy, artifact hashes
python scripts/closure_pack.py sign   PACK --private-key signer.pem
python scripts/closure_pack.py verify PACK --public-key signer.pub.pem \
    --require-binding metric_definition --require-binding cost_matrix --require-binding solver_configuration
```

`sign` refuses a closure that fails `check`, a declared fingerprint that is not the key's, a
non-local signer declaration, and an already signed pack. A signed `closure.json` is never
rewritten in place; a correction is a new closure.

## 8. Departures from the 2026-10-01 design notes

The design notes for the C-000125 closure were the starting point. They were changed where they
were circular, unverifiable, or would have let a record claim more than it shows:

1. **Subject and bindings carry paths.** The notes listed bare digests; a digest without a path
   cannot be rechecked. Every binding is `{path, sha256}`.
2. **Detached signature, no self-digest.** The notes embedded `signing.closure_sha256` and
   `signing.signature_base64` with an exclusion rule. Both live in separate files, so nothing is
   excluded from the signed payload.
3. **Two verification reports.** The notes bound `verification_report_sha256` while listing
   `closure_schema_valid` among the checks it performed. A report cannot check a closure that
   does not yet exist. The stage-A report is bound; the stage-B report is not.
4. **No `closure_receipt` inside the closure.** A receipt that records the closure must reference
   the closure's digest, not the other way round.
5. **The signer is named truthfully.** The notes put a Cloud KMS `CryptoKeyVersion` path in
   `signing_key_id` while reporting KMS as unverified. A local key now has a local key id.
6. **The canonical bytes are signed directly**, not their SHA-256 digest.
7. **Only exploratory evidence is adjudicated** until rules for other statuses are decided.

## 9. Building the C-000125 closure

The C-000125 pack is not on the machine where this was written, so no C-000125 closure exists.
On the machine that holds the pack:

1. Record the exact source revision and run the pack verifier; keep `pack-verification-report.json`.
2. Check every statement in the draft (for example the replicate count per theta setting, the
   number of aggregate settings, the backend) against the pack itself. The draft came from a chat
   conversation and has not been checked against the pack files.
3. Build `closure.json` from the actual files with `artifact_entry()`. Bind at least the metric
   definition, cost matrix and solver configuration, since the claim rests on a W2-derived score.
4. `check`, `sign` with a local key (its id must not be a KMS path), then `verify` with
   `--require-binding` for those three.
