# OSIRIS Master Claim Audit & Technical Grounding Register

**Classification:** Internal Architecture & Governance Audit  
**Document ID:** `CLAIM-AUDIT-20260927`  
**Governing Standard:** OSIRIS Epistemic Non-Substitution & Verification Standard  
**Last Updated:** 2026-09-27T11:15:00Z  

---

## 1. Audit Overview & Methodology

This audit cross-references every technical, architectural, cryptographic, and operational claim asserted across the OSIRIS documentation corpus against actual source code, unit test suites, and live runtime evidence.

### Epistemic Status Taxonomy
- **`IMPLEMENTED_TESTED`**: Backed by reproducible source code and passing automated offline tests in `/home/enki/osiris-governance` or `/home/enki/fold`.
- **`PROPOSED_DESIGN`**: Architecturally sound and formally specified; pending implementation or external dependency.
- **`UNVERIFIED_CONCEPTUAL`**: Theoretical hypothesis or design concept lacking direct empirical or platform-level evidence.
- **`REJECTED_OVERSTATED`**: Technically inaccurate, incompatible with underlying platform contracts (e.g., Cloud Run or Android), or claiming unsupported guarantees. **Must be removed or rewritten in all public artifacts.**

---

## 2. Comprehensive Claim Evaluation Matrix

| ID | Current Assertion in Draft | Category | Audit Concern / Technical Reality | Status | Source Location | Test Evidence | Safer Public Wording | Disposition |
|---|---|---|---|:---:|---|---|---|:---:|
| **CLM-001** | “Immutable, content-addressable binary container artifact anchored to Git SHA” | Cloud Run / Build | A container tag using `$COMMIT_SHA` is mutable; Docker tags can be overwritten or retargeted in Artifact Registry. | `REJECTED_OVERSTATED` | `cloudbuild.yaml`, `Dockerfile` | None (tags are mutable) | “Container candidate tagged by commit SHA; promote only immutable image digests (`sha256:...`).” | Revised |
| **CLM-002** | “Cloud Run runtime seccomp filter probing” | Cloud Run / Kernel | Cloud Run does not provide a workload-level contract for application inspection or control of seccomp state; `/proc` observations are not a reliable confinement guarantee. | `REJECTED_OVERSTATED` | `osiris/execution/` | None (unsupported platform API) | “Runtime health and platform-supported configuration checks; do not claim seccomp enforcement without documented platform evidence.” | Removed from claims |
| **CLM-003** | “Container capability drops (`CAP_DROP=ALL`)” | Cloud Run / Security | Docker capability drop directives do not map directly to Google Cloud Run’s fully managed execution surface. | `REJECTED_OVERSTATED` | `Dockerfile` | None | “Use Cloud Run’s documented sandbox and service configuration; validate identity, ingress, egress design, and application-level least privilege.” | Revised |
| **CLM-004** | “Runtime secrets injected dynamically and non-exportable” | Security / Secrets | Environment-injected secrets reside in process memory and can be exposed in debug logs or core dumps if mishandled. | `REJECTED_OVERSTATED` | `osiris/security/credentials.py` | `test_secret_redaction.py` (redacts, but doesn't make memory unreadable) | “Secrets are retrieved or mounted using approved secret management; minimize scope, avoid logging, and rotate on exposure.” | Revised |
| **CLM-005** | “Immutable cryptographic ledger” | Cryptography / Audit | SHA-256 hash chains alone provide tamper-evidence upon verification, not physical storage immutability, trusted timestamps, or non-repudiation without external anchoring. | `REJECTED_OVERSTATED` | `src/osiris_governance/ledger.py` | `test_dynamic_ledger.py` | “Hash-linked local evidence ledger model; tamper resistance and retention require independently validated storage and signing controls.” | Revised |
| **CLM-006** | “Kotlin replaces runtime parsing checks with compile-time schema safety” | Edge / Android | Kotlin types ensure internal compile-time safety, but external inputs (JSON, Intents, QR codes, IPC, network) remain untrusted and require strict runtime schema validation. | `REJECTED_OVERSTATED` | Android codebase | None | “Kotlin types complement strict runtime schema validation at all trust boundaries.” | Revised |
| **CLM-007** | “Kotlin gives strict memory and thread safety by default” | Language / Concurrency | Kotlin reduces null-pointer errors but does not eliminate race conditions, deadlock, mutable aliasing, Android IPC flaws, or native JNI defects. | `REJECTED_OVERSTATED` | Android codebase | None | “Kotlin supports safer domain modeling; concurrency and input safety remain explicit engineering responsibilities.” | Revised |
| **CLM-008** | “Data class `val` guarantees immutable objects” | Language / Immutability | `val` enforces read-only reference reassignment, not deep immutability of the underlying object graph (e.g., mutable lists or maps). | `REJECTED_OVERSTATED` | Android codebase | None | “Use immutable collections, value objects, and defensive copies; `val` alone is insufficient for deep immutability.” | Revised |
| **CLM-009** | “Titan M2 signing guarantees unforgeable proof” | Hardware / Edge | Termux cannot directly invoke the Titan M2 chip; requires Android Keystore implementation, Key Attestation certificate verification, and backend validation. | `UNVERIFIED_CONCEPTUAL` | Edge design docs | None (Termux lacks hardware access) | “Designed to support device-bound signing; hardware-backed status must be demonstrated through validated Android Key Attestation.” | Downscoped to Target Design |
| **CLM-010** | “Post-quantum Android 17 ML-DSA integration” | Cryptography / Roadmap | Android 17 platform APIs and hardware integration for ML-DSA (FIPS 204) are future items not yet established or testable on current devices. | `UNVERIFIED_CONCEPTUAL` | Experimental papers | None | “Post-quantum signature support is a future research item pending documented platform support and implementation review.” | Moved to Research Roadmap |
| **CLM-011** | “ART ensures byte-identical output” | Runtime / Replay | Android Runtime (ART) with AOT/JIT does not guarantee deterministic floating-point, memory layout, or execution order across ABI versions and devices. | `REJECTED_OVERSTATED` | Runtime spec | None | “Deterministic replay requires fixed inputs, canonical serialization, fixed algorithm version, controlled RNG, and repeated output comparison.” | Revised |
| **CLM-012** | “Network security config whitelists outbound egress” | Android / Network | Android `networkSecurityConfig` controls TLS trust anchors and cleartext traffic; it is not an outbound destination firewall or IP allowlist. | `REJECTED_OVERSTATED` | Android manifest | None | “Use transport security configuration plus an app-level destination allowlist and, where needed, network/VPN/proxy enforcement.” | Revised |
| **CLM-013** | “App can inspect SELinux/kernel audit denials” | Android / Sandbox | Unprivileged Android applications cannot access `/var/log/audit`, `dmesg`, or SELinux audit buffers without root access. | `REJECTED_OVERSTATED` | Android cockpit spec | None | “Rely on Android’s app sandbox and documented platform behavior; collect only app-accessible diagnostics.” | Removed |
| **CLM-014** | “Host `/tmp` write proves Cloud Run filesystem escape” | Cloud Run / Sandbox | Writing to `/tmp` in Cloud Run is standard documented behavior (in-memory tmpfs); it does not indicate host breakout. | `REJECTED_OVERSTATED` | Forensic scripts | None | “Define explicit application write-policy tests; do not treat `/tmp` usage alone as host escape.” | Corrected |
| **CLM-015** | “Bluegrass Station / defense deployment relevance” | Governance / Defense | Language implies government endorsement, DoD contract authority, or operational field deployment readiness. | `REJECTED_OVERSTATED` | Proposals / narrative | None | “Research context only; no Department of Defense affiliation, authorization, or operational deployment claim.” | Strictly Prohibited |
| **CLM-016** | “RFC 8785 Canonical JSON Profile (V1)” | Governance / Data | Until 2026-10-01 the profile silently NFC-normalized strings and accepted integers beyond 2^53, emitting bytes RFC 8785 would not, and no test compared it with an RFC 8785 implementation. Both inputs are now rejected. | `IMPLEMENTED_TESTED` | `src/osiris_governance/canonical.py` | `test_canonical_rfc8785.py` (cross-implementation vs `rfc8785` 0.1.4, incl. 5,000-value differential) + `test_canonical_binding.py` | “A strict subset of RFC 8785: every accepted input serializes to the RFC 8785 bytes.” | Revised 2026-10-01 |
| **CLM-017** | “Adverse-First Monotonic Gating” | Governance / Gating | Upstream gate failure immediately forces `BLOCKED` status, preventing downstream execution. | `IMPLEMENTED_TESTED` | `src/osiris_governance/adjudication.py` | `test_adjudication.py` (8/8 PASS) | “Adverse-first monotonic gate evaluation; failures halt pipeline without side effects.” | Retained |
| **CLM-018** | “Permanent Failure Retention (`S_deployed=FALSE`)” | Provenance / Audit | Real operational failure campaign `REAL-CAMPAIGN-20260926T160434Z` is permanently recorded and never overwritten. | `IMPLEMENTED_TESTED` | `evidence/operational/` | `test_project_system.py` (10/10 PASS) | “Immutable historical failure record preserved; remediation appends new successor campaigns.” | Retained |
| **CLM-019** | “Cross-Plane Non-Substitution Invariant” | Architecture / Epistemic | Formal separation: $\text{SCIENCE} \not\vdash \text{DEPLOYMENT}$. | `IMPLEMENTED_TESTED` | `docs/13_CROSS_PLANE_PROVENANCE.md` | `test_cross_plane_provenance.py` (2/2 PASS) | “Strict epistemic boundary: simulation or experimental results cannot authorize deployment.” | Retained |
| **CLM-020** | “Layer 3 Risk Gateway with Fractional Kelly Sizing” | Risk / Financial | Evaluates multi-gate minimum function ($f^*$) with integer discretization threshold. | `IMPLEMENTED_TESTED` | `osiris/execution/` | `test_capability_governor.py` (PASS) | “Integer-scaled fractional risk sizing engine with hard circuit breaker.” | Retained |

---

## 3. Implementation Verification Checklist

- [x] All 15 problematic assertions cataloged with technical root causes.
- [x] Unverified hardware claims (Titan M2 direct access, post-quantum ML-DSA) converted to research hypotheses.
- [x] Cloud Run security model purged of unsupported kernel/seccomp claims.
- [x] Defense affiliation and deployment endorsements permanently removed.
- [x] Verified capabilities anchored to passing unit tests in test suite.
