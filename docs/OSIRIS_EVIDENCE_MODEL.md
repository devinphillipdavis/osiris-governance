# OSIRIS Canonical Evidence Model & Hash-Linked Ledger Specification

**Classification:** Evidence Architecture Standard  
**Document ID:** `OSIRIS-EVIDENCE-MODEL-V1`  
**Status:** Approved Reference Implementation  
**Governing Standard:** RFC 8785 JSON Canonicalization & OSIRIS Epistemic Separation  
**Last Updated:** 2026-10-01  

---

## 1. Architectural Purpose

In distributed autonomous systems, claims of verification or compliance are invalid without tamper-evident, reproducible evidence. The OSIRIS Evidence Model defines the canonical representation, hash-linking mechanisms, and scope boundaries required to establish verifiable audit trails across heterogeneous execution planes.

---

## 2. Canonical Data Representation: RFC 8785 Profile (V1)

To ensure that cryptographic digests are invariant across programming languages, operating systems, and serialization libraries, OSIRIS uses `OSIRIS-CANONICAL-JSON-V1`, implemented in `src/osiris_governance/canonical.py`. It is a **strict subset of RFC 8785 (JCS)**: it accepts fewer inputs, and every input it accepts serializes to exactly the bytes RFC 8785 produces. `tests/test_canonical_rfc8785.py` checks this against the independent `rfc8785` package, including a 5,000-value differential test.

### Canonicalization Invariants
1. **Deterministic Key Ordering:** Object keys are ASCII-only, so code-point order equals the UTF-16 code-unit order RFC 8785 specifies.
2. **Whitespace Stripping:** No whitespace outside of string literals (separators `,` and `:`).
3. **Unicode:** Strings must already be in NFC. Non-NFC input is **rejected, not normalized** (`NON_NFC_STRING`): canonicalization never changes a value it hashes. Producers that accept free text normalize it before building the record (as `LivLMService.handle_intent` does). Lone surrogates, bidirectional controls and C0 controls other than tab, newline and carriage return are rejected.
4. **Prohibition of IEEE 754 Floats:**
   - **Rationale:** Floating-point representations suffer from cross-platform non-determinism (`-0.0` vs `+0.0`, NaN payloads, precision differences between x86 and ARM).
   - **Enforcement:** Floats are strictly rejected at canonical boundaries. Continuous metrics (e.g., currency, percentages, weights) must be represented as **fixed-point integers** or scaled integer representations (e.g., basis points or integer micro-units), or as decimal strings.
5. **Integer Range:** Integers must lie within +/-(2^53 - 1) (`INTEGER_OUT_OF_RANGE` otherwise). RFC 8785 serializes numbers as IEEE 754 doubles, so larger integers cannot be represented exactly; encode them as decimal strings.
6. **Strict Parsing:** Duplicate keys, a byte-order mark, NaN/Infinity and trailing data are rejected at parse time (`strict_parse_json`).

Change log: on 2026-10-01 rules 3 and 5 changed from silently normalizing to NFC and accepting any integer, which produced bytes RFC 8785 would not, to rejecting those inputs. No digest of an input that is still accepted changed.

---

## 3. Four-Coordinate Scope Binding

Evidence cannot exist as an unanchored, floating assertion. Every evidence object in OSIRIS is strictly bound to a four-coordinate operational scope:

$$\operatorname{Scope}(E) = \big(\text{Artifact Digest}, \text{Environment ID}, \text{Execution Interval}, \text{Policy Revision}\big)$$

```
                               ┌────────────────────────────────────────────────────────┐
                               │                    EVIDENCE SCOPE                      │
                               ├────────────────────────────────────────────────────────┤
                               │ 1. Artifact:    sha256:d8c5f2b... (Pinned Digest)      │
                               │ 2. Environment: cloud-run-europe-west1                 │
                               │ 3. Interval:    [2026-09-27T10:00Z, 2026-09-27T10:15Z] │
                               │ 4. Policy:      POL-REV-20260926-01                    │
                               └────────────────────────────────────────────────────────┘
```

- **Scope Mismatch Invalidation:** If an evidence item is evaluated outside its declared interval or against a mutated artifact digest, the evaluation engine immediately emits a `SCOPE_MISMATCH_VIOLATION`.
- **Policy Pinning:** Evidence verified under Policy Revision $X$ cannot be reused to assert compliance under Policy Revision $X+1$ without re-adjudication.

---

## 4. The Local Hash-Linked Ledger Model

### Technical Grounding & Architectural Limitations
- **Tamper-Evidence vs. Absolute Immutability:** SHA-256 hash chains provide **tamper-evidence upon verification**—any modification to a historical event invalidates all downstream hash links. 
- **Storage Reality:** A local hash chain stored on disk or SQLite is *not* physically immutable against an attacker with root filesystem write access. True non-repudiation requires external anchoring (e.g., public transparency logs, RFC 3161 trusted timestamping authorities, or distributed witness nodes).

### Merkle Chaining Mechanics
Each ledger event $E_n$ is cryptographically chained to its predecessor $E_{n-1}$:

$$H_n = \operatorname{SHA-256}\Big(\operatorname{CanonicalJSON}(E_n) \,\|\, H_{n-1}\Big)$$

```
┌─────────────────────────┐       ┌─────────────────────────┐       ┌─────────────────────────┐
│        EVENT 01         │       │        EVENT 02         │       │        EVENT 03         │
├─────────────────────────┤       ├─────────────────────────┤       ├─────────────────────────┤
│ Parent: sha256:0000...  │◀──────│ Parent: sha256:a1b2...  │◀──────│ Parent: sha256:c3d4...  │
│ Payload: Secret Scan OK │       │ Payload: Tests Passed   │       │ Payload: Deploy Failed  │
│ Hash: sha256:a1b2...    │       │ Hash: sha256:c3d4...    │       │ Hash: sha256:e5f6...    │
└─────────────────────────┘       └─────────────────────────┘       └─────────────────────────┘
```

---

## 5. Failure Preservation & Immutability of Campaign Records

Traditional CI/CD systems treat failed builds as ephemeral noise, overwriting state with subsequent passing runs. OSIRIS enforces **Permanent Failure Preservation**:

- **No History Rewrites:** Failed release campaigns, security violations, and runtime denials are permanently recorded as first-class evidence.
- **Reference Case:** Campaign `REAL-CAMPAIGN-20260926T160434Z` recorded `S_deployed = FALSE` when a deployment was blocked. This record is frozen on disk (`evidence/operational/REAL-CAMPAIGN-20260926T160434Z/ROOT_HASH.json`) with root hash `sha256:fcb966e6b010c282531a7bc8c962b1154c156f71b9543e09968940e79dc314da`.
- **Successor Campaigns:** Remediation does not alter `REAL-CAMPAIGN-20260926T160434Z`. Instead, remediation creates a new campaign identifier (e.g., `REAL-CAMPAIGN-20260927T...`) which explicitly references the prior failure record as its predecessor.

---

## 6. Deterministic Replay Protocol

To independently verify any claim asserted in the evidence ledger, an auditor executes the deterministic replay protocol:

1. **Input Extraction:** Retrieve the raw, un-canonicalized inputs recorded in the evidence artifact.
2. **Canonical Transformation:** Run inputs through `canonicalize_json()`, which rejects floats, out-of-range integers and non-NFC strings.
3. **Digest Verification:** Assert that $\operatorname{SHA-256}(\operatorname{CanonicalJSON}(\text{Inputs})) == \text{Recorded Input Hash}$.
4. **Isolated Policy Execution:** Execute the exact policy version specified by `policy_revision` inside a deterministic runtime.
5. **Decision Comparison:** Assert that the re-computed gate outcome matches the recorded adjudication status exactly. If results diverge, the evidence is rejected as `UNVERIFIED_OR_CORRUPT`.
