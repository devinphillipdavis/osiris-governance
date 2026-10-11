# OSIRIS Android Edge Prototype: Architecture & Operational Boundaries

**Classification:** Edge Prototype Specification & Boundary Analysis  
**Document ID:** `OSIRIS-ANDROID-EDGE-PROTOTYPE-V1`  
**Status:** Experimental Prototype Design  
**Governing Standard:** OSIRIS Epistemic Separation & Edge Operational Standards  
**Last Updated:** 2026-09-27T11:26:00Z  

---

## 1. Prototype Scope & System Concept

The OSIRIS edge node prototype implements an asynchronous, store-and-forward telemetry cockpit operating across a dual-node topology:
1. **Workstation / Primary Server:** Runs the authoritative capability governor, simulation runner, and full evidence evaluation pipeline.
2. **Android Edge Node (Google Pixel Fold):** Functions as an **evidence cockpit and constrained observational node**, capturing field metrics, user attestation, and local state transitions.

> **Operational Boundary Warning:** The Android application is a **prototype evidence cockpit and constrained node, NOT a hardened execution vault.** It must not be represented as an uncompromisable physical security anchor or autonomous authority plane until runtime enforcement is independently validated.

---

## 2. Technical Grounding & De-Scoping of Unsupported Claims

To maintain engineering accuracy, this prototype specification formally corrects earlier architectural assumptions:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             TECHNICAL DE-SCOPING MATRIX                          │
├──────────────────────────────┬───────────────────────────────────────────────────┤
│ Overstated Draft Assertion   │ Technical Grounding & Architectural Reality        │
├──────────────────────────────┼───────────────────────────────────────────────────┤
│ "Termux directly signs via   │ Termux runs in userland without hardware access to│
│  Titan M2 hardware vault"    │ Titan M2. Hardware-backed signing requires an     │
│                              │ Android companion APK using the Android Keystore.  │
├──────────────────────────────┼───────────────────────────────────────────────────┤
│ "Post-quantum ML-DSA signed  │ Android 14/15/16 Keystore does not support ML-DSA │
│  at the edge"                │ (FIPS 204). ML-DSA is a future research roadmap   │
│                              │ exploration item, not an active edge feature.     │
├──────────────────────────────┼───────────────────────────────────────────────────┤
│ "Kotlin compile-time types   │ Compile-time typing governs internal references;  │
│  eliminate runtime checks"   │ external inputs (JSON, IPC, SQLite, network) must │
│                              │ undergo strict runtime schema validation.         │
├──────────────────────────────┼───────────────────────────────────────────────────┤
│ "Kotlin data class `val`     │ `val` prevents reference reassignment only. Deep  │
│  ensures deep immutability"  │ immutability requires immutable collections and   │
│                              │ defensive copying.                                │
├──────────────────────────────┼───────────────────────────────────────────────────┤
│ "Network Security Config     │ `networkSecurityConfig` controls TLS trust anchors│
│  whitelists outbound egress" │ and cleartext HTTP; it is NOT an outbound packet  │
│                              │ firewall. Egress requires app-level allowlisting. │
├──────────────────────────────┼───────────────────────────────────────────────────┤
│ "Edge node monitors SELinux  │ Unprivileged Android userland cannot access       │
│  and kernel audit denials"   │ `/var/log/audit` or kernel `dmesg` buffers.       │
└──────────────────────────────┴───────────────────────────────────────────────────┘
```

---

## 3. Verified Hardware Attestation Architecture (Target Model)

To achieve genuine hardware-anchored device identity, the Android edge node must interface through a native Android Keystore companion bridge rather than raw shell scripts:

```
┌──────────────────────┐         IPC          ┌─────────────────────────────────────────┐
│     Termux / User    │─────────────────────▶│         Android Companion Service       │
│    Execution Node    │                      ├─────────────────────────────────────────┤
│ (Observational Logic)│                      │ 1. Generates Key in StrongBox / TEE     │
└──────────────────────┘                      │ 2. Issues KeyGenParameterSpec           │
                                              │ 3. Obtains Android Key Attestation Cert │
                                              └────────────────────┬────────────────────┘
                                                                   │ Device-Bound Signature
                                                                   ▼
                                              ┌─────────────────────────────────────────┐
                                              │           Titan M2 Security Chip        │
                                              │ (Hardware Private Key Storage & Signing)│
                                              └─────────────────────────────────────────┘
```

### Implementation Rules for Hardware Signing
1. **StrongBox / TEE Key Generation:** Keys must be created using `setIsStrongBoxBacked(true)` and `setPurposes(PURPOSE_SIGN)`.
2. **Key Attestation Verification:** The peer server or workstation must receive and cryptographically verify the certificate chain rooted in the Google Attestation Root Certificate to authenticate that the key was generated in legitimate hardware.
3. **No Key Extraction:** Private keys never enter userland memory or application storage.

---

## 4. Runtime Resilience & Store-and-Forward Sync

Android's aggressive power management (Doze Mode, App Standby buckets, Low Memory Killer) terminates long-running background processes. An edge node cannot assume continuous execution.

### Architectural Mitigations
1. **Foreground Service Execution:** Any active observational collector must run as an Android Foreground Service with an ongoing user-visible notification and appropriate wake lock management.
2. **Local SQLite WAL Durability:**
   - Telemetry events, state transitions, and audit records are written immediately to a local SQLite database configured with **Write-Ahead Logging (`PRAGMA journal_mode=WAL;`)**.
   - Records are structured as an append-only Merkle hash chain (`record_hash = SHA256(prev_hash + canonical_json(payload))`).
3. **Store-and-Forward Reconciliation:**
   - Network connectivity to the primary workstation or cloud is assumed to be intermittent.
   - When the WireGuard/Tailscale VPN link is active, the edge node flushes queued un-synced events to the primary ledger.
   - The primary node verifies cryptographic hash continuity before admitting edge events into the central evidence plane.

---

## 5. Security Posture Summary

| Capability | Current Prototype Status | Production Prerequisite |
|---|:---:|---|
| **Local SQLite WAL Storage** | `IMPLEMENTED` | Comprehensive schema migration tests |
| **Store-and-Forward Hash Chaining** | `IMPLEMENTED` | Offline partition recovery validation |
| **Android Foreground Service** | `PROTOTYPE` | Battery consumption and lifecycle profiling |
| **StrongBox Key Attestation** | `TARGET_DESIGN` | Native Kotlin companion APK with cert chain validator |
| **Post-Quantum ML-DSA Signing** | `RESEARCH_ROADMAP` | Formal Android platform API release and FIPS validation |
