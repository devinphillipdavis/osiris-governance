# OSIRIS Governance & Authority Control Plane

`osiris-governance` provides the deterministic capability governor and provider-neutral authority boundary for the OSIRIS ecosystem.

## Core Architectural Invariants

1. **Cognition Proposes; Governance Authorizes**: No cognitive substrate (Gemini, Antigravity, local model, or replay fixture) possesses execution authority. Substrates generate serialized `ActionProposal` records only.
2. **Deterministic Byte Binding**: Authorization decisions bind strictly to the exact serialized canonical bytes of the proposal via SHA-256. Any byte modification invalidates the binding.
3. **Fail-Closed Execution**: Action proposals are denied unless explicitly permitted by policy. All denials occur *prior* to adapter invocation.
4. **Zero Filesystem Authority in Replay**: In the offline replay slice, the adapter has zero filesystem, subprocess, network, or environment access.
5. **Non-Authoritative Replay Permits**: In offline replay, execution tokens are typed `ReplayExecutionPermit` with scope `REPLAY_ONLY_NON_CRYPTOGRAPHIC`. They confer zero authority for real-world side effects.

## Layout

```text
src/osiris_governance/
├── __init__.py
├── contracts.py       # ActionProposal, ReplayExecutionPermit, Enums
├── canonical.py       # OSIRIS-CANONICAL-JSON-V1 serialization & hashing (strict RFC 8785 subset)
├── closure.py         # Claim closure schema, policy v1, signed payload
├── closure_verify.py  # Closure signing and stage-B verification (pure)
├── signing.py         # Ed25519 over canonical bytes (optional `cryptography`)
├── governor.py        # Deterministic CapabilityGovernor & Policy
├── replay.py          # Pure in-memory ReplayAdapter (Zero filesystem)
└── errors.py          # Typed GovernanceViolation hierarchy
```

## Documentation

- [`OSIRIS_CLAIM_CLOSURE.md`](docs/OSIRIS_CLAIM_CLOSURE.md): Signed claim closure records: pack layout, two-stage verification, policy v1, and what verification does not establish. CLI: `scripts/closure_pack.py`.
  * Financial KPI: Digital Rights Retention Rate (100\% hardware-enforced protection; zero audit expenditure).

Strategic Executive Summary

* The Fundamental Shift: Encoding classical enterprise datasets into quantum state amplitudes converts information from an infinitely copyable, nonrival resource into a physical consumable good subject to measurement collapse.
* Restoration of Perfect Co