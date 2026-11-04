# Specification Conformance and Implementation Choices

How `tpm-rs` handles contradictions and implementation choices in the TPM 2.0 Library Specification, compared with the TCG reference implementation (`tcgtpm`).

## Document Guide

| Path | IDs | Contents |
| :--- | :--- | :--- |
| [`tpm2_v185/`](tpm2_v185/README.md) | — | Spec PDFs (Parts 0–3, Errata v1) and their provenance. |
| [`CONFLICTS.md`](CONFLICTS.md) | `C-<DOM>-#` | Spec contradictions, `tcgtpm` spec violations, and intentional `tpm-rs` deviations. |
| [`DIVERGENCES.md`](DIVERGENCES.md) | `D-<DOM>-#` | Spec-permitted choices (including omitted commands) where `tpm-rs` and `tcgtpm` differ. |
| [`ALIGNED.md`](ALIGNED.md) | `A-<DOM>-#` | Spec-permitted choices where `tpm-rs` and `tcgtpm` agree. |

## Baseline and Scope

- **Spec**: v185 plus Errata v1. Errata v1 supersedes the clauses it amends. Behavioral text in Part 1 and Errata v1 is treated as normative and may produce conflicts.
- **Typos**: These obvious Part 3 typos are read as intended and have no entries: `TPM_RC_NV_INITIALIZED` (§31.1), `TPM_RC_OWNER` / `TPM_RC_PLATFORM` (§28.5), and "sign and encrypt" (§12.1, §12.2).
- **Behavior**: Entries describe the intended canonical behavior of `tpm2-engine`. A crate is named only when the behavior lives elsewhere (e.g., `tpm2`).
- **Crypto**: Choices internal to a `tpm2::crypto` backend (supported algorithms, RSA exponents, EdDSA verification mode, etc.) are out of scope.

## Identifiers

IDs are `<KIND>-<DOM>-#`, where `<KIND>` is `C`, `D`, or `A`. Within a domain, a number is never reused across files, so an item can move between files and keep its number.

| `<DOM>` | Domain |
| :--- | :--- |
| `CMD` | Command set and capabilities |
| `ALG` | Algorithms, curves, and key parameters |
| `WIRE` | Structures, marshaling, and buffer bounds |
| `DISP` | Dispatch, check ordering, and response codes |
| `SESS` | Sessions, HMAC, binding, and contexts |
| `POL` | Enhanced authorization (`TPM2_Policy*`) |
| `DA` | Dictionary attack protection |
| `HIER` | Hierarchies, startup/shutdown, and clear |
| `OBJ` | Object creation, loading, duplication, and wrapping |
| `SIG` | Signing, verification, and attestation |
| `NV` | NV Indices and counters |
| `PCR` | PCRs and localities |
| `CLK` | Time, Clock, and ACTs |

## Tags

| Tag | Meaning |
| :--- | :--- |
| `[SPEC-BUG]` | The spec is contradictory, incomplete, or wrong. |
| `[C-BUG]` | `tcgtpm` violates the spec. |
| `[RUST-BUG]` | `tpm-rs` does not yet match the behavior documented here. |
| `[?-BUG]` | Unclear whether the spec or `tcgtpm` is at fault. |
| `[DESIGN]` | Intentional `tpm-rs` design choice. |
| `[SECURITY]` | Has security impact. |
| `[UNIMPL]` | Intentionally not implemented in `tpm-rs`. |
