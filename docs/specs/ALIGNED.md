# Aligned Implementation Choices (`tpm-rs` == `tcgtpm`)

## Sessions (`SESS`)

| ID | Spec | Open Point | Behavior |
| :--- | :--- | :--- | :--- |
| `A-SESS-2` | Part 1 §16.7.14 | Error code when a trial session authorizes a command. | `TPM_RC_ATTRIBUTES + S` |
| `A-SESS-3` | Part 1 §16.4 | Error code when `TPM_RS_PW` has a non-empty `nonceCaller`. | `TPM_RC_NONCE + S` |

---

## Objects (`OBJ`)

| ID | Spec | Open Point | Behavior |
| :--- | :--- | :--- | :--- |
| `A-OBJ-4` | Part 1 §24.7.3 | Size that `authValue` is padded to when wrapping `TPMT_SENSITIVE`. | The object's `nameAlg` digest size. |
| `A-OBJ-5` | Part 2 §12.3.7 | Maximum `TPM2B_PRIVATE` size accepted during unmarshaling. | Largest `_PRIVATE` for the enabled profile (e.g., 910 octets for RSA-2048); otherwise `TPM_RC_SIZE + P` (`tpm2`). |

---

## Signing and Verification (`SIG`)

| ID | Spec | Open Point | Behavior |
| :--- | :--- | :--- | :--- |
| `A-SIG-3` | Part 3 §18.1, §20.5 | Whether `inScheme` must match the key's scheme hash as well as its scheme. | Both must match; otherwise `TPM_RC_SCHEME`. |
| `A-SIG-4` | Part 3 §20.4, §20.7 | Error code for non-empty `context` with a scheme that takes no context. | `TPM_RC_VALUE + P1`, checked after key attributes and before the scheme. |

---

## NV Storage (`NV`)

| ID | Spec | Open Point | Behavior |
| :--- | :--- | :--- | :--- |
| `A-NV-2` | Part 1 §34.2.6.2 | Fill value for unwritten octets after a partial first write. | `0xFF`, or `0x00` if `TPMA_NV_ORDERLY` is `SET`. |
| `A-NV-3` | Part 3 §31.7, §31.13 | Error codes for `size > MAX_NV_BUFFER_SIZE` or `offset > dataSize`. | `TPM_RC_VALUE + P1` / `TPM_RC_VALUE + P2`, checked after lock/initialization checks and before `TPM_RC_NV_RANGE`. |
