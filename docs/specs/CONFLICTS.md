# Specification Conflicts, Reference Bugs, and Intentional Deviations

## Algorithms (`ALG`)

### `C-ALG-1` -- `TPM_ECC_CURVE_448` buffers too small for `Ed448` [SPEC-BUG] [C-BUG]

- **Spec**: `Ed448` (RFC 8032) keys and signature hints are 57 octets and signatures are 114 octets. `TPM2B_ECC_PARAMETER` is bounded by `MAX_ECC_KEY_BYTES` (Part 2 §11.2.5.1) and `TPM2B_SIGNATURE_EDDSA` by `2 * MAX_ECC_KEY_BYTES` (§11.3.3); deriving `MAX_ECC_KEY_BYTES` from the 448-bit curve size gives 56 / 112 octets. `MAX_SIGNATURE_HINT_SIZE` (§11.3.9) has no stated minimum.
- **Spec fix**: When `TPM_ECC_CURVE_448` and `TPM_ALG_EDDSA` or `TPM_ALG_HASH_EDDSA` are supported, require `MAX_ECC_KEY_BYTES >= 57` and `MAX_SIGNATURE_HINT_SIZE >= 57`.
- **tcgtpm**: `MAX_ECC_KEY_BYTES = 56` (`TpmAlgorithmDefines.h`) regardless of `ALG_EDDSA`.
- **tpm-rs**: Implements the spec fix in `tpm2` when the `curve448` and `eddsa` features are enabled.

---

## Objects (`OBJ`)

### `C-OBJ-1` -- `TPM2_LoadExternal` with `nameAlg == TPM_ALG_NULL` [DESIGN] [C-BUG] [RUST-BUG]

- **Spec**: Part 3 §12.3 types `inPublic` as `TPM2B_PUBLIC+`, allowing `nameAlg == TPM_ALG_NULL`. Part 3 §12.4 (`TPM2_ReadPublic`) types `outPublic` as `TPM2B_PUBLIC`, which cannot represent such an object.
- **tcgtpm**: Loads the object; `TPM2_ReadPublic` on it fails response marshaling and enters Failure Mode.
- **tpm-rs**: Intentionally deviates from §12.3: rejects `nameAlg == TPM_ALG_NULL` with `TPM_RC_HASH + P2`.
  - *Required changes*: in `tpm2`, change `TpmtPublic::name_alg` from `Option<TpmiAlgHash>` to `TpmiAlgHash` and remove `Tpm2bPublic::unmarshal_nullable`; remove the `name_alg.is_none()` branches.

### `C-OBJ-2` -- `TPM2_CreateLoaded` without Derived Objects [DESIGN] [UNIMPL]

- **Spec**: Part 3 §12.9 and Part 1 §25 require `TPM2_CreateLoaded` to create Derived Objects under a Derivation Parent (`TPM_ALG_KEYEDHASH` with `restricted` and `decrypt` `SET`).
- **tcgtpm**: Supported.
- **tpm-rs**: Intentionally unsupported; such templates are rejected with `TPM_RC_ATTRIBUTES + P2`. Primary and Ordinary objects are supported.

---

## Signing and Verification (`SIG`)

### `C-SIG-1` -- Missing checks in `TPM2_VerifyDigestSignature` and `TPM2_SignDigest` [C-BUG]

- **Spec**: Part 3 §20.4 and §20.7 forbid `TPM_ALG_HMAC`, require the key to have a signing scheme, and require `digest.size` to match the scheme hash. §20.4 also requires `signature`'s scheme and hash to match the key's.
- **tcgtpm**: `VerifyDigestSignature.c` performs none of these checks for non-ML-DSA keys; `SignDigest.c` accepts `TPM_ALG_HMAC` keys.
- **tpm-rs**: Follows the spec: `TPM_RC_SCHEME + H1` (HMAC or NULL-scheme key), `TPM_RC_SIZE + P2` (digest size), `TPM_RC_SCHEME + P3` (signature mismatch).

### `C-SIG-2` -- Restricted HMAC keys and sequence/verify commands [SPEC-BUG]

- **Spec**: Restricted `TPM_ALG_KEYEDHASH` keys MAC digests (`TPM2_Sign`), while sequence commands MAC raw messages, so restricted keys cannot use sequences. Two gaps:
  1. Part 3 §17.5 (`TPM2_SignSequenceStart`) states this only in a Note; §17.6 (`TPM2_VerifySequenceStart`) omits it.
  2. Errata v1 §3.2 says `TPM2_Sign` remains required for restricted MAC keys, but not that `TPM2_VerifySignature` remains required to verify them (`TPM2_VerifyDigestSignature` forbids HMAC).
- **Spec fix**: Add a normative `TPM_RC_KEY` check for restricted `TPM_ALG_KEYEDHASH` keys to §17.5 and §17.6; extend Errata v1 §3.2 to cover `TPM2_VerifySignature`.
- **tcgtpm**: Returns `TPM_RC_KEY + H1` in both sequence start commands.
- **tpm-rs**: Agrees with `tcgtpm`.

---

## NV Storage (`NV`)

### `C-NV-1` -- Orderly counter NV write threshold [SPEC-BUG]

- **Spec**: After a disorderly shutdown, an orderly counter recovers as `nvCount | MAX_ORDERLY_COUNT`, where `MAX_ORDERLY_COUNT` is $2^n - 1$. Part 1 §34.2.6.3 writes NV when `(ramCount & MAX_ORDERLY_COUNT) == 0`. Part 3 §31.2 and §31.8 use `ramCount - nvCount` thresholds instead (and disagree on `>=` vs. `>`). A difference threshold can roll the counter back: with `MAX_ORDERLY_COUNT = 0xFF`, `nvCount = 0xFA`, and `ramCount = 0x1F8`, no write occurs and recovery yields `0xFF`.
- **Spec fix**: Use Part 1's rollover rule in Part 3 §31.2 and §31.8.
- **tcgtpm**: Uses the rollover rule (`NV_Increment.c`).
- **tpm-rs**: Agrees with `tcgtpm`.
