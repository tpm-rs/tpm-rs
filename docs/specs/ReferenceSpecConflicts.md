# Reference Spec Conflicts

Places where the TCG reference implementation (`tcgtpm`) directly violates the
TPM 2.0 Library Specification (Version 185 with Errata v1). See
[`README.md`](README.md) for definitions and the entry template.

### Spec Conflict 1: `TPM2_ReadPublic` on an object with a NULL *nameAlg*

- **Spec:** Part 3 §12.3 types the *inPublic* parameter of `TPM2_LoadExternal`
  as `TPM2B_PUBLIC+`, where the `+` allows a *nameAlg* of `TPM_ALG_NULL`.
  Part 3 §12.4 (`TPM2_ReadPublic`) returns the public area of a loaded object,
  but types *outPublic* as `TPM2B_PUBLIC`, without the `+`.
- **Fix:** Undecided. The options are:
  - Type *outPublic* as `TPM2B_PUBLIC+` in §12.4, and marshal it that way in
    the reference implementation.
  - Stop allowing a *nameAlg* of `TPM_ALG_NULL` in `TPM2_LoadExternal` (§12.3),
    in both the specification and the reference implementation.
- **Reference implementation:** Loads such an object, but `TPM2_ReadPublic`
  marshals *outPublic* with `MARSHAL_ID_TPM2B_PUBLIC`, which rejects
  `TPM_ALG_NULL` while marshaling the response and puts the TPM into failure
  mode (`FATAL_ERROR_INTERNAL`). Neither command needs authorization, so any
  caller can trigger this.
- **tpm-rs:** Rejects a *nameAlg* of `TPM_ALG_NULL` in `TPM2_LoadExternal`
  (`TPM_RC_HASH + P2`), which matches the second option. The `tpm2` crate still
  accepts it when unmarshaling (`TpmtPublic::name_alg` is
  `Option<TpmiAlgHash>`).

### Spec Conflict 2: Missing checks in `TPM2_VerifyDigestSignature` and `TPM2_SignDigest`

- **Spec:** Part 3 §20.4 (`TPM2_VerifyDigestSignature`) and §20.7
  (`TPM2_SignDigest`) do not support `TPM_ALG_HMAC`, require the key to have a
  signing scheme, and require *digest* to be the size of that scheme's hash.
  §20.4 also requires the signature's scheme and hash to match the key's
  (`TPM_RC_SCHEME`).
- **Fix:** Add the missing checks to the reference implementation.
- **Reference implementation:** For keys other than ML-DSA,
  `VerifyDigestSignature.c` passes the signature straight to
  `CryptoCommon_ValidateDigestSignature()`, which checks none of these, so it
  verifies HMAC signatures, digests of any length, and signatures whose scheme
  or hash differs from the key's. `SignDigest.c` likewise signs with HMAC keys.
- **tpm-rs:** Follows the specification: `TPM_RC_SCHEME + H1` for an HMAC key
  or a key without a signing scheme, `TPM_RC_SIZE + P2` for a digest of the
  wrong size, and, in `TPM2_VerifyDigestSignature`, `TPM_RC_SCHEME + P3` for a
  signature whose scheme or hash does not match the key's.

### Spec Conflict 3: `MAX_ECC_KEY_BYTES` is too small for Ed448

- **Spec:** Part 2 §11.2.5.1 sizes `TPM2B_ECC_PARAMETER` by
  `MAX_ECC_KEY_BYTES`, "the largest ECC parameter". Ed448 (RFC 8032) public
  keys, private keys and the signature *R* value are 57 bytes, so a TPM that
  supports Curve448 with EdDSA needs a `MAX_ECC_KEY_BYTES` of at least 57. The
  same value sizes `TPM2B_SIGNATURE_EDDSA` (§11.3.3, twice `MAX_ECC_KEY_BYTES`,
  so 114 bytes for Ed448) and bounds `MAX_SIGNATURE_HINT_SIZE` (§11.3.9) from
  below.
- **Fix:** Use 57 in the reference implementation when Curve448 is the largest
  enabled curve. Optionally, add a note to §11.2.5.1 giving the Ed448 sizes.
- **Reference implementation:** Derives `MAX_ECC_KEY_BYTES` from the 448-bit
  key size of Curve448, giving 56 (`TpmAlgorithmDefines.h`), so 57-byte Ed448
  values do not fit.
- **tpm-rs:** Follows the fix: the `tpm2` crate uses 57 when the `curve448` and
  `eddsa` features are enabled.
