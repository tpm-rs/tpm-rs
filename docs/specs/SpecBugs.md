# Spec Bugs

Places where the TPM 2.0 Library Specification (Version 185 with Errata v1)
contradicts itself, contradicts a standard it relies on, or leaves out a
requirement it needs. See [`README.md`](README.md) for definitions and the
entry template.

### Spec Bug 1: Restricted HMAC keys and the sign/verify sequence commands

- **Spec:** The sequence commands sign raw messages, but a restricted HMAC key
  (`TPM_ALG_KEYEDHASH`) signs only digests (`TPM2_Sign`, Part 3 §20.5), so it
  cannot be used with them. No clause requires this check: Part 3 §17.5
  (`TPM2_SignSequenceStart`) mentions it only in a Note, and §17.6
  (`TPM2_VerifySequenceStart`) not at all. Separately, Errata v1 §3.2 notes that
  the deprecated `TPM2_Sign` is still needed to sign with a restricted HMAC key,
  but not that the deprecated `TPM2_VerifySignature` (§20.2) is still needed to
  verify its signatures (`TPM2_VerifyDigestSignature` does not support HMAC).
- **Fix:** Add a normative `TPM_RC_KEY` check for restricted HMAC keys to §17.5
  and §17.6, and extend Errata v1 §3.2 to cover `TPM2_VerifySignature`.
- **Reference implementation:** Already implements the fix (`TPM_RC_KEY + H1`
  in `SignSequenceStart.c` and `VerifySequenceStart.c`).
- **tpm-rs:** Follows the fix.

### Spec Bug 2: Schemes and commands for Curve25519 and Curve448 keys

- **Spec:** On Curve25519 and Curve448, a key's scheme selects its Edwards
  (EdDSA) or Montgomery (X25519, X448) form (Part 1 §44.5.4). For a key that is
  not a Storage Key, Part 2 §12.2.3.5 rules out only `TPM_ALG_NULL`, so the key
  may use a scheme that is defined only for Weierstrass curves (ECDSA, ECDAA,
  EC Schnorr, SM2, ECMQV). Commands defined only for Weierstrass curves are not
  excluded either: `TPM2_EC_Ephemeral` (Part 3 §19.3) takes only a curve ID,
  `TPM2_ZGen_2Phase` (§14.7) explicitly allows ECDH keys, and
  `TPM2_ECC_Encrypt` and `TPM2_ECC_Decrypt` (§14.8, §14.9), whose SM2
  encryption needs a *y* coordinate, accept any ECC key.
- **Fix:** Add a Part 1 subclause listing the allowed keys: signing keys use
  `TPM_ALG_EDDSA` or `TPM_ALG_HASH_EDDSA`, unrestricted decryption keys use
  `TPM_ALG_ECDH`, and Storage Keys use `TPM_ALG_NULL`. Reject any other scheme
  (`TPM_RC_SCHEME`) and keys with both *sign* and *decrypt* SET
  (`TPM_RC_ATTRIBUTES`), and state that split operations, two-phase key
  exchange and SM2 encryption are not supported. Refer to this subclause from
  Part 2 §12.2.3.5. In Part 3, have `TPM2_EC_Ephemeral` return `TPM_RC_VALUE`,
  and `TPM2_ZGen_2Phase`, `TPM2_ECC_Encrypt` and `TPM2_ECC_Decrypt` return
  `TPM_RC_KEY`, for these curves.
- **Reference implementation:** Does not support Curve25519 or Curve448.
- **tpm-rs:** Follows the fix.

### Spec Bug 3: Key generation for Curve25519 and Curve448

- **Spec:** Part 1 §44.6 generates every ECC key with FIPS 186-5 A.2.1
  (`d = (c mod (n - 1)) + 1`, `Q = [d]G`). That does not produce an RFC 8032
  EdDSA private key, and does not match RFC 7748, which clamps the X25519 and
  X448 scalar instead of reducing it. A primary key on Curve25519 or Curve448
  therefore has no defined derivation.
- **Fix:** Change Part 1 §44.6 so that, on Curve25519 and Curve448, the private
  key is the first 32 (Ed25519, X25519), 57 (Ed448) or 56 (X448) bytes from the
  random number generator, without reduction, and the public key is computed as
  RFC 8032 or RFC 7748 specifies. X25519 and X448 private keys are stored
  unclamped.
- **Reference implementation:** Does not support Curve25519 or Curve448.
- **tpm-rs:** Follows the fix.

### Spec Bug 4: Private key format for Curve25519 and Curve448

- **Spec:** Part 1 §44.5.2 says that Edwards and Montgomery private keys are
  "little-endian as specified in RFC 7748". That is correct for X25519 and X448
  scalars, but an EdDSA private key is an RFC 8032 secret key, which is a byte
  string with no byte order.
- **Fix:** Change Part 1 §44.5.2 to say that X25519 and X448 private keys are
  32- or 56-byte little-endian RFC 7748 scalars, and EdDSA private keys are 32-
  or 57-byte RFC 8032 secret keys.
- **Reference implementation:** Does not support Curve25519 or Curve448.
- **tpm-rs:** Follows the fix.

### Spec Bug 5: X25519 and X448 shared secret

- **Spec:** Part 1 §44.8.3 (`TPM2_ECDH_ZGen`) and §44.7 (ECC Labeled KEM)
  compute a shared secret as `h[d]Q`, multiplying by the curve's cofactor *h*.
  Part 2 §6.3 defines `TPM_ALG_ECDH` on Curve25519 and Curve448 as the X25519
  and X448 functions of RFC 7748, which already account for the cofactor, so the
  extra factor of 8 (Curve25519) or 4 (Curve448) gives a different result. The
  specification also does not say what happens when the result is all zeros,
  which happens when the peer's point has low order.
- **Fix:** For X25519 and X448 keys, compute the shared secret with the RFC 7748
  function and no extra cofactor. Treat an all-zero result as a point that is
  not on the curve, with the same response code.
- **Reference implementation:** Does not support Curve25519 or Curve448.
- **tpm-rs:** Follows the fix.

### Spec Bug 6: ECC key encapsulation has no defined KEM identifier

- **Spec:** Part 1 §44.4 and Part 2 §12.2.3.5 (*kdf*) define
  `TPM2_Encapsulate` and `TPM2_Decapsulate` for ECC keys as RFC 9180
  DHKEM(*curveID*, *kdf*). DHKEM labels its key derivation with a 2-byte KEM
  identifier, which RFC 9180 assigns to only five curve and KDF pairs: P-256
  with HKDF-SHA256, P-384 with HKDF-SHA384, P-521 with HKDF-SHA512, X25519 with
  HKDF-SHA256, and X448 with HKDF-SHA512. The specification never names the
  identifier and allows any HKDF hash, so other pairs have no defined result.
- **Fix:** Require (*curveID*, *kdf*) to be one of the RFC 9180 pairs
  (`TPM_RC_KDF`), and state that the KEM identifier is the one RFC 9180 assigns
  to that pair.
- **Reference implementation:** Does not support ECC key encapsulation, and
  rejects an ECC key with a *kdf* other than `TPM_ALG_NULL` (`TPM_RC_KDF`).
- **tpm-rs:** Follows the fix. ECC key encapsulation is not implemented yet;
  until it is, tpm-rs rejects a *kdf* other than `TPM_ALG_NULL` (`TPM_RC_KDF`).

### Spec Bug 7: When an orderly counter is written to NV

- **Spec:** After a disorderly shutdown, an orderly NV counter
  (`TPMA_NV_ORDERLY`) recovers as `nvCount | MAX_ORDERLY_COUNT`, where
  `MAX_ORDERLY_COUNT` is `2^n - 1`. Part 1 §34.2.6.3 writes the counter to NV
  when `(ramCount & MAX_ORDERLY_COUNT) == 0`. Part 3 §31.2 and §31.8 instead
  write when `ramCount - nvCount` reaches a threshold, and disagree on whether
  that is `>=` or `>`. A difference threshold can move the counter backward:
  with `MAX_ORDERLY_COUNT = 0xFF`, `nvCount = 0xFA` and `ramCount = 0x1F8`,
  nothing is written, and recovery yields `0xFF`, less than the `0x1F8` already
  reached.
- **Fix:** Use the Part 1 rule in Part 3 §31.2 and §31.8.
- **Reference implementation:** Already implements the fix (`NV_Increment.c`).
- **tpm-rs:** Follows the fix.
