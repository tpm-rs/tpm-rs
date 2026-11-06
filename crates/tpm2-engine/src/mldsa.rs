//! ML-DSA (FIPS 204) message representatives.
//!
//! The crypto backend signs and verifies the message representative `mu`
//! ([`tpm2::crypto::MldsaPrivateKey::sign_mu_internal`], [`tpm2::crypto::MldsaPublicKey::verify`]);
//! the engine
//! computes `mu` itself with [`Shake256`]:
//!
//! ```text
//! tr := SHAKE256(pk, 64)                                    (Algorithm 6 line 6)
//! mu := SHAKE256(tr || M', 64)                              (Algorithm 7 line 6)
//! M' := 0 || len(ctx) || ctx || M                           (ML-DSA, Algorithm 2 line 10)
//! M' := 1 || len(ctx) || ctx || OID(PH) || PH(M)            (HashML-DSA, Algorithm 4 line 23)
//! ```
//!
//! For an external-mu key (`allowExternalMu`), the caller provides `mu` directly.

use tpm2::TpmiAlgHash;

use crate::shake256::Shake256;

/// The size of the message representative `mu` (`MLDSA_MU_SIZE`).
pub(crate) const MU_SIZE: usize = tpm2::TpmiMldsaParms::MU_BYTES;

/// The size of the public-key hash `tr`.
pub(crate) const TR_SIZE: usize = 64;

/// A SHAKE256 computation of `mu` for the verification key `public_key`, with `tr` absorbed
/// (the caller absorbs `M'` and squeezes [`MU_SIZE`] bytes).
pub(crate) fn mu_start(public_key: &[u8]) -> Shake256 {
    let mut tr = [0u8; TR_SIZE];
    Shake256::digest(public_key, &mut tr);
    let mut shake = Shake256::new();
    shake.update(&tr);
    shake
}

/// A SHAKE256 computation of the pure ML-DSA `mu` for the verification key `public_key` and the
/// context string `context`, with `tr || 0 || len(ctx) || ctx` absorbed (the caller absorbs the
/// message `M` and squeezes [`MU_SIZE`] bytes), or `None` if `context` is longer than
/// 255 octets (`MLDSA_CTX_MAX_SIZE`).
pub(crate) fn pure_mu_start(public_key: &[u8], context: &[u8]) -> Option<Shake256> {
    let context_len = u8::try_from(context.len()).ok()?;
    let mut shake = mu_start(public_key);
    shake.update(&[0, context_len]);
    shake.update(context);
    Some(shake)
}

/// The DER encoding of the object identifier of the pre-hash function `hash_alg` of HashML-DSA
/// (FIPS 204, Section 5.4.1), or `None` for a hash function without an approved identifier.
pub(crate) fn pre_hash_oid(hash_alg: TpmiAlgHash) -> Option<&'static [u8]> {
    // 2.16.840.1.101.3.4.2.<n> (NIST hash algorithms).
    const fn nist_hash(n: u8) -> [u8; 11] {
        [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, n,
        ]
    }
    const SHA256: [u8; 11] = nist_hash(0x01);
    const SHA384: [u8; 11] = nist_hash(0x02);
    const SHA512: [u8; 11] = nist_hash(0x03);
    const SHA3_256: [u8; 11] = nist_hash(0x08);
    const SHA3_384: [u8; 11] = nist_hash(0x09);
    const SHA3_512: [u8; 11] = nist_hash(0x0a);
    match tpm2::Alg::from(hash_alg) {
        tpm2::Alg::SHA256 => Some(&SHA256),
        tpm2::Alg::SHA384 => Some(&SHA384),
        tpm2::Alg::SHA512 => Some(&SHA512),
        tpm2::Alg::SHA3_256 => Some(&SHA3_256),
        tpm2::Alg::SHA3_384 => Some(&SHA3_384),
        tpm2::Alg::SHA3_512 => Some(&SHA3_512),
        _ => None,
    }
}

/// The HashML-DSA `mu` of the pre-hashed message `digest` (computed with `hash_alg`) for
/// `public_key` and `context`, or `None` if `context` is longer than 255 octets or
/// `hash_alg` has no pre-hash identifier ([`pre_hash_oid`]).
pub(crate) fn hash_mu(
    public_key: &[u8],
    context: &[u8],
    hash_alg: TpmiAlgHash,
    digest: &[u8],
) -> Option<[u8; MU_SIZE]> {
    let context_len = u8::try_from(context.len()).ok()?;
    let oid = pre_hash_oid(hash_alg)?;
    let mut shake = mu_start(public_key);
    shake.update(&[1, context_len]);
    shake.update(context);
    shake.update(oid);
    shake.update(digest);
    let mut mu = [0u8; MU_SIZE];
    shake.finalize_into(&mut mu);
    Some(mu)
}
