//! Cryptographic hashing.

use core::ffi::CStr;

use super::{
    CryptoError,
    backend::{Hash, HashState},
    match_hash_alg,
};
use crate::{TpmiAlgHash, TpmtHa};

/// Streaming hash context for a runtime-selected algorithm.
///
/// Use [`hash`] instead if all the data is available at once.
///
/// While a [`Hash`] implementation can implement whichever algorithms it
/// wants, the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum HashContext<H: Hash> {
    #[cfg(feature = "sha1")]
    Sha1(H::Sha1),
    #[cfg(feature = "sha256")]
    Sha256(H::Sha256),
    #[cfg(feature = "sha384")]
    Sha384(H::Sha384),
    #[cfg(feature = "sha512")]
    Sha512(H::Sha512),
    #[cfg(feature = "sm3_256")]
    Sm3_256(H::Sm3_256),
    #[cfg(feature = "sha3_256")]
    Sha3_256(H::Sha3_256),
    #[cfg(feature = "sha3_384")]
    Sha3_384(H::Sha3_384),
    #[cfg(feature = "sha3_512")]
    Sha3_512(H::Sha3_512),
}

impl<H: Hash> HashContext<H> {
    /// Initializes a new [`HashContext`] for `alg`.
    pub fn new(alg: TpmiAlgHash) -> Result<Self, CryptoError> {
        match_hash_alg!(match alg {
            TpmiAlgHash::$Alg => { Ok(Self::$Alg(HashState::init()?)) },
        })
    }

    /// Returns the hash algorithm of this context.
    pub const fn alg(&self) -> TpmiAlgHash {
        match_hash_alg!(match self {
            Self::$Alg(_) => { TpmiAlgHash::$Alg },
        })
    }

    /// Feeds `data` into the context.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match_hash_alg!(match self {
            Self::$Alg(ctx) => { ctx.update(data) },
        })
    }

    /// Writes the digest into the start of `out` and returns the tagged
    /// [`TpmtHa`].
    ///
    /// Consumes the context. `out` can be longer than the digest (e.g.
    /// [`TpmiAlgHash::MAX_DIGEST_BYTES`]). Returns [`CryptoError::Internal`] if
    /// `out.len() < alg.digest_size()`.
    pub fn finalize(mut self, out: &mut [u8]) -> Result<TpmtHa<'_>, CryptoError> {
        Ok(match_hash_alg!(match (&mut self) {
            Self::$Alg(ctx) => {
                TpmtHa::$Alg({
                    let out = out.first_chunk_mut().ok_or(CryptoError::Internal)?;
                    ctx.finalize(out)?;
                    out
                })
            },
        }))
    }
}

/// Writes the digest of the concatenation of `data` into the start of a
/// caller-provided buffer.
///
/// This is for one-shot hashing, e.g. `hash::<H>(alg, &[a, b, c], out)`
/// computes `H(a || b || c)`. [`HashContext`] allows for streaming hashing.
/// `out` can be longer than the digest (e.g.
/// [`TpmiAlgHash::MAX_DIGEST_BYTES`]). Returns [`CryptoError::Internal`] if
/// `out.len() < alg.digest_size()`.
pub fn hash<'a, H: Hash>(
    alg: TpmiAlgHash,
    data: &[&[u8]],
    out: &'a mut [u8],
) -> Result<TpmtHa<'a>, CryptoError> {
    match_hash_alg!(match alg {
        TpmiAlgHash::$Alg => {
            let out = out.first_chunk_mut().ok_or(CryptoError::Internal)?;
            H::$Alg::hash(data, out)?;
            Ok(TpmtHa::$Alg(out))
        },
    })
}

/// NIST SP 800-56A/C One-Step Key Derivation Function (`KDFe`), as specified in
/// TPM 2.0 Part 1.
///
/// This is only used with ECDH; [`kdfa`](super::kdfa) is used everywhere else.
///
/// The `alg` parameter is used to initialize the hash state for each block,
/// filling `out` with derived key material. The shared secret `z` is the
/// x-coordinate of the product of a public point and a private key. The
/// "OtherInfo" is the concatenation of `label` (always null-terminated as it's
/// a [`CStr`]), `party_info.0` (`partyUInfo`), and `party_info.1`
/// (`partyVInfo`).
///
/// There is no explicit `bits` parameter: `out` is always completely filled,
/// giving an effective `bits` of `8 * out.len()`.
pub fn kdfe<H: Hash>(
    alg: TpmiAlgHash,
    z: &[u8],
    label: &CStr,
    party_info: (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), CryptoError> {
    match_hash_alg!(match alg {
        TpmiAlgHash::$Alg => { H::$Alg::kdfe(z, label, party_info, out) },
    })
}
