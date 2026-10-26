//! HMAC calculation.

use core::ffi::CStr;

use super::{
    CryptoError,
    backend::{Hmac, HmacState},
    match_hash_alg,
};
use crate::{TpmiAlgHash, TpmtHa};

/// Streaming HMAC context for a runtime-selected hash algorithm.
///
/// Use [`hmac`] instead if all the data is available at once.
///
/// While an [`Hmac`] implementation can implement whichever algorithms it
/// wants, the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum HmacContext<H: Hmac> {
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

impl<H: Hmac> HmacContext<H> {
    /// Initializes a new [`HmacContext`] for `alg` with `key`.
    pub fn new(alg: TpmiAlgHash, key: &[u8]) -> Result<Self, CryptoError> {
        match_hash_alg!(match alg {
            TpmiAlgHash::$Alg => { Ok(Self::$Alg(HmacState::init(key)?)) },
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

    /// Writes the MAC into the start of `out` and returns the tagged
    /// [`TpmtHa`].
    ///
    /// Consumes the context. `out` can be longer than the MAC (e.g.
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

/// Writes the MAC of the concatenation of `data` into the start of a
/// caller-provided buffer.
///
/// This is for one-shot HMAC calculation, e.g. `hmac::<H>(alg, key, &[a, b],
/// out)` computes `HMAC(key, a || b)`. [`HmacContext`] allows for streaming
/// HMAC calculation. `out` can be longer than the MAC (e.g.
/// [`TpmiAlgHash::MAX_DIGEST_BYTES`]). Returns [`CryptoError::Internal`] if
/// `out.len() < alg.digest_size()`.
pub fn hmac<'a, H: Hmac>(
    alg: TpmiAlgHash,
    key: &[u8],
    data: &[&[u8]],
    out: &'a mut [u8],
) -> Result<TpmtHa<'a>, CryptoError> {
    match_hash_alg!(match alg {
        TpmiAlgHash::$Alg => {
            let out = out.first_chunk_mut().ok_or(CryptoError::Internal)?;
            H::$Alg::hmac(key, data, out)?;
            Ok(TpmtHa::$Alg(out))
        },
    })
}

/// NIST SP 800-108 KDF in Counter Mode (`KDFa`), as specified in TPM 2.0 Part 1.
///
/// The `alg` and `key` parameters are used to initialize the HMAC state for
/// each block, filling `out` with derived key material. The `label` is a
/// [`CStr`], ensuring a separation indicator (`0x00`) is always present. The
/// "Context" used is the concatenation of `context.0` (`contextU`) and
/// `context.1` (`contextV`).
///
/// There is no explicit `bits` parameter: `out` is always completely filled,
/// giving an effective `bits` of `8 * out.len()`.
///
/// ## Example Bound Session Key Generation
///
/// ```
/// # use tpm2::{TpmiAlgHash, crypto::{kdfa, Crypto, CryptoError}};
/// # fn gen_session_key<C: Crypto>() -> Result<(), CryptoError> {
/// const ALG: TpmiAlgHash = TpmiAlgHash::Sha256;
/// let auth = b"secret auth value";
/// let nonce_tpm = [0x11; 8];
/// let nonce_caller = [0x22; 8];
///
/// let mut key = [0x00; ALG.digest_size()];
/// kdfa::<C>(ALG, auth, c"ATH", (&nonce_tpm, &nonce_caller), &mut key)?;
/// # Ok(())
/// # }
/// ```
pub fn kdfa<H: Hmac>(
    alg: TpmiAlgHash,
    key: &[u8],
    label: &CStr,
    context: (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), CryptoError> {
    match_hash_alg!(match alg {
        TpmiAlgHash::$Alg => { H::$Alg::kdfa(key, label, context, out) },
    })
}
