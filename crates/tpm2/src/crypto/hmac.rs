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

/// XORs the output of [`kdfa`] into `data`, as used by XOR obfuscation in TPM
/// 2.0 Part 1.
///
/// This computes `data ^= KDFa(alg, key, label, context, 8 * data.len())`
/// without a buffer the size of `data`. For XOR obfuscation, `label` is
/// `c"XOR"`. XOR obfuscation is its own inverse, so this both obfuscates and
/// deobfuscates.
pub fn kdfa_xor<H: Hmac>(
    alg: TpmiAlgHash,
    key: &[u8],
    label: &CStr,
    context: (&[u8], &[u8]),
    data: &mut [u8],
) -> Result<(), CryptoError> {
    match_hash_alg!(match alg {
        TpmiAlgHash::$Alg => { H::$Alg::kdfa_xor(key, label, context, data) },
    })
}

/// Returns the number of bytes (`ceil(bits / 8)`) produced by [`kdfa_bits`] and
/// [`kdfe_bits`](super::kdfe_bits), or [`CryptoError::Internal`] if `out` is too
/// small for them.
pub(super) fn bits_output_len(bits: u32, out: &[u8]) -> Result<usize, CryptoError> {
    let required = usize::try_from(bits.div_ceil(8)).map_err(|_| CryptoError::Internal)?;
    if out.len() < required {
        return Err(CryptoError::Internal);
    }
    Ok(required)
}

/// Clears the unused high-order bits of `out[0]` (the most significant octet)
/// when `bits` is not a multiple of 8, without shifting.
pub(super) fn mask_high_order_bits(bits: u32, out: &mut [u8]) {
    if !bits.is_multiple_of(8)
        && let Some(first) = out.first_mut()
    {
        *first &= (1u8 << (bits % 8)) - 1;
    }
}

/// Computes `KDFa` into `out` with HMAC state `S`, a raw `label` and `bits`.
fn kdfa_bits_inner<S: HmacState<N>, const N: usize>(
    key: &[u8],
    label: &[u8],
    context: (&[u8], &[u8]),
    bits: u32,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut block = [0u8; N];
    // `bits_output_len` bounds `out.len()` by `u32::MAX / 8`, so the counter
    // can't overflow.
    for (chunk, counter) in out.chunks_mut(N).zip(1u32..) {
        // Use the state inside the `Result`: moving it out would copy it.
        match &mut S::init(key) {
            Ok(h) => {
                h.update(&counter.to_be_bytes())?;
                h.update(label)?;
                if label.last() != Some(&0) {
                    h.update(&[0x00])?;
                }
                h.update(context.0)?;
                h.update(context.1)?;
                h.update(&bits.to_be_bytes())?;
                h.finalize(&mut block)?;
            }
            Err(e) => return Err(*e),
        }
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    Ok(())
}

/// NIST SP 800-108 KDF in Counter Mode (`KDFa`), as specified in TPM 2.0 Part 1,
/// with a raw byte `label` and an explicit output length in `bits`.
///
/// This is a tpm-rs extension, following the TPM reference implementation
/// (`CryptKDFa`) more closely than [`kdfa`]:
///   - `label` is a raw byte string, which may contain interior `0x00` octets.
///     A zero octet (`0x00`) separator is appended after `label` if and only if
///     `label` is empty or its last byte is not `0x00`. For labels without
///     interior or trailing `0x00` octets, this matches [`kdfa`] with the same
///     label as a [`CStr`].
///   - The output length is `bits`, not `8 * out.len()`. Only the first
///     `ceil(bits / 8)` bytes of `out` are written (the rest is left untouched),
///     and that number of bytes is returned. If `bits` is not a multiple of 8,
///     the unused high-order bits of `out[0]` (the most significant octet) are
///     cleared to zero without shifting.
///
/// The "Context" used is the concatenation of `context.0` (`contextU`) and
/// `context.1` (`contextV`).
///
/// # Errors
/// * [`CryptoError::Internal`] - `out` is smaller than `ceil(bits / 8)` bytes
///   (checked before any HMAC computation).
/// * [`CryptoError::Unsupported`] - the backend does not support HMAC with
///   `alg`.
///
/// ## Example
///
/// ```
/// # use tpm2::{TpmiAlgHash, crypto::{kdfa_bits, Crypto, CryptoError}};
/// # fn derive<C: Crypto>(seed: &[u8], name: &[u8]) -> Result<(), CryptoError> {
/// // Derive a 128-bit symmetric key (as `TPM2_Duplicate` does for `STORAGE`).
/// let mut sym_key = [0u8; 32];
/// let len = kdfa_bits::<C>(TpmiAlgHash::Sha256, seed, b"STORAGE", (name, &[]), 128, &mut sym_key)?;
/// assert_eq!(len, 16);
/// # Ok(())
/// # }
/// ```
pub fn kdfa_bits<H: Hmac>(
    alg: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context: (&[u8], &[u8]),
    bits: u32,
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let required = bits_output_len(bits, out)?;
    let out = &mut out[..required];
    match_hash_alg!(match alg {
        TpmiAlgHash::$Alg => { kdfa_bits_inner::<H::$Alg, _>(key, label, context, bits, out)? },
    });
    mask_high_order_bits(bits, out);
    Ok(required)
}
