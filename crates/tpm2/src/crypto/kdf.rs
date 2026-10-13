//! Implementation of KDFa and KDFe
//!
//! This module implements the key derivation functions (KDF) used within TPM
//! 2.0: NIST SP 800-108 KDFa ([`kdfa`]) and NIST SP 800-56A KDFe ([`kdfe`]).
//! They are generic over the [`Hmac`] and [`Hash`] interfaces, so they work
//! with any cryptographic backend.
//!
//! [`kdfa`] and [`kdfe`] always fill their whole output buffer and take a
//! [`CStr`] label. [`kdfa_bits`] and [`kdfe_bits`] are extensions of this crate
//! that follow the TPM reference implementation more closely: they take a raw
//! byte label (appending the `0x00` separator only if it is missing) and an
//! explicit output length in `bits`, which may not be a multiple of 8.
//!
//! TODO: as_chunks_mut / chunks_exact_mut might help with code size.
use core::ffi::CStr;

use super::{CryptoError, Hash, HashStream, Hmac, HmacStream};
use crate::TpmiAlgHash;

/// SP800-108 KDF in Counter Mode (KDFa) as specified in TPM 2.0 Part 1.
///
/// The `h`, `alg`, and `key` parameters are used to create the [`HmacStream`],
/// which fills `out` with derived key material. The `label` is a [`CStr`],
/// ensuring a separation indicator (`0x00`) is always present. The
/// "Context" used is the concatenation of `context_u` and `context_v`.
///
/// We _do not_ have an explicit `bits` parameter, `out` will always be
/// completely filled, giving an effective `bits` of `8 * out.len()`.
/// See [`kdfa_bits`] for a variant with an explicit `bits` parameter and a
/// raw byte label.
///
/// ## Example Bound Session Key Generation
///
/// ```
/// # use tpm2::{TpmiAlgHash, crypto::{kdfa, Hmac, CryptoError}};
/// # fn gen_session_key(crypto: impl Hmac) -> Result<(), CryptoError> {
/// const ALG: TpmiAlgHash = TpmiAlgHash::Sha256;
/// let auth = b"secret auth value";
/// let nonce_tpm = [0x11; 8];
/// let nonce_caller = [0x22; 8];
///
/// let mut key = [0x00; ALG.digest_size()];
/// kdfa(&crypto, ALG, auth, c"ATH", &nonce_tpm, &nonce_caller, &mut key)?;
/// # Ok(())
/// # }
/// ```
pub fn kdfa(
    h: &impl Hmac,
    alg: TpmiAlgHash,
    key: &[u8],
    label: &CStr,
    context_u: &[u8],
    context_v: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let bits = (out.len() as u32) * 8;
    let mut mac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

    for (i, chunk) in out.chunks_mut(alg.digest_size()).enumerate() {
        let counter = (i as u32) + 1;
        let mut state = HmacStream::new(h, alg, key)?;

        state.update(&counter.to_be_bytes())?;
        state.update(label.to_bytes_with_nul())?;
        state.update(context_u)?;
        state.update(context_v)?;
        state.update(&bits.to_be_bytes())?;

        let mac = state.finalize(&mut mac_buf)?;
        chunk.copy_from_slice(&mac.digest()[..chunk.len()]);
    }

    Ok(())
}

/// NIST SP 800-56A/C One-Step Key Derivation Function (KDFe) as specified in TPM 2.0 Part 1.
///
/// This is only used with ECDH, [`kdfa`] is used everywhere else.
///
/// The `h` and `alg` parameters are used to create the [`HashStream`],
/// which fills `out` with derived key material. The shared secret `z` is the
/// x-coordinate of the product of a public point and a private key. The
/// "OtherInfo" is the concatenation of `label` (always null-terminated as it's
/// a [`CStr`]), `party_u_info`, and `party_v_info`.
///
/// We _do not_ have an explicit `bits` parameter, `out` will always be
/// completely filled, giving an effective `bits` of `8 * out.len()`.
/// See [`kdfe_bits`] for a variant with an explicit `bits` parameter and a
/// raw byte label.
pub fn kdfe(
    h: &impl Hash,
    alg: TpmiAlgHash,
    z: &[u8],
    label: &CStr,
    party_u_info: &[u8],
    party_v_info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

    for (i, chunk) in out.chunks_mut(alg.digest_size()).enumerate() {
        let counter = (i as u32) + 1;
        let mut state = HashStream::new(h, alg)?;

        state.update(&counter.to_be_bytes())?;
        state.update(z)?;
        state.update(label.to_bytes_with_nul())?;
        state.update(party_u_info)?;
        state.update(party_v_info)?;

        let digest = state.finalize(&mut digest_buf)?;
        chunk.copy_from_slice(&digest.digest()[..chunk.len()]);
    }

    Ok(())
}

/// Returns the number of bytes (`ceil(bits / 8)`) produced by [`kdfa_bits`] and
/// [`kdfe_bits`], or [`CryptoError::Internal`] if `out` is too small for them.
fn required_bytes(bits: u32, out: &[u8]) -> Result<usize, CryptoError> {
    let required = bits.div_ceil(8) as usize;
    if out.len() < required {
        return Err(CryptoError::Internal);
    }
    Ok(required)
}

/// Clears the unused high-order bits of `out[0]` (the most significant octet)
/// when `bits` is not a multiple of 8, without shifting.
fn mask_high_order_bits(bits: u32, out: &mut [u8]) {
    if !bits.is_multiple_of(8)
        && let Some(first) = out.first_mut()
    {
        *first &= (1u8 << (bits % 8)) - 1;
    }
}

/// SP800-108 KDF in Counter Mode (KDFa) as specified in TPM 2.0 Part 1, Section 11.4.9.2,
/// with a raw byte `label` and an explicit output length in `bits`.
///
/// This is an extension of this crate, following the TPM reference
/// implementation (`CryptKDFa`) more closely than [`kdfa`]:
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
/// The `h`, `alg`, and `key` parameters are used to create the [`HmacStream`].
/// The "Context" used is the concatenation of `context_u` and `context_v`.
///
/// # Errors
/// * [`CryptoError::Internal`] - `out` is smaller than `ceil(bits / 8)` bytes
///   (checked before any HMAC computation).
/// * [`CryptoError::Unsupported`] - `h` does not support HMAC with `alg`.
/// * Any error returned by the underlying HMAC computation.
///
/// ## Example
///
/// ```
/// # use tpm2::{TpmiAlgHash, crypto::{kdfa_bits, Hmac, CryptoError}};
/// # fn derive(crypto: impl Hmac, seed: &[u8], name: &[u8]) -> Result<(), CryptoError> {
/// // Derive a 128-bit symmetric key (as `TPM2_Duplicate` does for `STORAGE`).
/// let mut sym_key = [0u8; 32];
/// let len = kdfa_bits(
///     &crypto,
///     TpmiAlgHash::Sha256,
///     seed,
///     b"STORAGE",
///     name,
///     &[],
///     128,
///     &mut sym_key,
/// )?;
/// assert_eq!(len, 16);
/// # Ok(())
/// # }
/// ```
#[allow(clippy::too_many_arguments)]
pub fn kdfa_bits(
    h: &impl Hmac,
    alg: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let required = required_bytes(bits, out)?;
    let mut mac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

    for (i, chunk) in out[..required].chunks_mut(alg.digest_size()).enumerate() {
        let counter = (i as u32) + 1;
        let mut state = HmacStream::new(h, alg, key)?;

        state.update(&counter.to_be_bytes())?;
        state.update(label)?;
        if label.last() != Some(&0) {
            state.update(&[0x00])?;
        }
        state.update(context_u)?;
        state.update(context_v)?;
        state.update(&bits.to_be_bytes())?;

        let mac = state.finalize(&mut mac_buf)?;
        chunk.copy_from_slice(&mac.digest()[..chunk.len()]);
    }

    mask_high_order_bits(bits, &mut out[..required]);
    Ok(required)
}

/// NIST SP 800-56A One-Step Key Derivation Function (KDFe) as specified in TPM 2.0 Part 1,
/// Section 11.4.9.3, with a raw byte `label` and an explicit output length in `bits`.
///
/// This is an extension of this crate, following the TPM reference
/// implementation (`CryptKDFe`) more closely than [`kdfe`]:
///   - `label` is a raw byte string, which may contain interior `0x00` octets.
///     A zero octet (`0x00`) separator is appended after `label` if and only if
///     `label` is empty or its last byte is not `0x00`. For labels without
///     interior or trailing `0x00` octets, this matches [`kdfe`] with the same
///     label as a [`CStr`].
///   - The output length is `bits`, not `8 * out.len()`. Only the first
///     `ceil(bits / 8)` bytes of `out` are written (the rest is left untouched),
///     and that number of bytes is returned. If `bits` is not a multiple of 8,
///     the unused high-order bits of `out[0]` (the most significant octet) are
///     cleared to zero without shifting.
///
/// The `h` and `alg` parameters are used to create the [`HashStream`]. The
/// shared secret `z` is the x-coordinate of the product of a public point and a
/// private key. The "OtherInfo" is the concatenation of `label` (with its
/// separator), `party_u_info`, and `party_v_info`.
///
/// # Errors
/// * [`CryptoError::Internal`] - `out` is smaller than `ceil(bits / 8)` bytes
///   (checked before any hash computation).
/// * [`CryptoError::Unsupported`] - `h` does not support `alg`.
/// * Any error returned by the underlying hash computation.
#[allow(clippy::too_many_arguments)]
pub fn kdfe_bits(
    h: &impl Hash,
    alg: TpmiAlgHash,
    z: &[u8],
    label: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    bits: u32,
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let required = required_bytes(bits, out)?;
    let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

    for (i, chunk) in out[..required].chunks_mut(alg.digest_size()).enumerate() {
        let counter = (i as u32) + 1;
        let mut state = HashStream::new(h, alg)?;

        state.update(&counter.to_be_bytes())?;
        state.update(z)?;
        state.update(label)?;
        if label.last() != Some(&0) {
            state.update(&[0x00])?;
        }
        state.update(party_u_info)?;
        state.update(party_v_info)?;

        let digest = state.finalize(&mut digest_buf)?;
        chunk.copy_from_slice(&digest.digest()[..chunk.len()]);
    }

    mask_high_order_bits(bits, &mut out[..required]);
    Ok(required)
}
