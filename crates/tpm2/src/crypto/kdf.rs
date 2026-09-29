//! TPM 2.0 Key Derivation Function (KDF) Abstractions
//!
//! This module defines the cryptographic traits for key derivation functions (KDF) used within
//! TPM 2.0, specifically NIST SP 800-56A KDFe and NIST SP 800-108 KDFa.
//!
//! ### Provider Abstraction
//!
//! Similar to other cryptographic components in `tpm-rs`, these operations are defined as traits
//! rather than concrete structs. This allows the core library to remain independent of the
//! underlying cryptographic backend (e.g., RustCrypto, BoringSSL).
//!
//! Users can implement these traits for their specific hardware or software stack and provide
//! the implementation via the [`CryptoProvider`](super::CryptoProvider) trait.
//!
//! ### Error Handling
//!
//! All operations return [`CryptoError`] to indicate failure. This includes errors returned
//! by the hardware itself (wrapped as [`CryptoError::HardwareFailure`]) and client-side
//! validation errors (e.g., [`CryptoError::BufferTooSmall`]).

use super::CryptoError;

/// NIST SP 800-56A Key Derivation Function (KDFe) as specified in TPM 2.0 Part 1, Section 11.4.9.3.
///
/// A zero octet (`0x00`) separator is appended after `use_label` if and only if `use_label` is
/// empty or its last byte is not `0x00`. If `bits` is not an even multiple of 8, the unused
/// high-order bits of `out_buffer[0]` (the most significant octet) are cleared to zero without shifting.
///
/// # Errors
/// * `CryptoError::BufferTooSmall` - Returned if the provided `out_buffer` is smaller than the requested `bits`.
#[allow(clippy::too_many_arguments)]
pub fn kdfe<H: crate::crypto::Hash<Error = CryptoError>>(
    hash_provider: &H,
    alg: crate::TpmiAlgHash,
    z: &[u8],
    use_label: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    bits: u32,
    out_buffer: &mut [u8],
) -> Result<usize, CryptoError> {
    let required_bytes = bits.div_ceil(8) as usize;
    if out_buffer.len() < required_bytes {
        return Err(CryptoError::BufferTooSmall);
    }

    let mut counter: u32 = 1;
    let mut generated: usize = 0;

    while generated < required_bytes {
        let mut state = crate::crypto::HashCtx::new(hash_provider, alg)?;

        state.update(&counter.to_be_bytes())?;
        state.update(z)?;
        state.update(use_label)?;
        if use_label.last() != Some(&0) {
            state.update(&[0x00])?;
        }
        state.update(party_u_info)?;
        state.update(party_v_info)?;

        let mut digest_buf = [0u8; crate::TpmtHa::MAX_DIGEST_SIZE];
        let digest = state.finalize(&mut digest_buf)?;
        let digest_slice = digest.digest();

        let to_copy = core::cmp::min(digest_slice.len(), required_bytes - generated);
        out_buffer[generated..generated + to_copy].copy_from_slice(&digest_slice[..to_copy]);

        generated += to_copy;
        counter += 1;
    }

    if !bits.is_multiple_of(8) && required_bytes > 0 {
        out_buffer[0] &= (1u8 << (bits % 8)) - 1;
    }

    Ok(required_bytes)
}

/// SP800-108 Key Derivation Function in Counter Mode (KDFa) as specified in TPM 2.0 Part 1, Section 11.4.9.2.
///
/// A zero octet (`0x00`) separator is appended after `label` if and only if `label` is empty or
/// its last byte is not `0x00`. If `bits` is not an even multiple of 8, the unused high-order bits
/// of `out_buffer[0]` (the most significant octet) are cleared to zero without shifting.
///
/// # Errors
/// * `CryptoError::BufferTooSmall` - Returned if the provided `out_buffer` is smaller than the requested `bits`.
/// * `CryptoError::HardwareFailure` - Returned dynamically if any of the underlying continuous HMAC block operations sequence stall inside the native hardware API during execution.
#[allow(clippy::too_many_arguments)]
pub fn kdfa<H: crate::crypto::Hmac<Error = CryptoError>>(
    hmac_provider: &H,
    alg: crate::TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
    out_buffer: &mut [u8],
) -> Result<usize, CryptoError> {
    let required_bytes = bits.div_ceil(8) as usize;
    if out_buffer.len() < required_bytes {
        return Err(CryptoError::BufferTooSmall);
    }

    let mut counter: u32 = 1;
    let mut generated: usize = 0;

    while generated < required_bytes {
        let mut state = crate::crypto::HmacCtx::new(hmac_provider, alg, key)?;

        state.update(&counter.to_be_bytes())?;
        state.update(label)?;
        if label.last() != Some(&0) {
            state.update(&[0x00])?;
        }
        state.update(context_u)?;
        state.update(context_v)?;
        state.update(&bits.to_be_bytes())?;

        let mut mac_buf = [0u8; crate::TpmtHa::MAX_DIGEST_SIZE];
        let mac = state.finalize(&mut mac_buf)?;
        let mac_slice = mac.digest();

        let to_copy = core::cmp::min(mac_slice.len(), required_bytes - generated);
        out_buffer[generated..generated + to_copy].copy_from_slice(&mac_slice[..to_copy]);

        generated += to_copy;
        counter += 1;
    }

    if !bits.is_multiple_of(8) && required_bytes > 0 {
        out_buffer[0] &= (1u8 << (bits % 8)) - 1;
    }

    Ok(required_bytes)
}
