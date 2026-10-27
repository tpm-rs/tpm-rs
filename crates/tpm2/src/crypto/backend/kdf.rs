//! Default KDF implementations (`KDFa` and `KDFe`).

use core::ffi::CStr;

use super::{HashState, HmacState};
use crate::crypto::CryptoError;

/// Converts an output length in bytes to the number of bits used by the KDFs.
///
/// Returns `None` if the number of bits doesn't fit in a `u32` (the size of
/// `[L]_2` in `KDFa`). This also guarantees the 32-bit block counter can't
/// overflow in `KDFa` or `KDFe`.
///
/// This is more permissive than the reference implementation, where
/// `CryptKDFa()` and `CryptKDFe()` limit their output to at most `INT16_MAX`
/// bytes, and treat larger requests as fatal errors.
fn bytes_to_bits(n: usize) -> Option<u32> {
    u32::try_from(n).ok()?.checked_mul(8)
}

/// The default implementation of [`HmacState::kdfa`].
#[inline(never)]
pub fn default_kdfa<S: HmacState<N>, const N: usize>(
    key: &[u8],
    label: &CStr,
    context: (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut counter = 0u32;
    let bits = bytes_to_bits(out.len()).ok_or(CryptoError::Internal)?;
    let (chunks, tail) = out.as_chunks_mut();
    for chunk in chunks {
        counter += 1;
        kdfa_block::<S, N>(counter, bits, key, label, context, chunk)?;
    }
    if !tail.is_empty() {
        counter += 1;
        let mut tmp = [0u8; N];
        kdfa_block::<S, N>(counter, bits, key, label, context, &mut tmp)?;
        tail.copy_from_slice(&tmp[..tail.len()]);
    }
    Ok(())
}

/// The default implementation of [`HmacState::kdfa_xor`].
#[inline(never)]
pub fn default_kdfa_xor<S: HmacState<N>, const N: usize>(
    key: &[u8],
    label: &CStr,
    context: (&[u8], &[u8]),
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let bits = bytes_to_bits(data.len()).ok_or(CryptoError::Internal)?;
    let mut mask = [0u8; N];
    // `bytes_to_bits` ensures the counter can't overflow.
    for (chunk, counter) in data.chunks_mut(N).zip(1u32..) {
        kdfa_block::<S, N>(counter, bits, key, label, context, &mut mask)?;
        for (d, m) in chunk.iter_mut().zip(&mask) {
            *d ^= m;
        }
    }
    Ok(())
}

/// Computes a single `KDFa` block.
#[inline(never)]
fn kdfa_block<S: HmacState<N>, const N: usize>(
    counter: u32,
    bits: u32,
    key: &[u8],
    label: &CStr,
    context: (&[u8], &[u8]),
    block: &mut [u8; N],
) -> Result<(), CryptoError> {
    // Use the state inside the `Result`: moving it out would copy it.
    match &mut S::init(key) {
        Ok(h) => {
            h.update(&counter.to_be_bytes())?;
            h.update(label.to_bytes_with_nul())?;
            h.update(context.0)?;
            h.update(context.1)?;
            h.update(&bits.to_be_bytes())?;
            h.finalize(block)
        }
        Err(e) => Err(*e),
    }
}

/// The default implementation of [`HashState::kdfe`].
#[inline(never)]
pub fn default_kdfe<S: HashState<N>, const N: usize>(
    z: &[u8],
    label: &CStr,
    party_info: (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), CryptoError> {
    // KDFe doesn't hash the output size, but has the same length limit.
    bytes_to_bits(out.len()).ok_or(CryptoError::Internal)?;
    let mut counter = 0u32;
    let (chunks, tail) = out.as_chunks_mut();
    for chunk in chunks {
        counter += 1;
        kdfe_block::<S, N>(counter, z, label, party_info, chunk)?;
    }
    if !tail.is_empty() {
        counter += 1;
        let mut tmp = [0u8; N];
        kdfe_block::<S, N>(counter, z, label, party_info, &mut tmp)?;
        tail.copy_from_slice(&tmp[..tail.len()]);
    }
    Ok(())
}

/// Computes a single `KDFe` block.
#[inline(never)]
fn kdfe_block<S: HashState<N>, const N: usize>(
    counter: u32,
    z: &[u8],
    label: &CStr,
    party_info: (&[u8], &[u8]),
    block: &mut [u8; N],
) -> Result<(), CryptoError> {
    // Use the state inside the `Result`: moving it out would copy it.
    match &mut S::init() {
        Ok(h) => {
            h.update(&counter.to_be_bytes())?;
            h.update(z)?;
            h.update(label.to_bytes_with_nul())?;
            h.update(party_info.0)?;
            h.update(party_info.1)?;
            h.finalize(block)
        }
        Err(e) => Err(*e),
    }
}
