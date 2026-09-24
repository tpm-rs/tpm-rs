//! Implementation of KDFa and KDFe
//!
//! TODO: as_chunks_mut / chunks_exact_mut might help with code size.
use super::{CryptoError, Hash, HashStream, Hmac, HmacStream};
use crate::TpmiAlgHash;

/// SP800-108 Key Derivation Function in Counter Mode (KDFa) as specified in TPM 2.0 Part 1, Section 11.4.9.2.
///
/// Fills `out` with derived key material (`bits = out.len() * 8`). A zero octet (`0x00`) separator
/// is appended after `label` if and only if `label` is empty or its last byte is not `0x00`.
pub fn kdfa(
    h: &impl Hmac,
    alg: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
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

    Ok(())
}

/// NIST SP 800-56A / SP 800-56C One-Step Key Derivation Function (KDFe) as specified in TPM 2.0 Part 1, Section 11.4.9.3.
///
/// Fills `out` with derived key material (`bits = out.len() * 8`). A zero octet (`0x00`) separator
/// is appended after `use_label` if and only if `use_label` is empty or its last byte is not `0x00`.
pub fn kdfe(
    h: &impl Hash,
    alg: TpmiAlgHash,
    z: &[u8],
    use_label: &[u8],
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
        state.update(use_label)?;
        if use_label.last() != Some(&0) {
            state.update(&[0x00])?;
        }
        state.update(party_u_info)?;
        state.update(party_v_info)?;

        let digest = state.finalize(&mut digest_buf)?;
        chunk.copy_from_slice(&digest.digest()[..chunk.len()]);
    }

    Ok(())
}
