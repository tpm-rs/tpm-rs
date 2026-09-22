//! Implementation of KDFa and KDFe
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
