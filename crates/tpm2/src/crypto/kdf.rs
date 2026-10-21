//! Key derivation functions (`KDFa` and `KDFe`).

use core::{ffi::CStr, mem::MaybeUninit};

use super::{
    Active, CryptoError, Finalize, Hash, HashSlot, Hmac, HmacSlot, Init, InitFrom, Update,
};

/// SP800-108 KDF in Counter Mode (KDFa) as specified in TPM 2.0 Part 1.
///
/// The `slot` and `key` parameters are used to initialize the HMAC state for
/// each block, filling `out` with derived key material. The `label` is a
/// [`CStr`], ensuring a separation indicator (`0x00`) is always present. The
/// "Context" used is the concatenation of `context.0` (`contextU`) and
/// `context.1` (`contextV`).
///
/// We _do not_ have an explicit `bits` parameter, `out` will always be
/// completely filled, giving an effective `bits` of `8 * out.len()`.
///
/// ## Example Bound Session Key Generation
///
/// ```
/// # use tpm2::{TpmiAlgHash, crypto::{kdfa, Hmac, HmacSlot, CryptoError}};
/// # fn gen_session_key<H: Hmac>() -> Result<(), CryptoError> {
/// const ALG: TpmiAlgHash = TpmiAlgHash::Sha256;
/// let auth = b"secret auth value";
/// let nonce_tpm = [0x11; 8];
/// let nonce_caller = [0x22; 8];
///
/// let mut key = [0x00; ALG.digest_size()];
/// let mut slot = HmacSlot::<H>::new(ALG);
/// kdfa(&mut slot, auth, c"ATH", (&nonce_tpm, &nonce_caller), &mut key)?;
/// # Ok(())
/// # }
/// ```
pub fn kdfa<H: Hmac>(
    slot: &mut HmacSlot<H>,
    key: &[u8],
    label: &CStr,
    context: (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), CryptoError> {
    match slot {
        #[cfg(feature = "sha1")]
        HmacSlot::Sha1(s) => kdfa_helper(s, key, label, context, out),
        #[cfg(feature = "sha256")]
        HmacSlot::Sha256(s) => kdfa_helper(s, key, label, context, out),
        #[cfg(feature = "sha384")]
        HmacSlot::Sha384(s) => kdfa_helper(s, key, label, context, out),
        #[cfg(feature = "sha512")]
        HmacSlot::Sha512(s) => kdfa_helper(s, key, label, context, out),
        #[cfg(feature = "sm3_256")]
        HmacSlot::Sm3_256(s) => kdfa_helper(s, key, label, context, out),
        #[cfg(feature = "sha3_256")]
        HmacSlot::Sha3_256(s) => kdfa_helper(s, key, label, context, out),
        #[cfg(feature = "sha3_384")]
        HmacSlot::Sha3_384(s) => kdfa_helper(s, key, label, context, out),
        #[cfg(feature = "sha3_512")]
        HmacSlot::Sha3_512(s) => kdfa_helper(s, key, label, context, out),
    }
}

fn kdfa_helper<S: InitFrom<[u8]> + Update + Finalize<N>, const N: usize>(
    s: &mut MaybeUninit<S>,
    key: &[u8],
    label: &CStr,
    context: (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut counter = 0u32;
    let bits = (out.len() as u32) * 8;

    let mut write_chunk = |chunk: &mut [u8; N]| -> Result<(), CryptoError> {
        counter += 1;
        let mut h = Active::new_from(s, key)?;
        h.update(&counter.to_be_bytes())?;
        h.update(label.to_bytes_with_nul())?;
        h.update(context.0)?;
        h.update(context.1)?;
        h.update(&bits.to_be_bytes())?;
        h.finalize(chunk)
    };

    let (chunks, tail) = out.as_chunks_mut();
    for chunk in chunks {
        write_chunk(chunk)?;
    }
    if !tail.is_empty() {
        let mut tmp = [0u8; N];
        write_chunk(&mut tmp)?;
        tail.copy_from_slice(&tmp[..tail.len()]);
    }
    Ok(())
}

/// NIST SP 800-56A/C One-Step Key Derivation Function (KDFe) as specified in TPM 2.0 Part 1.
///
/// This is only used with ECDH, [`kdfa`] is used everywhere else.
///
/// The `slot` parameter is used to initialize the hash state for each block,
/// filling `out` with derived key material. The shared secret `z` is the
/// x-coordinate of the product of a public point and a private key. The
/// "OtherInfo" is the concatenation of `label` (always null-terminated as it's
/// a [`CStr`]), `party_info.0` (`partyUInfo`), and `party_info.1`
/// (`partyVInfo`).
///
/// We _do not_ have an explicit `bits` parameter, `out` will always be
/// completely filled, giving an effective `bits` of `8 * out.len()`.
pub fn kdfe<H: Hash>(
    slot: &mut HashSlot<H>,
    z: &[u8],
    label: &CStr,
    party_info: (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), CryptoError> {
    match slot {
        #[cfg(feature = "sha1")]
        HashSlot::Sha1(s) => kdfe_helper(s, z, label, party_info, out),
        #[cfg(feature = "sha256")]
        HashSlot::Sha256(s) => kdfe_helper(s, z, label, party_info, out),
        #[cfg(feature = "sha384")]
        HashSlot::Sha384(s) => kdfe_helper(s, z, label, party_info, out),
        #[cfg(feature = "sha512")]
        HashSlot::Sha512(s) => kdfe_helper(s, z, label, party_info, out),
        #[cfg(feature = "sm3_256")]
        HashSlot::Sm3_256(s) => kdfe_helper(s, z, label, party_info, out),
        #[cfg(feature = "sha3_256")]
        HashSlot::Sha3_256(s) => kdfe_helper(s, z, label, party_info, out),
        #[cfg(feature = "sha3_384")]
        HashSlot::Sha3_384(s) => kdfe_helper(s, z, label, party_info, out),
        #[cfg(feature = "sha3_512")]
        HashSlot::Sha3_512(s) => kdfe_helper(s, z, label, party_info, out),
    }
}

fn kdfe_helper<S: Init + Update + Finalize<N>, const N: usize>(
    s: &mut MaybeUninit<S>,
    z: &[u8],
    label: &CStr,
    party_info: (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut counter = 0u32;

    let mut write_chunk = |chunk: &mut [u8; N]| -> Result<(), CryptoError> {
        counter += 1;
        let mut h = Active::new(s)?;
        h.update(&counter.to_be_bytes())?;
        h.update(z)?;
        h.update(label.to_bytes_with_nul())?;
        h.update(party_info.0)?;
        h.update(party_info.1)?;
        h.finalize(chunk)
    };

    let (chunks, tail) = out.as_chunks_mut();
    for chunk in chunks {
        write_chunk(chunk)?;
    }
    if !tail.is_empty() {
        let mut tmp = [0u8; N];
        write_chunk(&mut tmp)?;
        tail.copy_from_slice(&tmp[..tail.len()]);
    }
    Ok(())
}
