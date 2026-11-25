use tpm2::Tpm2bDigest;
use tpm2::commands::{GetRandom, StirRandom, responses};
use tpm2::crypto::Rng;
use tpm2::errors::TpmRc;

use crate::MAX_RESPONSE_BODY;
use crate::handler::{marshal_response, unmarshal_command};

/// Handles `TPM2_GetRandom` (Part 3, Section 16.1).
///
/// Any error from [`Rng::fill_bytes`] puts the TPM into failure mode per the
/// [`CryptoError::Internal`](tpm2::crypto::CryptoError::Internal) contract.
#[doc(alias = "TPM2_GetRandom")]
pub(crate) fn get_random(
    rng: &mut impl Rng,
    params: &[u8],
    rsp_body: &mut [u8; MAX_RESPONSE_BODY],
) -> Result<usize, TpmRc> {
    let cmd = unmarshal_command::<GetRandom>(params)?;
    let count = usize::from(cmd.bytes_requested).min(Tpm2bDigest::CAP);

    let mut random_buf = [0u8; Tpm2bDigest::CAP];
    let out = random_buf.get_mut(..count).ok_or(TpmRc::FAILURE)?;
    if count > 0 {
        rng.fill_bytes(out).map_err(|_| TpmRc::FAILURE)?;
    }

    let random_bytes = Tpm2bDigest::new(out).ok_or(TpmRc::FAILURE)?;
    Ok(marshal_response(
        &responses::GetRandom { random_bytes },
        rsp_body,
    ))
}

/// Handles `TPM2_StirRandom` (Part 3, Section 16.2).
///
/// Any error from [`Rng::stir_bytes`] puts the TPM into failure mode per the
/// [`CryptoError::Internal`](tpm2::crypto::CryptoError::Internal) contract
/// (stricter than the TCG reference `TPM2_StirRandom`, which discards the
/// return value of `CryptoRand_Stir`).
#[doc(alias = "TPM2_StirRandom")]
pub(crate) fn stir_random(rng: &mut impl Rng, params: &[u8]) -> Result<usize, TpmRc> {
    let cmd = unmarshal_command::<StirRandom<'_>>(params)?;
    rng.stir_bytes(cmd.in_data.as_slice())
        .map_err(|_| TpmRc::FAILURE)?;
    Ok(0)
}
