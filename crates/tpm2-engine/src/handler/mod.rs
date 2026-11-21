pub(crate) mod random;
pub(crate) mod startup;

use tpm2::errors::TpmRc;
use tpm2::{EntityHandle, Handle, Response, UnmarshalCommand};

use crate::MAX_RESPONSE_BODY;

/// Unmarshals a zero-handle command's parameter area and rejects trailing bytes.
pub(crate) fn unmarshal_command<'a, C>(mut params: &'a [u8]) -> Result<C, TpmRc>
where
    C: UnmarshalCommand<'a, Handles<'a> = [EntityHandle<'a>; 0]>,
{
    // TODO: Distinguish truncated input (`TPM_RC_INSUFFICIENT`), bad selectors
    // (`TPM_RC_VALUE`), and oversized buffers (`TPM_RC_SIZE`) once
    // `tpm2::errors::UnmarshalError` carries more detail.
    let cmd =
        C::unmarshal_with_handles([], &mut params).map_err(|_| TpmRc::INSUFFICIENT.to_rc())?;
    if !params.is_empty() {
        return Err(TpmRc::SIZE.to_rc());
    }
    Ok(cmd)
}

/// Marshals a zero-handle response's parameter area directly into `dst`,
/// returning the number of bytes written.
///
/// A compile-time assertion guarantees `R::MAX_SIZE <= MAX_RESPONSE_BODY`.
pub(crate) fn marshal_response<R, const N: usize>(
    rsp: &R,
    dst: &mut [u8; MAX_RESPONSE_BODY],
) -> usize
where
    R: Response<Handles = [Handle; 0], MaxBuffer = [u8; N]>,
{
    const { assert!(N <= MAX_RESPONSE_BODY, "response exceeds MAX_RESPONSE_SIZE") };
    rsp.marshal(dst.first_chunk_mut::<N>().unwrap())
}
