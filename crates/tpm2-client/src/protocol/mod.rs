//! Low-level TPM 2.0 protocol structures and utility functions.

use crate::sessions::{AuthorizationArea, Session};
use core::mem::size_of;
use tpm2_rs_base::constants::{TpmCc, TpmSt};
use tpm2_rs_base::errors::{TssError, TssResult};
use tpm2_rs_base::marshal::{Marshalable, UnmarshalBuf};
use tpm2_rs_base::{TpmiStCommandTag, TpmsAuthResponse};

/// Maximum buffer size for sending TPM commands.
pub const CMD_BUFFER_SIZE: usize = 4096;

/// Maximum buffer size for receiving TPM responses.
pub const RESP_BUFFER_SIZE: usize = 4096;

/// TPM 2.0 Command Header
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Marshalable)]
pub struct CmdHeader {
    /// Command tag indicating session usage (`TPM_ST_NO_SESSIONS` or `TPM_ST_SESSIONS`).
    pub tag: TpmiStCommandTag,
    /// Total size in bytes of the command including this header.
    pub size: u32,
    /// Command code (`TPM_CC`).
    pub code: TpmCc,
}
impl CmdHeader {
    pub fn new(has_sessions: bool, code: TpmCc) -> CmdHeader {
        let tag = if has_sessions {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        };
        CmdHeader { tag, size: 0, code }
    }
}

/// TPM 2.0 Response Header
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Marshalable)]
pub struct RespHeader {
    /// Response tag which matches the corresponding tag in the command.
    pub tag: TpmSt,
    /// Total size in bytes of the response including this header.
    pub size: u32,
    /// Response code (`TPM_RC`).
    pub rc: u32,
}

/// Marshals the auth_size parameter of the session area into the given
/// `buffer`, which should point to the beginning of the session area.
/// `auth_offset` indicates the offset to the end of the authorization area
fn marshal_auth_size(auth_offset: usize, buffer: &mut [u8]) -> TssResult<usize> {
    let auth_size = (auth_offset - size_of::<u32>()) as u32;
    auth_size.try_marshal(buffer)?;
    Ok(auth_offset)
}

/// Marshals the session area (u32 size + 0-3 `TPMS_AUTH_COMMAND` structs) into
/// the given buffer, returning the number of bytes that were marshaled.
pub fn write_command_sessions<
    X: Session,
    Y: Session,
    Z: Session,
    AA: AuthorizationArea<X, Y, Z>,
>(
    sessions: &AA,
    buffer: &mut [u8],
) -> TssResult<usize> {
    if sessions.is_empty() {
        return Ok(0);
    }
    let mut auth_offset = size_of::<u32>();
    let (s1, s2, s3) = sessions.decompose_ref();
    let Some(s1) = s1 else {
        return marshal_auth_size(auth_offset, buffer);
    };
    auth_offset += s1
        .get_auth_command()
        .try_marshal(&mut buffer[auth_offset..])?;
    let Some(s2) = s2 else {
        return marshal_auth_size(auth_offset, buffer);
    };
    auth_offset += s2
        .get_auth_command()
        .try_marshal(&mut buffer[auth_offset..])?;
    let Some(s3) = s3 else {
        return marshal_auth_size(auth_offset, buffer);
    };
    auth_offset += s3
        .get_auth_command()
        .try_marshal(&mut buffer[auth_offset..])?;
    marshal_auth_size(auth_offset, buffer)
}

/// Unmarshals the response header from the given `buffer`.
pub fn read_response_header(buffer: &[u8]) -> TssResult<(RespHeader, usize)> {
    let mut unmarsh = UnmarshalBuf::new(buffer);
    let resp_header = RespHeader::try_unmarshal(&mut unmarsh)?;
    if let Ok(error) = TssError::try_from(resp_header.rc) {
        return TssResult::Err(error);
    }
    Ok((resp_header, buffer.len() - unmarsh.len()))
}

/// Unmarshals the session area (0-3 `TPMS_AUTH_RESPONSE` structs) from the
/// given `buffer`.
pub fn read_response_sessions<
    X: Session,
    Y: Session,
    Z: Session,
    AA: AuthorizationArea<X, Y, Z>,
>(
    sessions: &AA,
    buffer: &mut UnmarshalBuf,
) -> TssResult<()> {
    let (s1, s2, s3) = sessions.decompose_ref();
    let Some(s1) = s1 else { return Ok(()) };
    let auth = TpmsAuthResponse::try_unmarshal(buffer)?;
    s1.validate_auth_response(&auth)?;
    let Some(s2) = s2 else { return Ok(()) };
    let auth = TpmsAuthResponse::try_unmarshal(buffer)?;
    s2.validate_auth_response(&auth)?;
    let Some(s3) = s3 else { return Ok(()) };
    let auth = TpmsAuthResponse::try_unmarshal(buffer)?;
    s3.validate_auth_response(&auth)?;
    Ok(())
}
