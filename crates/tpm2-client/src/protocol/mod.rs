use crate::ClientError;
use crate::sessions::{AuthorizationArea, Session};
use core::mem::size_of;
use tpm2::errors::UnmarshalError;
pub use tpm2::{CommandHeader, ResponseHeader};
use tpm2::{Marshal, TpmsAuthResponse, Unmarshal};

/// Maximum buffer size for sending TPM commands.
pub const CMD_BUFFER_SIZE: usize = 4096;

/// Maximum buffer size for receiving TPM responses.
pub const RESP_BUFFER_SIZE: usize = 4096;

/// Marshals the auth_size parameter of the session area into the given
/// `buffer`, which should point to the beginning of the session area.
/// `auth_offset` indicates the offset to the end of the authorization area
fn marshal_auth_size(auth_offset: usize, buffer: &mut [u8]) -> Result<usize, UnmarshalError> {
    let auth_size = (auth_offset - size_of::<u32>()) as u32;
    if buffer.len() < 4 {
        return Err(UnmarshalError::SIZE);
    }
    auth_size.marshal((&mut buffer[..4]).try_into().unwrap());
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
) -> Result<usize, UnmarshalError> {
    if sessions.is_empty() {
        return Ok(0);
    }
    let mut auth_offset = size_of::<u32>();
    let (s1, s2, s3) = sessions.decompose_ref();
    let Some(s1) = s1 else {
        return marshal_auth_size(auth_offset, buffer);
    };
    if buffer.len() < auth_offset + tpm2::TpmsAuthCommand::MAX_SIZE {
        return Err(UnmarshalError::SIZE);
    }
    auth_offset += s1.auth_command().marshal(
        (&mut buffer[auth_offset..auth_offset + tpm2::TpmsAuthCommand::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    let Some(s2) = s2 else {
        return marshal_auth_size(auth_offset, buffer);
    };
    if buffer.len() < auth_offset + tpm2::TpmsAuthCommand::MAX_SIZE {
        return Err(UnmarshalError::SIZE);
    }
    auth_offset += s2.auth_command().marshal(
        (&mut buffer[auth_offset..auth_offset + tpm2::TpmsAuthCommand::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    let Some(s3) = s3 else {
        return marshal_auth_size(auth_offset, buffer);
    };
    if buffer.len() < auth_offset + tpm2::TpmsAuthCommand::MAX_SIZE {
        return Err(UnmarshalError::SIZE);
    }
    auth_offset += s3.auth_command().marshal(
        (&mut buffer[auth_offset..auth_offset + tpm2::TpmsAuthCommand::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    marshal_auth_size(auth_offset, buffer)
}

/// Unmarshals the response header from the given `buffer`.
pub fn read_response_header<E>(buffer: &[u8]) -> Result<(ResponseHeader, usize), ClientError<E>> {
    let mut slice = buffer;
    let resp_header = ResponseHeader::unmarshal(&mut slice)?;
    resp_header.rc?;
    Ok((resp_header, buffer.len() - slice.len()))
}

/// Unmarshals the session area (0-3 `TPMS_AUTH_RESPONSE` structs) from the
/// given `buffer`.
pub fn read_response_sessions<
    E,
    X: Session,
    Y: Session,
    Z: Session,
    AA: AuthorizationArea<X, Y, Z>,
>(
    sessions: &AA,
    slice: &mut &[u8],
) -> Result<(), ClientError<E>> {
    let (s1, s2, s3) = sessions.decompose_ref();
    let Some(s1) = s1 else { return Ok(()) };
    let auth = TpmsAuthResponse::unmarshal(slice)?;
    s1.validate_auth_response(&auth)?;
    let Some(s2) = s2 else { return Ok(()) };
    let auth = TpmsAuthResponse::unmarshal(slice)?;
    s2.validate_auth_response(&auth)?;
    let Some(s3) = s3 else { return Ok(()) };
    let auth = TpmsAuthResponse::unmarshal(slice)?;
    s3.validate_auth_response(&auth)?;
    Ok(())
}
