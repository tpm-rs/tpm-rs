use crate::ClientError;
use crate::sessions::AuthorizationArea;
use core::mem::size_of;
use tpm2::errors::UnmarshalError;
use tpm2::*;

/// Maximum buffer size for sending TPM commands.
pub const CMD_BUFFER_SIZE: usize = 4096;

/// Maximum buffer size for receiving TPM responses.
pub const RESP_BUFFER_SIZE: usize = 4096;

/// Marshals a full command, returning the number of bytes written to `dst`.
///
/// This includes:
/// - the [`CommandHeader`]
/// - the [`Handle`]s
/// - the [`AuthorizationArea`] (if present)
/// - the [`Command`]'s parameters
///
/// ## Compile-time checks
///
/// This function checks that the destination buffer is large enough to hold
/// the largest possible marshaled command. If too big of a command is used,
/// the function will fail during monomorphization time.
///
/// ```compile_fail,E0080
/// # use tpm2_client::protocol::{CMD_BUFFER_SIZE, marshal_command};
/// # use tpm2::*;
/// struct TooBig([u8; CMD_BUFFER_SIZE]);
///
/// # impl Command for TooBig {
/// #     const CMD_CODE: TpmCc = TpmCc::new(0);
/// #     type Response<'a> = ();
/// # }
/// # impl Message for TooBig {
/// #     type Handles = [Handle; 0];
/// #     fn handles(&self) -> Self::Handles {
/// #         []
/// #     }
/// # }
/// impl Marshal for TooBig {
///     const MAX_SIZE: usize = CMD_BUFFER_SIZE;
///     type MaxBuffer = [u8; CMD_BUFFER_SIZE];
///     fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
///         dst.copy_from_slice(&self.0);
///         CMD_BUFFER_SIZE
///     }
/// }
///
/// let mut buf = [0u8; CMD_BUFFER_SIZE];
/// let cmd = TooBig([0; CMD_BUFFER_SIZE]);
/// // Fails to compile, raising "command is too big for buffer".
/// marshal_command(&cmd, &(), &mut buf);
/// ```
pub fn marshal_command<C: Command<MaxBuffer = [u8; N]>, const N: usize>(
    cmd: &C,
    cmd_sessions: &impl AuthorizationArea,
    dst: &mut [u8; CMD_BUFFER_SIZE],
) -> usize {
    const {
        // Note: size_of::<Handle>() == Handle::MAX_SIZE (4 bytes).
        let max_size = CommandHeader::MAX_SIZE
            + size_of::<C::Handles>()
            + (u32::MAX_SIZE + 3 * TpmsAuthCommand::MAX_SIZE)
            + C::MAX_SIZE;
        assert!(max_size <= CMD_BUFFER_SIZE, "command is too big for buffer");
    };

    let mut remaining_buf: &mut [u8] = dst;

    // Don't marshal the header until later, but increment bytes_written.
    let header_buf: &mut [u8; CommandHeader::MAX_SIZE];
    (header_buf, remaining_buf) = remaining_buf.split_first_chunk_mut().unwrap();
    let mut bytes_written = CommandHeader::MAX_SIZE;

    // Marshal Handles
    for handle in cmd.handles().as_ref() {
        let handle_buf: &mut [u8; Handle::MAX_SIZE];
        (handle_buf, remaining_buf) = remaining_buf.split_first_chunk_mut().unwrap();
        bytes_written += handle.marshal(handle_buf);
    }

    // Marshal Sessions
    if cmd_sessions.tag() == TpmiStCommandTag::Sessions {
        // Don't marshal auth_size until later, but increment bytes_written.
        let auth_size_buf: &mut [u8; u32::MAX_SIZE];
        (auth_size_buf, remaining_buf) = remaining_buf.split_first_chunk_mut().unwrap();
        bytes_written += u32::MAX_SIZE;

        let auth_buf: &mut [u8; 3 * TpmsAuthCommand::MAX_SIZE] =
            remaining_buf.first_chunk_mut().unwrap();
        let auth_size = cmd_sessions.marshal_auth_commands(auth_buf);
        remaining_buf = &mut remaining_buf[auth_size..];
        bytes_written += auth_size;

        (auth_size as u32).marshal(auth_size_buf);
    }

    // Marshal Parameters
    let dst: &mut [u8; N] = remaining_buf.first_chunk_mut().unwrap();
    bytes_written += cmd.marshal(dst);

    // Marshal the header after we've computed the total bytes written.
    CommandHeader {
        tag: cmd_sessions.tag(),
        size: bytes_written as u32,
        code: C::CMD_CODE,
    }
    .marshal(header_buf);
    bytes_written
}

/// Unmarshals a full response from `src`.
///
/// This includes validating:
/// - the [`ResponseHeader`]
/// - [`TpmRc`](tpm2::errors::TpmRc) status
/// - [`TpmiStCommandTag`] session tag
/// - the response [`Handle`]s
/// - the `parameterSize` and response parameters
/// - the [`AuthorizationArea`] responses (if present)
pub fn unmarshal_response<'a, R: UnmarshalMessage<'a>, E>(
    cmd_sessions: &impl AuthorizationArea,
    src: &'a [u8],
) -> Result<R, ClientError<E>> {
    let mut remaining = src;

    let resp_header = ResponseHeader::unmarshal(&mut remaining)?;
    resp_header.rc?;

    if resp_header.size as usize != src.len() {
        return Err(ClientError::InvalidResponseSize);
    }
    if resp_header.tag != cmd_sessions.tag() {
        return Err(ClientError::UnexpectedTag);
    }

    // Unmarshal Handles
    let mut rsp_handles = R::Handles::default();
    for handle in rsp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut remaining)?;
    }

    // If sessions are present, split `remaining` into parameters and sessions.
    let sessions: &[u8];
    if resp_header.tag == TpmiStCommandTag::Sessions {
        let param_size = u32::unmarshal(&mut remaining)? as usize;
        (remaining, sessions) = remaining
            .split_at_checked(param_size)
            .ok_or(UnmarshalError)?;
    } else {
        sessions = &[];
    }

    // Unmarshal Parameters
    let resp = R::unmarshal_with_handles(rsp_handles, &mut remaining)?;
    if !remaining.is_empty() {
        return Err(ClientError::TrailingBytes);
    }

    // Unmarshal and validate Sessions
    cmd_sessions.validate_auth_responses(sessions)?;
    Ok(resp)
}
