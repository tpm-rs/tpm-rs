use crate::ClientError;
use crate::sessions::{AuthError, AuthorizationArea, CommandData, ResponseData};
use core::mem::size_of;
use tpm2::errors::UnmarshalError;
use tpm2::*;

/// Maximum buffer size for sending TPM commands.
pub const CMD_BUFFER_SIZE: usize = 8192;

/// Maximum buffer size for receiving TPM responses.
pub const RESP_BUFFER_SIZE: usize = 8192;

/// Marshals a full command, returning the number of bytes written to `dst`.
///
/// This includes:
/// - the [`CommandHeader`]
/// - the [`Handle`]s
/// - the [`AuthorizationArea`] (if present)
/// - the [`Command`]'s parameters
///
/// `names` are the Names of the command's handles, which sessions may need
/// (see [`CommandData::names`]).
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
/// marshal_command(&cmd, &[], &mut (), &mut buf);
/// ```
pub fn marshal_command<C: Command<MaxBuffer = [u8; N]>, const N: usize>(
    cmd: &C,
    names: &[Option<Tpm2bName>],
    cmd_sessions: &mut impl AuthorizationArea,
    dst: &mut [u8; CMD_BUFFER_SIZE],
) -> Result<usize, AuthError> {
    const MAX_AUTH_SIZE: usize = 3 * TpmsAuthCommand::MAX_SIZE;
    const {
        // Note: size_of::<Handle>() == Handle::MAX_SIZE (4 bytes).
        let max_size = CommandHeader::MAX_SIZE
            + size_of::<C::Handles>()
            + (u32::MAX_SIZE + MAX_AUTH_SIZE)
            + C::MAX_SIZE;
        assert!(max_size <= CMD_BUFFER_SIZE, "command is too big for buffer");
    };

    // Don't marshal the header until later, but skip over it.
    let mut offset = CommandHeader::MAX_SIZE;

    // Marshal Handles
    let handles = cmd.handles();
    for handle in handles.as_ref() {
        offset += handle.marshal(dst[offset..].first_chunk_mut().unwrap());
    }

    if cmd_sessions.tag() == TpmiStCommandTag::Sessions {
        // The sessions (via cpHash) depend on the parameters, so marshal the
        // parameters first, after space reserved for the largest possible
        // authorization area. Then marshal the sessions and move the
        // parameters down to directly follow them.
        let auth_size_offset = offset;
        let auth_offset = auth_size_offset + u32::MAX_SIZE;
        let params_offset = auth_offset + MAX_AUTH_SIZE;

        let (auth_buf, params_buf) = dst[auth_offset..].split_at_mut(MAX_AUTH_SIZE);
        let auth_buf: &mut [u8; MAX_AUTH_SIZE] = auth_buf.try_into().unwrap();
        let params_buf: &mut [u8; N] = params_buf.first_chunk_mut().unwrap();

        // Marshal Parameters
        let params_size = cmd.marshal(params_buf);

        // Marshal Sessions
        let cmd_data = CommandData {
            code: C::CMD_CODE,
            handles: handles.as_ref(),
            names,
            params: &params_buf[..params_size],
        };
        let auth_size = cmd_sessions.marshal_auth_commands(&cmd_data, auth_buf)?;
        (auth_size as u32).marshal(dst[auth_size_offset..].first_chunk_mut().unwrap());

        dst.copy_within(
            params_offset..params_offset + params_size,
            auth_offset + auth_size,
        );
        offset = auth_offset + auth_size + params_size;
    } else {
        // Marshal Parameters
        offset += cmd.marshal(dst[offset..].first_chunk_mut().unwrap());
    }

    // Marshal the header after we've computed the total bytes written.
    CommandHeader {
        tag: cmd_sessions.tag(),
        size: offset as u32,
        code: C::CMD_CODE,
    }
    .marshal(dst.first_chunk_mut().unwrap());
    Ok(offset)
}

/// Unmarshals a full response from `src`.
///
/// This includes validating:
/// - the [`ResponseHeader`]
/// - [`TpmRc`](tpm2::errors::TpmRc) status
/// - [`TpmiStCommandTag`] session tag
/// - the response [`Handle`]s
/// - the `parameterSize` and response parameters
/// - the [`AuthorizationArea`] responses (if present), for the command
///   `cmd_code`
pub fn unmarshal_response<'a, R: UnmarshalMessage<'a>, E>(
    cmd_code: TpmCc,
    cmd_sessions: &mut impl AuthorizationArea,
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
    let rsp_data = ResponseData {
        code: cmd_code,
        params: remaining,
    };
    let resp = R::unmarshal_with_handles(rsp_handles, &mut remaining)?;
    if !remaining.is_empty() {
        return Err(ClientError::TrailingBytes);
    }

    // Unmarshal and validate Sessions
    cmd_sessions.validate_auth_responses(&rsp_data, sessions)?;
    Ok(resp)
}
