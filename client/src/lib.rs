#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use connection::Connection;
use core::mem::size_of;
use sessions::{AuthorizationArea, Session};
use tpm2_rs_base::commands::*;
use tpm2_rs_base::constants::{TpmCc, TpmSt};
use tpm2_rs_base::errors::{TssError, TssResult, TssTcsError};
use tpm2_rs_base::marshal::{Marshalable, UnmarshalBuf};
use tpm2_rs_base::{TpmiStCommandTag, TpmsAuthResponse};

pub mod connection;
pub mod sessions;

pub const CMD_BUFFER_SIZE: usize = 4096;
pub const RESP_BUFFER_SIZE: usize = 4096;

pub fn get_capability<T>(tpm: &mut T, command: &GetCapabilityCmd) -> TssResult<GetCapabilityResp>
where
    T: Connection,
    TssError: From<<T as Connection>::Error>,
{
    run_command(command, tpm)
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct CmdHeader {
    tag: TpmiStCommandTag,
    size: u32,
    code: TpmCc,
}
impl CmdHeader {
    fn new(has_sessions: bool, code: TpmCc) -> CmdHeader {
        let tag = if has_sessions {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        };
        CmdHeader { tag, size: 0, code }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable, Debug)]
pub struct RespHeader {
    pub tag: TpmSt,
    pub size: u32,
    pub rc: u32,
}

/// Runs a command with default/unset handles.
pub fn run_command<CmdT, T>(cmd: &CmdT, tpm: &mut T) -> TssResult<CmdT::RespT>
where
    CmdT: TpmCommand,
    T: Connection,
    TssError: From<<T as Connection>::Error>,
{
    Ok(run_command_with_handles(cmd, CmdT::Handles::default(), (), tpm)?.0)
}

/// This function serializes the size of the authorization area. `buffer` should
/// point to the beginning of the authorization area, specifically to the location
/// where the size of the authorization area will be serialized. The `auth_offset`
/// indicates the offset to the end of the authorization area. The size to be
/// serialized is calculated as the difference between the offset and the start
/// of the buffer, excluding the size of the integer used to store the size.
fn marshal_auth_size(auth_offset: usize, buffer: &mut [u8]) -> TssResult<usize> {
    let auth_size = (auth_offset - size_of::<u32>()) as u32;
    auth_size.try_marshal(buffer)?;
    Ok(auth_offset)
}

/// Adds any command sessions to the command buffer.
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

/// Umarshals the response header and checks the contained response code.
pub fn read_response_header(buffer: &[u8]) -> TssResult<(RespHeader, usize)> {
    let mut unmarsh = UnmarshalBuf::new(buffer);
    let resp_header = RespHeader::try_unmarshal(&mut unmarsh)?;
    if let Ok(error) = TssError::try_from(resp_header.rc) {
        return TssResult::Err(error);
    }
    Ok((resp_header, buffer.len() - unmarsh.len()))
}

/// Unmarshals any response sessions.
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

/// Runs a command with provided handles and sessions.
pub fn run_command_with_handles<
    CmdT,
    T,
    X: Session,
    Y: Session,
    Z: Session,
    AA: AuthorizationArea<X, Y, Z>,
>(
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    cmd_sessions: AA,
    tpm: &mut T,
) -> TssResult<(CmdT::RespT, CmdT::RespHandles)>
where
    CmdT: TpmCommand,
    T: Connection,
    TssError: From<<T as Connection>::Error>,
{
    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let mut cmd_header = CmdHeader::new(cmd_sessions.is_empty(), CmdT::CMD_CODE);
    let mut written = cmd_header.try_marshal(&mut cmd_buffer)?;

    written += cmd_handles.try_marshal(&mut cmd_buffer[written..])?;
    written += write_command_sessions(&cmd_sessions, &mut cmd_buffer[written..])?;
    written += cmd.try_marshal(&mut cmd_buffer[written..])?;

    // Update the command size
    cmd_header.size = written as u32;
    let _ = cmd_header.try_marshal(&mut cmd_buffer)?;

    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    tpm.transact(&cmd_buffer[..written], &mut resp_buffer)?;

    let (resp_header, read) = read_response_header(&resp_buffer)?;
    let resp_size = resp_header.size as usize;
    if resp_size > resp_buffer.len() {
        return TssResult::Err(TssTcsError::OutOfMemory.into());
    }
    let mut unmarsh = UnmarshalBuf::new(&resp_buffer[read..resp_size]);
    let resp_handles = CmdT::RespHandles::try_unmarshal(&mut unmarsh)?;
    if resp_header.tag == TpmSt::Sessions {
        let _param_size = u32::try_unmarshal(&mut unmarsh)?;
    }
    let resp = CmdT::RespT::try_unmarshal(&mut unmarsh)?;
    read_response_sessions(&cmd_sessions, &mut unmarsh)?;

    if !unmarsh.is_empty() {
        return TssResult::Err(TssTcsError::TpmUnexpected.into());
    }
    Ok((resp, resp_handles))
}

#[cfg(test)]
mod tests;
