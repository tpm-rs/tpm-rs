#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]
use core::mem::size_of;
use sessions::CmdSessions;
use tpm2_rs_base::commands::*;
use tpm2_rs_base::constants::{TpmCc, TpmSt};
use tpm2_rs_base::errors::{TssError, TssResult, TssTcsError};
use tpm2_rs_base::marshal::{Marshalable, UnmarshalBuf};
use tpm2_rs_base::{TpmiStCommandTag, TpmsAuthResponse};

pub const CMD_BUFFER_SIZE: usize = 4096;
pub const RESP_BUFFER_SIZE: usize = 4096;

pub mod sessions;

pub trait Tpm {
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TssResult<()>;
}

pub fn get_capability<T: Tpm>(
    tpm: &mut T,
    command: &GetCapabilityCmd,
) -> TssResult<GetCapabilityResp> {
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
    T: Tpm,
{
    Ok(run_command_with_handles(cmd, CmdT::Handles::default(), CmdSessions::default(), tpm)?.0)
}

/// Adds any command sessions to the command buffer.
pub fn write_command_sessions(sessions: &CmdSessions, buffer: &mut [u8]) -> TssResult<usize> {
    if sessions.is_empty() {
        return Ok(0);
    }
    let mut auth_offset = size_of::<u32>();
    for session in sessions {
        // TODO: Support parameter encryption.
        auth_offset += session
            .get_auth_command()
            .try_marshal(&mut buffer[auth_offset..])?;
    }
    let auth_size = (auth_offset - size_of::<u32>()) as u32;
    auth_size.try_marshal(buffer)?;
    Ok(auth_offset)
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
pub fn read_response_sessions(sessions: &CmdSessions, buffer: &mut UnmarshalBuf) -> TssResult<()> {
    for session in sessions {
        // TODO: Support parameter decryption.
        let auth = TpmsAuthResponse::try_unmarshal(buffer)?;
        session.validate_auth_response(&auth)?;
    }
    Ok(())
}

/// Runs a command with provided handles and sessions.
pub fn run_command_with_handles<CmdT, T>(
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    cmd_sessions: CmdSessions,
    tpm: &mut T,
) -> TssResult<(CmdT::RespT, CmdT::RespHandles)>
where
    CmdT: TpmCommand,
    T: Tpm,
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
