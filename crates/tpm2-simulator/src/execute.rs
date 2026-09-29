use core::fmt;
use tpm2::TpmiStCommandTag;
use tpm2::commands::*;
use tpm2::errors::{TpmRc, UnmarshalError};
use tpm2::{Marshal, Unmarshal};
use tpm2::{TpmCc, TpmSt};

const CMD_BUFFER_SIZE: usize = 4096;
const RESP_BUFFER_SIZE: usize = 4096;

/// Errors that can occur during simulator execution.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ExecuteError {
    /// TPM device returned a response code error (`TPM_RC`).
    Tpm(TpmRc),
    /// Failed to unmarshal TPM data structure.
    Unmarshal(UnmarshalError),
    /// Command exceeded the maximum buffer capacity.
    CommandTooLarge,
    /// Response exceeded the response buffer capacity.
    ResponseTooLarge,
    /// Unexpected trailing bytes left after unmarshaling the response.
    TrailingBytes,
    /// Internal simulator unexpected failure.
    Unexpected,
}

impl fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tpm(rc) => write!(f, "TPM error: {rc}"),
            Self::Unmarshal(e) => write!(f, "unmarshal error: {e}"),
            Self::CommandTooLarge => write!(f, "command size exceeds buffer capacity"),
            Self::ResponseTooLarge => write!(f, "response size exceeds buffer capacity"),
            Self::TrailingBytes => write!(f, "unexpected trailing bytes in response"),
            Self::Unexpected => write!(f, "unexpected simulator failure"),
        }
    }
}

impl core::error::Error for ExecuteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Tpm(rc) => Some(rc),
            Self::Unmarshal(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TpmRc> for ExecuteError {
    fn from(rc: TpmRc) -> Self {
        Self::Tpm(rc)
    }
}

impl From<UnmarshalError> for ExecuteError {
    fn from(err: UnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
}

impl PartialEq<TpmRc> for ExecuteError {
    fn eq(&self, other: &TpmRc) -> bool {
        match self {
            Self::Tpm(rc) => rc == other,
            _ => false,
        }
    }
}

impl PartialEq<UnmarshalError> for ExecuteError {
    fn eq(&self, other: &UnmarshalError) -> bool {
        match self {
            Self::Unmarshal(err) => err == other,
            _ => false,
        }
    }
}

impl ExecuteError {
    /// Returns the underlying TPM response code as a `u32` if this is a `Tpm` error.
    pub const fn get(&self) -> u32 {
        match self {
            Self::Tpm(rc) => rc.get(),
            _ => 0,
        }
    }

    /// Returns the underlying [`TpmRc`] if this is a `Tpm` error.
    pub const fn tpm_rc(&self) -> Option<TpmRc> {
        match self {
            Self::Tpm(rc) => Some(*rc),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct CmdHeader {
    pub tag: TpmiStCommandTag,
    pub size: u32,
    pub code: TpmCc,
}

impl Marshal for CmdHeader {
    const MAX_SIZE: usize = 10;
    type MaxBuffer = [u8; 10];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut written = self.tag.marshal((&mut dst[0..2]).try_into().unwrap());
        written += self.size.marshal((&mut dst[2..6]).try_into().unwrap());
        written += self.code.marshal((&mut dst[6..10]).try_into().unwrap());
        written
    }
}

impl<'a> Unmarshal<'a> for CmdHeader {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let tag = TpmiStCommandTag::unmarshal(src)?;
        let size = u32::unmarshal(src)?;
        let code = TpmCc::unmarshal(src)?;
        Ok(Self { tag, size, code })
    }
}

impl CmdHeader {
    pub fn new(code: TpmCc) -> CmdHeader {
        let tag = TpmiStCommandTag::NoSessions;
        CmdHeader { tag, size: 0, code }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct RespHeader {
    pub tag: TpmSt,
    pub size: u32,
    pub rc: u32,
}

impl Marshal for RespHeader {
    const MAX_SIZE: usize = 10;
    type MaxBuffer = [u8; 10];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut written = self.tag.marshal((&mut dst[0..2]).try_into().unwrap());
        written += self.size.marshal((&mut dst[2..6]).try_into().unwrap());
        written += self.rc.marshal((&mut dst[6..10]).try_into().unwrap());
        written
    }
}

impl<'a> Unmarshal<'a> for RespHeader {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let tag = TpmSt::unmarshal(src)?;
        let size = u32::unmarshal(src)?;
        let rc = u32::unmarshal(src)?;
        Ok(Self { tag, size, rc })
    }
}

/// Runs a command with default/unset handles.
pub fn run_command<CmdT: Command>(
    cmd: &CmdT,
    tpm: &mut crate::Simulator<'_>,
) -> Result<CmdT::Response<'static>, ExecuteError>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    Ok(run_command_with_handles(cmd, CmdT::Handles::default(), tpm)?.0)
}

/// Unmarshals the response header and checks the contained response code.
fn read_response_header(buffer: &[u8]) -> Result<(RespHeader, usize), ExecuteError> {
    let mut slice = buffer;
    let resp_header = RespHeader::unmarshal(&mut slice)?;
    if let Some(error) = TpmRc::new(resp_header.rc) {
        return Err(ExecuteError::Tpm(error));
    }
    Ok((resp_header, buffer.len() - slice.len()))
}

/// Runs a command with provided handles and sessions.
pub fn run_command_with_handles<CmdT: Command>(
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    tpm: &mut crate::Simulator<'_>,
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), ExecuteError>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut num_sessions = 0;
    let num_handles = tpm2_impl::command_handles_count(CmdT::CMD_CODE);
    for h_idx in 0..num_handles {
        if tpm2_impl::handle_requires_auth(CmdT::CMD_CODE, h_idx) {
            num_sessions += 1;
        }
    }

    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let tag = if num_sessions > 0 {
        tpm2::TpmiStCommandTag::Sessions
    } else {
        tpm2::TpmiStCommandTag::NoSessions
    };
    let mut cmd_header = CmdHeader {
        tag,
        size: 0,
        code: CmdT::CMD_CODE,
    };
    let mut written = cmd_header.marshal(
        (&mut cmd_buffer[0..CmdHeader::MAX_SIZE])
            .try_into()
            .unwrap(),
    );

    if written + CmdT::Handles::MAX_SIZE > CMD_BUFFER_SIZE {
        return Err(ExecuteError::CommandTooLarge);
    }
    let handles_len = cmd_handles.marshal(
        (&mut cmd_buffer[written..written + CmdT::Handles::MAX_SIZE])
            .try_into()
            .ok()
            .unwrap(),
    );
    written += handles_len;

    if num_sessions > 0 {
        let auth_cmd = tpm2::TpmsAuthCommand {
            session_handle: tpm2::Handle::RS_PW, // Password handle
            nonce: tpm2::Tpm2bNonce::default(),
            session_attributes: tpm2::TpmaSession(0),
            hmac: tpm2::Tpm2bAuth::default(),
        };
        let mut auth_buffer = [0u8; 1024];
        let mut auth_written = 0;
        for _ in 0..num_sessions {
            auth_written += auth_cmd.marshal(
                (&mut auth_buffer[auth_written..auth_written + tpm2::TpmsAuthCommand::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if written + 4 + auth_written > CMD_BUFFER_SIZE {
            return Err(ExecuteError::CommandTooLarge);
        }
        written += (auth_written as u32)
            .marshal((&mut cmd_buffer[written..written + 4]).try_into().unwrap());
        cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
        written += auth_written;
    }

    let mut param_buf = [0u8; 8192];
    if CmdT::MAX_SIZE > param_buf.len() {
        return Err(ExecuteError::CommandTooLarge);
    }
    let cmd_len = cmd.marshal((&mut param_buf[..CmdT::MAX_SIZE]).try_into().ok().unwrap());
    if written + cmd_len > CMD_BUFFER_SIZE {
        return Err(ExecuteError::CommandTooLarge);
    }
    cmd_buffer[written..written + cmd_len].copy_from_slice(&param_buf[..cmd_len]);
    written += cmd_len;

    // Update the command size
    cmd_header.size = written as u32;
    let _ = cmd_header.marshal(
        (&mut cmd_buffer[0..CmdHeader::MAX_SIZE])
            .try_into()
            .unwrap(),
    );

    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    tpm.transact(&cmd_buffer[..written], &mut resp_buffer)?;

    let (resp_header, read) = read_response_header(&resp_buffer)?;
    let resp_size = resp_header.size as usize;
    if resp_size > resp_buffer.len() {
        return Err(ExecuteError::ResponseTooLarge);
    }
    let mut slice: &'static [u8] = std::vec::Vec::leak(resp_buffer[read..resp_size].to_vec());
    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice)?;
    if resp_header.tag == TpmSt::SESSIONS {
        let _param_size = u32::unmarshal(&mut slice)?;
    }
    let resp = <CmdT::Response<'static>>::unmarshal(&mut slice)?;

    if resp_header.tag == TpmSt::SESSIONS {
        for _ in 0..num_sessions {
            let _auth_resp = tpm2::TpmsAuthResponse::unmarshal(&mut slice)?;
        }
    }

    if !slice.is_empty() {
        return Err(ExecuteError::TrailingBytes);
    }
    Ok((resp, resp_handles))
}
