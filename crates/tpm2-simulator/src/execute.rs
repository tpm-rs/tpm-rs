use core::fmt;
use tpm2::commands::*;
use tpm2::errors::{TpmRc, UnmarshalError};
use tpm2::{Handle, Marshal, Message, Unmarshal};
use tpm2::{TpmCc, TpmSt, TpmiStCommandTag};

const CMD_BUFFER_SIZE: usize = tpm2_impl::MAX_MESSAGE_SIZE;
const RESP_BUFFER_SIZE: usize = tpm2_impl::MAX_MESSAGE_SIZE;

/// Errors that can occur during simulator execution.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ExecuteError {
    /// TPM device returned a response code error (`TPM_RC`).
    Tpm(TpmRc),
    /// Failed to unmarshal TPM data structure.
    Unmarshal(UnmarshalError),
    /// Failed to unmarshal the response parameters.
    ///
    /// The [`TpmRc`] identifies the reason and the failing parameter (as returned by
    /// [`UnmarshalMessage::unmarshal_with_handles`]), but was produced locally rather than
    /// returned by the TPM.
    ///
    /// PORTING: exp reported these as [`ExecuteError::Unmarshal`]; the new response types
    /// return a [`TpmRc`] with the parameter position instead of an [`UnmarshalError`].
    MalformedResponse(TpmRc),
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
            Self::MalformedResponse(rc) => write!(f, "malformed response parameters: {rc}"),
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
            Self::Tpm(rc) | Self::MalformedResponse(rc) => Some(rc),
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
        let mut tag = [0u8; TpmiStCommandTag::MAX_SIZE];
        let mut code = [0u8; TpmCc::MAX_SIZE];
        let written = self.tag.marshal(&mut tag) + self.code.marshal(&mut code);
        let [t0, t1] = tag;
        let [s0, s1, s2, s3] = self.size.to_be_bytes();
        let [c0, c1, c2, c3] = code;
        *dst = [t0, t1, s0, s1, s2, s3, c0, c1, c2, c3];
        written + u32::MAX_SIZE
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
        let mut tag = [0u8; TpmSt::MAX_SIZE];
        let written = self.tag.marshal(&mut tag);
        let [t0, t1] = tag;
        let [s0, s1, s2, s3] = self.size.to_be_bytes();
        let [r0, r1, r2, r3] = self.rc.to_be_bytes();
        *dst = [t0, t1, s0, s1, s2, s3, r0, r1, r2, r3];
        written + u32::MAX_SIZE + u32::MAX_SIZE
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

/// Marshals `value` into `dst` at `offset` and returns the offset just past it.
///
/// Returns [`ExecuteError::CommandTooLarge`] if `value` does not fit.
fn put<const N: usize>(
    value: &impl Marshal<MaxBuffer = [u8; N]>,
    dst: &mut [u8],
    offset: usize,
) -> Result<usize, ExecuteError> {
    let mut buf = [0u8; N];
    let len = value.marshal(&mut buf);
    let src = buf.get(..len).ok_or(ExecuteError::Unexpected)?;
    let end = offset
        .checked_add(len)
        .ok_or(ExecuteError::CommandTooLarge)?;
    dst.get_mut(offset..end)
        .ok_or(ExecuteError::CommandTooLarge)?
        .copy_from_slice(src);
    Ok(end)
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

/// Runs a command with its handles, adding an empty password session for each handle that
/// requires authorization.
///
/// PORTING: exp had `run_command` (default handles) and `run_command_with_handles` (explicit
/// handles, returning the response handles separately). The new `tpm2` commands carry their
/// handles and responses carry their response handles, so a single function remains.
pub fn run_command<CmdT: Command<MaxBuffer = [u8; N]>, const N: usize>(
    cmd: &CmdT,
    tpm: &mut crate::Simulator<'_>,
) -> Result<CmdT::Response<'static>, ExecuteError> {
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
    // The header is marshaled last, once the command size is known.
    let mut written = CmdHeader::MAX_SIZE;

    for handle in cmd.handles().as_ref() {
        written = put(handle, &mut cmd_buffer, written)?;
    }

    if num_sessions > 0 {
        let auth_cmd = tpm2::TpmsAuthCommand {
            session_handle: tpm2::Handle::RS_PW, // Password handle
            nonce: tpm2::Tpm2bNonce::default(),
            session_attributes: tpm2::TpmaSession(0),
            hmac: tpm2::Tpm2bAuth::default(),
        };
        let auth_size_offset = written;
        written = put(&0u32, &mut cmd_buffer, written)?;
        let auth_start = written;
        for _ in 0..num_sessions {
            written = put(&auth_cmd, &mut cmd_buffer, written)?;
        }
        let auth_size =
            u32::try_from(written - auth_start).map_err(|_| ExecuteError::CommandTooLarge)?;
        put(&auth_size, &mut cmd_buffer, auth_size_offset)?;
    }

    written = put(cmd, &mut cmd_buffer, written)?;

    // Update the command size
    cmd_header.size = u32::try_from(written).map_err(|_| ExecuteError::CommandTooLarge)?;
    put(&cmd_header, &mut cmd_buffer, 0)?;

    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    let command = cmd_buffer.get(..written).ok_or(ExecuteError::Unexpected)?;
    tpm.transact(command, &mut resp_buffer)?;

    let (resp_header, read) = read_response_header(&resp_buffer)?;
    let resp_size =
        usize::try_from(resp_header.size).map_err(|_| ExecuteError::ResponseTooLarge)?;
    if resp_size > resp_buffer.len() {
        return Err(ExecuteError::ResponseTooLarge);
    }
    let resp_bytes = resp_buffer
        .get(read..resp_size)
        .ok_or(ExecuteError::Unmarshal(UnmarshalError::Size))?;
    let mut slice: &'static [u8] = std::vec::Vec::leak(resp_bytes.to_vec());
    let mut resp_handles = <CmdT::Response<'static> as Message>::Handles::default();
    for handle in resp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut slice)?;
    }
    if resp_header.tag == TpmSt::SESSIONS {
        let _param_size = u32::unmarshal(&mut slice)?;
    }
    let resp = <CmdT::Response<'static>>::unmarshal_with_handles(resp_handles, &mut slice)
        .map_err(ExecuteError::MalformedResponse)?;

    if resp_header.tag == TpmSt::SESSIONS {
        for _ in 0..num_sessions {
            let _auth_resp = tpm2::TpmsAuthResponse::unmarshal(&mut slice)?;
        }
    }

    if !slice.is_empty() {
        return Err(ExecuteError::TrailingBytes);
    }
    Ok(resp)
}
