//! # Trusted Platform Module 2.0 (TPM2) Client Library
//!
//! <div class="warning">
//! This code is unstable and there are no guarantees of stability at this time.
//! </div>
//!
//! This client crate provides:
//!   - A [`Connection`] trait for communicating with a TPM
//!   - Various structs implementing [`Connection`] for specific transports.
//!   - High-level abstractions for building and sending commands over the
//!     interface.
//!
//! ## Example
//!
//! ```rust,no_run
//! use tpm2_client::{run_command, connection::tcp::TcpConnection, protocol::RESP_BUFFER_SIZE};
//! use tpm2::commands::GetRandom;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut tpm = TcpConnection::connect("127.0.0.1", None, None)?;
//! let cmd = GetRandom { bytes_requested: 16 };
//! let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
//! let resp = run_command(&cmd, &mut tpm, &mut resp_buffer)?;
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]
#![no_std]

use connection::Connection;
use core::fmt;
use protocol::*;
use sessions::{AuthError, AuthorizationArea, Session};
use tpm2::commands::*;
use tpm2::errors::{TpmRc, UnmarshalError};
use tpm2::{Marshal, Unmarshal};

pub mod connection;
pub mod protocol;
pub mod sessions;

/// Errors that can occur during TPM client operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ClientError<ConnErr = core::convert::Infallible> {
    /// Error returned by the underlying transport connection.
    Connection(ConnErr),
    /// TPM device returned a response code error (`TPM_RC`).
    Tpm(TpmRc),
    /// Failed to unmarshal TPM data structure.
    Unmarshal(UnmarshalError),
    /// Session authorization validation failed.
    Auth(AuthError),
    /// Command exceeded the maximum buffer capacity.
    CommandTooLarge,
    /// Response exceeded the response buffer capacity.
    ResponseTooLarge,
    /// Unexpected trailing bytes left after unmarshaling the response.
    TrailingBytes,
}

impl<E: fmt::Display> fmt::Display for ClientError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(e) => write!(f, "connection error: {e}"),
            Self::Tpm(rc) => write!(f, "TPM error: {rc}"),
            Self::Unmarshal(e) => write!(f, "unmarshal error: {e}"),
            Self::Auth(e) => write!(f, "auth error: {e}"),
            Self::CommandTooLarge => write!(f, "command size exceeds buffer capacity"),
            Self::ResponseTooLarge => write!(f, "response size exceeds buffer capacity"),
            Self::TrailingBytes => write!(f, "unexpected trailing bytes in response"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ClientError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Connection(e) => Some(e),
            Self::Tpm(rc) => Some(rc),
            Self::Unmarshal(e) => Some(e),
            Self::Auth(e) => Some(e),
            _ => None,
        }
    }
}

impl<E> From<TpmRc> for ClientError<E> {
    fn from(rc: TpmRc) -> Self {
        Self::Tpm(rc)
    }
}

impl<E> From<UnmarshalError> for ClientError<E> {
    fn from(err: UnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
}

impl<E> From<AuthError> for ClientError<E> {
    fn from(err: AuthError) -> Self {
        Self::Auth(err)
    }
}

impl<E> PartialEq<TpmRc> for ClientError<E> {
    fn eq(&self, other: &TpmRc) -> bool {
        match self {
            Self::Tpm(rc) => rc == other,
            _ => false,
        }
    }
}

impl<E> PartialEq<UnmarshalError> for ClientError<E> {
    fn eq(&self, other: &UnmarshalError) -> bool {
        match self {
            Self::Unmarshal(err) => err == other,
            _ => false,
        }
    }
}

impl<E> PartialEq<AuthError> for ClientError<E> {
    fn eq(&self, other: &AuthError) -> bool {
        match self {
            Self::Auth(err) => err == other,
            _ => false,
        }
    }
}

/// Runs a TPM command without sessions or handles over the given connection.
///
/// # Errors
/// Returns an error when marshaling, the underlying transaction on the
/// connection, or unmarshaling the response fails.
///
/// Note that a `TPM_RC` error in the response header translates to
/// [`ClientError::Tpm`].
pub fn run_command<'a, CmdT: Command, T: Connection>(
    cmd: &CmdT,
    tpm: &mut T,
    resp_buffer: &'a mut [u8],
) -> Result<CmdT::Response<'a>, ClientError<T::Error>>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    Ok(run_command_with_handles(cmd, CmdT::Handles::default(), (), tpm, resp_buffer)?.0)
}

/// Runs a TPM command with the provided handles and sessions over the given
/// connection.
///
/// # Errors
/// Returns an error when marshaling, the underlying transaction on the
/// connection, or unmarshaling the response fails.
///
/// Note that a `TPM_RC` error in the response header translates to
/// [`ClientError::Tpm`].
#[allow(clippy::type_complexity)]
pub fn run_command_with_handles<
    'a,
    CmdT: Command,
    T: Connection,
    X: Session,
    Y: Session,
    Z: Session,
    AA: AuthorizationArea<X, Y, Z>,
>(
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    cmd_sessions: AA,
    tpm: &mut T,
    resp_buffer: &'a mut [u8],
) -> Result<(CmdT::Response<'a>, CmdT::RespHandles), ClientError<T::Error>>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let mut cmd_header = CommandHeader::with_sessions(!cmd_sessions.is_empty(), CmdT::CMD_CODE);
    let mut written = cmd_header.marshal(
        (&mut cmd_buffer[0..CommandHeader::MAX_SIZE])
            .try_into()
            .unwrap(),
    );

    if written + CmdT::Handles::MAX_SIZE > CMD_BUFFER_SIZE {
        return Err(ClientError::CommandTooLarge);
    }
    let handles_len = cmd_handles.marshal(
        (&mut cmd_buffer[written..written + CmdT::Handles::MAX_SIZE])
            .try_into()
            .ok()
            .unwrap(),
    );
    written += handles_len;
    written += write_command_sessions(&cmd_sessions, &mut cmd_buffer[written..])?;
    let mut param_buf = [0u8; 8192];
    if CmdT::MAX_SIZE > param_buf.len() {
        return Err(ClientError::CommandTooLarge);
    }
    let cmd_len = cmd.marshal((&mut param_buf[..CmdT::MAX_SIZE]).try_into().ok().unwrap());
    if written + cmd_len > CMD_BUFFER_SIZE {
        return Err(ClientError::CommandTooLarge);
    }
    cmd_buffer[written..written + cmd_len].copy_from_slice(&param_buf[..cmd_len]);
    written += cmd_len;

    // Update the command size
    cmd_header.size = written as u32;
    let _ = cmd_header.marshal(
        (&mut cmd_buffer[0..CommandHeader::MAX_SIZE])
            .try_into()
            .unwrap(),
    );

    let resp_buffer = tpm
        .transact(&cmd_buffer[..written], resp_buffer)
        .map_err(ClientError::Connection)?;

    let (resp_header, read) = read_response_header(resp_buffer)?;
    let resp_size = resp_header.size as usize;
    if resp_size > resp_buffer.len() {
        return Err(ClientError::ResponseTooLarge);
    }
    let mut slice = &resp_buffer[read..resp_size];
    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice)?;
    if resp_header.tag == tpm2::TpmSt::SESSIONS {
        let _param_size = u32::unmarshal(&mut slice)?;
    }
    let resp = <CmdT::Response<'a>>::unmarshal(&mut slice)?;
    read_response_sessions(&cmd_sessions, &mut slice)?;

    if !slice.is_empty() {
        return Err(ClientError::TrailingBytes);
    }
    Ok((resp, resp_handles))
}
