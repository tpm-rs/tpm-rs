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
//! use tpm2_client::{run_command, connection::tcp::TcpConnection};
//! use tpm2_rs_base::commands::GetRandomCmd;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut tpm = TcpConnection::connect("127.0.0.1", None, None)?;
//! let cmd = GetRandomCmd{ bytes_requested: 16 };
//! let resp = run_command(&cmd, &mut tpm)?;
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]
#![no_std]

use connection::Connection;
use protocol::*;
use sessions::{AuthorizationArea, Session};
use tpm2_rs_base::commands::*;
use tpm2_rs_base::constants::TpmSt;
use tpm2_rs_base::errors::{TssError, TssTcsError};
use tpm2_rs_base::marshal::{Marshalable, UnmarshalBuf};

pub mod connection;
pub mod protocol;
pub mod sessions;

/// Runs a TPM command without sessions or handles over the given connectino.
///
/// # Errors
/// Returns an error when marshaling, the underlying transaction on the
/// connection, or unmarshaling the response fails.
///
/// Note that a `TPM_RC` error in the response header does not translate to an
/// error in this function.
pub fn run_command<CmdT: TpmCommand, T: Connection<Error: From<TssError>>>(
    cmd: &CmdT,
    tpm: &mut T,
) -> Result<CmdT::RespT, T::Error> {
    Ok(run_command_with_handles(cmd, CmdT::Handles::default(), (), tpm)?.0)
}

/// Runs a TPM command with the provided handles and sessions over the given
/// connectino.
///
/// # Errors
/// Returns an error when marshaling, the underlying transaction on the
/// connection, or unmarshaling the response fails.
///
/// Note that a `TPM_RC` error in the response header does not translate to an
/// error in this function.
pub fn run_command_with_handles<
    CmdT: TpmCommand,
    T: Connection<Error: From<TssError>>,
    X: Session,
    Y: Session,
    Z: Session,
    AA: AuthorizationArea<X, Y, Z>,
>(
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    cmd_sessions: AA,
    tpm: &mut T,
) -> Result<(CmdT::RespT, CmdT::RespHandles), T::Error> {
    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let mut cmd_header = CmdHeader::new(cmd_sessions.is_empty(), CmdT::CMD_CODE);
    let mut written = cmd_header
        .try_marshal(&mut cmd_buffer)
        .map_err(TssError::from)?;

    written += cmd_handles
        .try_marshal(&mut cmd_buffer[written..])
        .map_err(TssError::from)?;
    written += write_command_sessions(&cmd_sessions, &mut cmd_buffer[written..])?;
    written += cmd
        .try_marshal(&mut cmd_buffer[written..])
        .map_err(TssError::from)?;

    // Update the command size
    cmd_header.size = written as u32;
    let _ = cmd_header
        .try_marshal(&mut cmd_buffer)
        .map_err(TssError::from)?;

    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    tpm.transact(&cmd_buffer[..written], &mut resp_buffer)?;

    let (resp_header, read) = read_response_header(&resp_buffer)?;
    let resp_size = resp_header.size as usize;
    if resp_size > resp_buffer.len() {
        return Err(TssError::from(TssTcsError::OutOfMemory).into());
    }
    let mut unmarsh = UnmarshalBuf::new(&resp_buffer[read..resp_size]);
    let resp_handles = CmdT::RespHandles::try_unmarshal(&mut unmarsh).map_err(TssError::from)?;
    if resp_header.tag == TpmSt::Sessions {
        let _param_size = u32::try_unmarshal(&mut unmarsh).map_err(TssError::from)?;
    }
    let resp = CmdT::RespT::try_unmarshal(&mut unmarsh).map_err(TssError::from)?;
    read_response_sessions(&cmd_sessions, &mut unmarsh)?;

    if !unmarsh.is_empty() {
        return Err(TssError::from(TssTcsError::TpmUnexpected).into());
    }
    Ok((resp, resp_handles))
}

#[cfg(test)]
mod tests;
