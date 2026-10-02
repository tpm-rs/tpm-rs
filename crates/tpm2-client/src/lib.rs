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
use sessions::{AuthError, AuthorizationArea};
use tpm2::{Command, Marshal, Tpm2bName, TpmiAlgHash, TpmsNvPublic, TpmtHa};
use tpm2::crypto::{CryptoError, Hash, hash};
use tpm2::errors::{TpmRc, UnmarshalError};

pub mod connection;
pub mod protocol;
pub mod sessions;

/// Errors that can occur during TPM client operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ClientError<ConnErr = !> {
    /// Error returned by the underlying transport connection.
    Connection(ConnErr),
    /// TPM device returned a response code error (`TPM_RC`).
    Tpm(TpmRc),
    /// Failed to unmarshal TPM data structure.
    Unmarshal(UnmarshalError),
    /// Session authorization validation failed.
    Auth(AuthError),
    /// Response header size does not match the received buffer length.
    InvalidResponseSize,
    /// Response header tag does not match whether sessions were used.
    UnexpectedTag,
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
            Self::InvalidResponseSize => {
                write!(f, "response header size does not match buffer length")
            }
            Self::UnexpectedTag => write!(f, "unexpected response header tag"),
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

/// Computes the Name of an NV index from its public area
/// (TPM 2.0 Part 1, Section 16):
///
/// ```text
/// Name := nameAlg || H_nameAlg(TPMS_NV_PUBLIC)
/// ```
///
/// Note that the TPM sets [`TpmaNv::WRITTEN`](tpm2::TpmaNv::WRITTEN) on the
/// first write to an index, which changes its Name. Commands after that
/// (e.g. `TPM2_NV_Read`) need the Name computed with that attribute set.
pub fn nv_name<'a>(
    h: &impl Hash,
    public: &TpmsNvPublic,
    out: &'a mut [u8; Tpm2bName::CAP],
) -> Result<Tpm2bName<'a>, CryptoError> {
    let mut public_buf = [0u8; TpmsNvPublic::MAX_SIZE];
    let public_size = public.marshal(&mut public_buf);

    let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = hash(
        h,
        public.name_alg,
        &public_buf[..public_size],
        &mut digest_buf,
    )?;

    // A Name is a marshaled TPMT_HA.
    const { assert!(Tpm2bName::CAP == TpmtHa::MAX_SIZE) };
    let name_size = digest.marshal(out);
    Ok(Tpm2bName::new(&out[..name_size]).unwrap())
}

/// Runs a TPM command without sessions over the given connection.
///
/// # Errors
/// Returns an error when marshaling, the underlying transaction on the
/// connection, or unmarshaling the response fails.
///
/// Note that a `TPM_RC` error in the response header translates to
/// [`ClientError::Tpm`].
pub fn run_command<'a, C: Command<MaxBuffer = [u8; N]>, T: Connection, const N: usize>(
    cmd: &C,
    tpm: &mut T,
    resp_buffer: &'a mut [u8],
) -> Result<C::Response<'a>, ClientError<T::Error>> {
    run_command_with_sessions(cmd, &[], &mut (), tpm, resp_buffer)
}

/// Runs a TPM command with the provided sessions over the given
/// connection.
///
/// `names` are the Names of the command's handles, in handle order. Sessions
/// that compute a cpHash (e.g. [`HmacSession`](sessions::HmacSession)) need
/// a Name for every handle. Names of PCR, session, and permanent handles are
/// derived from the handle, so a `None` (or missing) entry can be used.
/// Other Names (e.g. of NV indices or objects) must be provided.
///
/// Sessions are updated in place (e.g. rolling nonces), so they are borrowed
/// mutably. Multiple sessions can be passed as a tuple of `&mut` references,
/// e.g. `&mut (&mut s1, &mut s2)`.
///
/// # Errors
/// Returns an error when marshaling, the underlying transaction on the
/// connection, or unmarshaling the response fails.
///
/// Note that a `TPM_RC` error in the response header translates to
/// [`ClientError::Tpm`].
pub fn run_command_with_sessions<
    'a,
    C: Command<MaxBuffer = [u8; N]>,
    T: Connection,
    const N: usize,
>(
    cmd: &C,
    names: &[Option<Tpm2bName>],
    cmd_sessions: &mut impl AuthorizationArea,
    tpm: &mut T,
    resp_buffer: &'a mut [u8],
) -> Result<C::Response<'a>, ClientError<T::Error>> {
    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let written = marshal_command(cmd, names, cmd_sessions, &mut cmd_buffer)?;

    let resp_buffer = tpm
        .transact(&cmd_buffer[..written], resp_buffer)
        .map_err(ClientError::Connection)?;

    unmarshal_response(C::CMD_CODE, cmd_sessions, resp_buffer)
}

#[cfg(test)]
mod tests;
