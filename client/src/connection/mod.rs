//! This module provides traits to communicate with a
//! TPM via a particular medium. The top-level trait
//! is [`Connection`].

use core::error::Error;

mod tcp;

#[cfg(feature = "connection-tcp")]
pub use tcp::*;

/// Trait for communicating with a TPM.
pub trait Connection {
    /// The type returned if [`Connection::transact`] fails.
    ///
    /// This type does not include `TPM_RC` errors, only errors related to the
    /// connection itself. If the connection can never fail, this can be
    /// [`Infallible`](core::convert::Infallible).
    type Error: Error;
    /// Perform a command/response transaction with the TPM.
    ///
    /// Returns a slice of the response containing the bytes that were written.
    ///
    /// Note that even if the response contains a `TPM_RC` error, this method
    /// still returns `Ok(...)`. `Err` is only returned when we are unable to
    /// get a response at all.
    fn transact<'a>(&mut self, cmd: &[u8], rsp: &'a mut [u8]) -> Result<&'a mut [u8], Self::Error>;
}
