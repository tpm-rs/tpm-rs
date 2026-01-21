//! This module provides traits to communicate with a
//! TPM via a particular medium. The top-level trait
//! is [`Connection`].

use core::error::Error;

/// Trait bound required for the [`Connection::Error`] associated type.
pub trait ConnectionError: Error + Send + Sync + 'static {}

/// Any type that implements the bounded traits also implements ConnectionError.
impl<T> ConnectionError for T where T: Error + Send + Sync + 'static {}

/// Trait for communicating with a TPM.
pub trait Connection {
    /// The type returned if [`Connection::transact`] fails.
    ///
    /// This type does not include `TPM_RC` errors, only errors related
    /// to the connection itself. If the connection can never fail,
    /// this can be [`Infallible`](core::convert::Infallible).
    type Error: ConnectionError;
    /// Perform a command/response transaction with the TPM.
    ///
    /// Note that even if the response contains a `TPM_RC` error,
    /// this method still returns `Ok(())`. `Err` is only returned
    /// when we are unable to get a response at all.
    fn transact(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<(), Self::Error>;
}
