//! TPM 2.0 Commands and Request/Response Protocol Layout
//!
//! This module defines the request and response structures, handle lists,
//! and [`Command`] / [`Message`] trait implementations for TPM 2.0 commands.
use crate::{Handle, Marshal, TpmCc, errors::UnmarshalError};

/// Common trait for a TPM 2.0 command [`Message`].
pub trait Command: Message {
    /// The [command code](TpmCc) for this command.
    const CMD_CODE: TpmCc;
    /// The corresponding response [`Message`] for this command.
    type Response<'a>: UnmarshalMessage<'a>;
}

/// Trait implemented for every [`Command`] and [`Command::Response`].
///
/// Note that the [`Marshal`] supertrait marshals only the parameter area of the
/// message; the handle area is accessed via [`Message::handles`].
pub trait Message: Marshal {
    /// Fixed-size array of [`Handle`]s in this message's handle area (`[Handle; N]`).
    type Handles: AsRef<[Handle]> + AsMut<[Handle]> + Default + Copy;
    /// Returns the handles in this message's handle area.
    fn handles(&self) -> Self::Handles;
}

/// Trait for unmarshaling a [`Message`] from its handle area and parameter bytes.
pub trait UnmarshalMessage<'a>: Message {
    /// Unmarshals the message's parameters from `src` and combines them with `handles`.
    fn unmarshal_with_handles(
        handles: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError>;
}

impl Message for () {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl UnmarshalMessage<'_> for () {
    fn unmarshal_with_handles([]: Self::Handles, _: &mut &'_ [u8]) -> Result<Self, UnmarshalError> {
        Ok(())
    }
}

mod random;
mod startup;

pub use {
    random::{GetRandom, StirRandom},
    startup::{Shutdown, Startup},
};

/// Response [`Message`] types corresponding to commands in [`crate::commands`].
pub mod responses {
    pub use super::random::GetRandomRsp as GetRandom;
}
