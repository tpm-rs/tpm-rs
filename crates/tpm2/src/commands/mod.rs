//! TPM2 Commands and Responses
//!
//! This module contains the structures for TPM2 [`Command`]s and their
//! corresponding [`Command::Response`]s.
//!
//! Command structs appear without the leading `TPM2_`. For example, the
//! `TPM2_GetRandom` command in the spec corresponds to [`GetRandom`].
//!
//! Using the [`Command::Response`] associated type is preffered to using the
//! standalone type in the [`responses`] sub-module. For example, when referring
//! to the TPM2_GetRandom Response, prefer [`GetRandom::Response`]
//! for `TPM2_GetRandom` should use ``
//! Generally, the type of a command's
//! response

/// TPM2 Responses
///
/// These types are defined here because they cannot be private and still
/// have docstrings. However, they should generally be used via
/// [`Command`]
pub mod responses;

/// TODO: Flesh out this trait
pub trait Command {
    type Response<'a>;
}

/// `TPM2_GetRandom`
///
/// Returns the next `bytesRequested` octets from the random number generator (RNG).
#[doc(alias("TPM2_GetRandom", "GetRandom_In"))]
#[derive(Clone, Copy, Debug)]
pub struct GetRandom {
    pub bytes_requested: u16,
}

// TODO: Implement these with a proc-macro or macro_rules!
impl Command for GetRandom {
    type Response<'a> = responses::GetRandom<'a>;
}
