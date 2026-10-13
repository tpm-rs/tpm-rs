//! This module defines [`Session`] and [`AuthorizationArea`] for attaching
//! zero to three authorization sessions (`()`, `S1`, `(S1, S2)`, or
//! `(S1, S2, S3)`) to a TPM command.
mod authorization_area;
mod password;
mod session;
#[cfg(test)]
mod tests;

pub use authorization_area::*;
pub use password::*;
pub use session::*;
