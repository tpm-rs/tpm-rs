//! This module contains a collection of traits setting lower bounds
//! on how many sessions are allowed in an authorization area.
//! In particular the this module defines the following traits
//! - [`AuthorizationArea`]: A trait for an authorization area with
//!   (possibly zero) unknown number of sessions up to three.
//! - [`AuthorizationArea1Plus`]: A trait for an authorization area
//!   with at least one session and at most three sessions
//! - [`AuthorizationArea2Plus`]: A trait for an authorization area
//!   with either two or three sessions.
//!
//! The concept of a session is defined by [`Session`].
//!
//! For command implementor, they need use the right trait from [`AuthorizationArea`],
//! [`AuthorizationArea1Plus`], and [`AuthorizationArea2Plus`]. Additionally the expected
//! authorization area type can be [`unit`] if no session is be expectd, or a tuple of
//! exactly three sessions if exactly three sessions are to be expected.
//!
//! For command users, they may pass a single session or a tuple of two or three sessions
//! depending on the command. The compiler should be able to catch cases where unsupported number
//! of sessions is being passed and return a compile time error.
mod authorization_area;
mod nosession;
mod password;
mod session;
#[cfg(test)]
mod tests;

pub use authorization_area::*;
pub use nosession::*;
pub use password::*;
pub use session::*;
