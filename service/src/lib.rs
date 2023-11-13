#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod buffer;
pub mod crypto;
pub mod error;
mod handler;
pub mod service;
#[cfg(test)]
mod tests;

use open_enum::open_enum;

/// The TPM_CC command codes
#[open_enum]
#[repr(u32)]
pub enum Command {
    /// Gets a random sequence of bytes (`TPM_CC_GetRandom`).
    GetRandom = 0x17B,
}
