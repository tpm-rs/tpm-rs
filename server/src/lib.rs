#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)] // rustc >= 1.90.0 (1159e78c4 2025-09-14)

mod buffers;
mod crypto;
mod error;
mod handler;
pub mod platform;
mod req_resp;
#[cfg(test)]
mod tests;
mod tpmctx;
pub use error::ServerError;
pub use tpmctx::TpmContext;
