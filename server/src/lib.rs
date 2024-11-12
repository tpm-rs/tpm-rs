#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod buffers;
mod handler;
pub mod platform;
mod req_resp;
#[cfg(test)]
mod tests;
mod tpmctx;
pub use tpmctx::TpmContext;
