//! # TPM2 Implementation Core
//!
//! <div class="warning">
//! This code is unstable and there are no guarantees of stability at this time.
//! </div>
//!
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

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
