#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod handler;
pub mod platform;
pub mod req_resp;
#[cfg(test)]
mod tests;
pub mod tpmctx;
