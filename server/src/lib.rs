#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod handler;
pub mod platform;
pub mod req_resp;
pub mod service;
#[cfg(test)]
mod tests;
