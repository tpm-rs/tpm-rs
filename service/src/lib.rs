#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod buffer;
pub mod crypto;
mod handler;
pub mod service;
#[cfg(test)]
mod tests;
