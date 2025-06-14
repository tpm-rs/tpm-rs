#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! A Deterministic Random Bit Generator(DRBG) mechanism based
//! on Hash Functions. Unless otherwise specified, references to section
//! come directly from
//! [NIST.SP.800-90Ar1](http://dx.doi.org/10.6028/NIST.SP.800-90Ar1).

mod props;
pub use props::{bits_to_bytes, HashDrbgProps};
