//! Cryptography Interfaces for TPM implementations and clients
use crate::Alg;

mod hash;
mod mac;
pub use {hash::*, mac::*};

pub trait Base {
    type Error;

    fn unimplemented(&self, alg: Alg) -> Self::Error;
}

pub trait Update<Error> {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
}
pub trait Finalize<const N: usize, Error> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), Error>;
}

impl<Error> Update<Error> for ! {
    fn update(&mut self, _: &[u8]) -> Result<(), Error> {
        match *self {}
    }
}
impl<const N: usize, Error> Finalize<N, Error> for ! {
    fn finalize(self, _: &mut [u8; N]) -> Result<(), Error> {
        match self {}
    }
}
