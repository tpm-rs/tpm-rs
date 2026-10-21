//! Low-level state traits implemented by cryptographic backend states.

use core::mem::MaybeUninit;

use super::{Active, CryptoError, Direction, ModeIv};

pub trait State: Sized {
    #[inline]
    fn cleanup_internal(&mut self) {}
}

pub trait Init: State {
    fn init_internal(slot: &mut MaybeUninit<Self>) -> Result<Active<'_, Self>, CryptoError>;
}

pub trait InitFrom<K: ?Sized>: State {
    fn init_internal<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &K,
    ) -> Result<Active<'a, Self>, CryptoError>;
}

pub trait Update: State {
    fn update_internal(&mut self, data: &[u8]) -> Result<(), CryptoError>;
}

pub trait Finalize<const N: usize>: State {
    fn finalize_internal(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError>;
}

pub trait Crypt: State {
    fn crypt_internal(
        &self,
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError>;
}

// Implementation for the never type !

impl State for ! {
    fn cleanup_internal(&mut self) {
        match *self {}
    }
}
impl Init for ! {
    fn init_internal(_: &mut MaybeUninit<Self>) -> Result<Active<'_, Self>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}
impl<K: ?Sized> InitFrom<K> for ! {
    fn init_internal<'a>(
        _: &'a mut MaybeUninit<Self>,
        _: &K,
    ) -> Result<Active<'a, Self>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}
impl Update for ! {
    fn update_internal(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        match *self {}
    }
}
impl<const N: usize> Finalize<N> for ! {
    fn finalize_internal(&mut self, _: &mut [u8; N]) -> Result<(), CryptoError> {
        match *self {}
    }
}
impl Crypt for ! {
    fn crypt_internal(&self, _: ModeIv<'_>, _: Direction, _: &mut [u8]) -> Result<(), CryptoError> {
        match *self {}
    }
}
