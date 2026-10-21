//! RAII handle for an initialized cryptographic state slot.

use core::mem::MaybeUninit;

use super::{Crypt, CryptoError, Direction, Finalize, Init, InitFrom, ModeIv, State, Update};

/// An active, initialized reference to a cryptographic state `S`.
///
/// Automatically invokes [`State::cleanup_internal`] when dropped.
pub struct Active<'a, S: State>(pub(super) &'a mut S);

impl<'a, S: State> Active<'a, S> {
    #[inline]
    pub fn new_internal(state: &'a mut S) -> Self {
        Self(state)
    }
    #[inline]
    pub fn new(slot: &'a mut MaybeUninit<S>) -> Result<Self, CryptoError>
    where
        S: Init,
    {
        S::init_internal(slot)
    }
    #[inline]
    pub fn new_from<K: ?Sized>(slot: &'a mut MaybeUninit<S>, key: &K) -> Result<Self, CryptoError>
    where
        S: InitFrom<K>,
    {
        S::init_internal(slot, key)
    }
    #[inline]
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>
    where
        S: Update,
    {
        self.0.update_internal(data)
    }
    #[inline]
    pub fn finalize<const N: usize>(self, out: &mut [u8; N]) -> Result<(), CryptoError>
    where
        S: Finalize<N>,
    {
        self.0.finalize_internal(out)
    }
    #[inline]
    pub fn crypt(
        &self,
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError>
    where
        S: Crypt,
    {
        self.0.crypt_internal(mode, dir, data)
    }
}

impl<S: State> Drop for Active<'_, S> {
    #[inline]
    fn drop(&mut self) {
        self.0.cleanup_internal();
    }
}
