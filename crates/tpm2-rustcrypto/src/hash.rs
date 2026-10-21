//! [`Hash`], [`Hmac`], and the streaming contexts.

use core::mem::MaybeUninit;

use hmac::{
    EagerHash,
    digest::{Digest, KeyInit, Mac, OutputSizeUser, typenum::Unsigned},
};
use tpm2::crypto::{Active, CryptoError, Finalize, Init, InitFrom, State, Update};

/// Streaming hash context wrapping a RustCrypto [`Digest`].
pub struct HashWrapper<D>(D);

impl<D: Digest> State for HashWrapper<D> {}

impl<D: Digest> Init for HashWrapper<D> {
    #[inline(never)]
    fn init_internal(slot: &mut MaybeUninit<Self>) -> Result<Active<'_, Self>, CryptoError> {
        let state = Self(Digest::new());
        Ok(Active::new_internal(slot.write(state)))
    }
}

impl<D: Digest> Update for HashWrapper<D> {
    #[inline(never)]
    fn update_internal(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl<D: Digest, const N: usize> Finalize<N> for HashWrapper<D> {
    #[inline(never)]
    fn finalize_internal(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        const { assert!(<D as OutputSizeUser>::OutputSize::USIZE == N) };
        let hasher = core::mem::replace(&mut self.0, Digest::new());
        out.copy_from_slice(&hasher.finalize());
        Ok(())
    }
}

/// Streaming HMAC context wrapping a RustCrypto [`hmac::Hmac`].
pub struct HmacWrapper<D: EagerHash>(pub(crate) hmac::Hmac<D>);

impl<D: EagerHash> State for HmacWrapper<D> {}

impl<D: EagerHash> InitFrom<[u8]> for HmacWrapper<D> {
    #[inline(never)]
    fn init_internal<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8],
    ) -> Result<Active<'a, Self>, CryptoError> {
        let mac = hmac::Hmac::<D>::new_from_slice(key).map_err(|_| CryptoError::Internal)?;
        Ok(Active::new_internal(slot.write(Self(mac))))
    }
}

impl<D: EagerHash> Update for HmacWrapper<D> {
    #[inline(never)]
    fn update_internal(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Mac::update(&mut self.0, data);
        Ok(())
    }
}

impl<D: EagerHash, const N: usize> Finalize<N> for HmacWrapper<D> {
    #[inline(never)]
    fn finalize_internal(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        const { assert!(<D as OutputSizeUser>::OutputSize::USIZE == N) };
        let mac = self.0.clone();
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }
}
