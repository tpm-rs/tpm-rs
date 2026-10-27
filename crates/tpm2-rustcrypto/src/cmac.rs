use cipher::consts::U16;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt};
use cipher::{BlockSizeUser, KeySizeUser, array::ArraySize};
use cmac::Cmac;
use hmac::Mac;
use tpm2::crypto::{CryptoError, backend::CmacState};

/// CMAC Wrapper
pub struct CmacWrapper<
    C: BlockCipherEncrypt + BlockCipherDecrypt + BlockSizeUser<BlockSize = U16> + Clone,
>(Cmac<C>);

impl<C, const KEY_SIZE: usize> CmacState<KEY_SIZE> for CmacWrapper<C>
where
    C: BlockCipherEncrypt
        + BlockCipherDecrypt
        + BlockSizeUser<BlockSize = U16>
        + KeySizeUser
        + Clone
        + cipher::KeyInit,
    C::KeySize: ArraySize<ArrayType<u8> = [u8; KEY_SIZE]>,
{
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        use cipher::KeyInit;
        Cmac::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut tpm2::crypto::Block) -> Result<(), CryptoError> {
        let result = self.0.clone().finalize().into_bytes();
        out.copy_from_slice(&result);
        Ok(())
    }
}
