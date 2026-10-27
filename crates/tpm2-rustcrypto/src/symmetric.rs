//! [`Symmetric`](tpm2::crypto::backend::Symmetric) encryption and decryption.

use cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, BlockSizeUser,
    InnerIvInit, IvState, KeyInit, KeySizeUser, StreamCipher, StreamCipherCore,
    StreamCipherCoreWrapper,
    array::{Array, ArraySize},
    consts::U16,
};
use tpm2::crypto::{Block, CryptoError, Direction, backend::SymmetricState};

/// Converts `tpm2` blocks into RustCrypto blocks (without copying).
fn blocks(data: &mut [Block]) -> &mut [Array<u8, U16>] {
    Array::cast_slice_from_core_mut(data)
}

/// Applies a [`StreamCipherCore`] mode (CTR or OFB) to `data` and writes the
/// resulting chaining value back to `iv`.
fn stream_cipher<Core>(cipher: Core::Inner, iv: &mut Block, data: &mut [u8])
where
    Core: StreamCipherCore<BlockSize = U16> + InnerIvInit<IvSize = U16> + IvState<IvSize = U16>,
{
    let mut stream = StreamCipherCoreWrapper::from_core(Core::inner_iv_init(cipher, (&*iv).into()));
    stream.apply_keystream(data);
    *iv = stream.get_core().iv_state().into();
}

/// Copies the final (possibly partial) block of `ciphertext` into the start of
/// `iv`, leaving `iv` unchanged if `ciphertext` is empty.
fn copy_last_block(iv: &mut Block, ciphertext: &[u8]) {
    let (blocks, tail): (&[Block], _) = ciphertext.as_chunks();
    let last = match blocks.last() {
        Some(block) if tail.is_empty() => block.as_slice(),
        _ => tail,
    };
    iv.iter_mut().zip(last).for_each(|(i, c)| *i = *c);
}

/// Symmetric cipher key wrapping a RustCrypto block cipher.
pub struct AesKey<C>(C);

impl<C, const KEY_SIZE: usize> SymmetricState<KEY_SIZE> for AesKey<C>
where
    C: KeyInit
        + KeySizeUser
        + BlockSizeUser<BlockSize = U16>
        + BlockCipherEncrypt
        + BlockCipherDecrypt,
    C::KeySize: ArraySize<ArrayType<u8> = [u8; KEY_SIZE]>,
{
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        Ok(Self(C::new(key.into())))
    }

    fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        stream_cipher::<ctr::CtrCore<&C, ctr::flavors::Ctr128BE>>(&self.0, iv, data);
        Ok(())
    }

    fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        stream_cipher::<ofb::OfbCore<&C>>(&self.0, iv, data);
        Ok(())
    }

    fn cbc(&self, dir: Direction, iv: &mut Block, data: &mut [Block]) -> Result<(), CryptoError> {
        let data = blocks(data);
        match dir {
            Direction::Encrypt => {
                let mut mode = cbc::Encryptor::inner_iv_init(&self.0, (&*iv).into());
                mode.encrypt_blocks(data);
                *iv = mode.iv_state().into();
            }
            Direction::Decrypt => {
                let mut mode = cbc::Decryptor::inner_iv_init(&self.0, (&*iv).into());
                mode.decrypt_blocks(data);
                *iv = mode.iv_state().into();
            }
        }
        Ok(())
    }

    fn cfb(&self, dir: Direction, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        // `cfb_mode` doesn't report the final ciphertext block, so copy it
        // from the ciphertext.
        match dir {
            Direction::Encrypt => {
                cfb_mode::Encryptor::inner_iv_init(&self.0, (&*iv).into()).encrypt(data);
                copy_last_block(iv, data);
            }
            Direction::Decrypt => {
                let mode = cfb_mode::Decryptor::inner_iv_init(&self.0, (&*iv).into());
                copy_last_block(iv, data);
                mode.decrypt(data);
            }
        }
        Ok(())
    }

    fn ecb(&self, dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
        let data = blocks(data);
        match dir {
            Direction::Encrypt => self.0.encrypt_blocks(data),
            Direction::Decrypt => self.0.decrypt_blocks(data),
        }
        Ok(())
    }
}
