//! [`Symmetric`] encryption and [`Cmac`].

use core::mem::MaybeUninit;

use cipher::{
    Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt,
    BlockSizeUser, InnerIvInit, IvState, KeyInit, KeySizeUser, StreamCipher, StreamCipherCore,
    StreamCipherCoreWrapper, consts::U16, inout::InOutBuf, typenum::Unsigned,
};
use tpm2::{
    AlgSym,
    crypto::{Active, Crypt, CryptoError, Direction, InitFrom, ModeIv, State},
};

const BLOCK_SIZE: usize = AlgSym::BLOCK_SIZE;

/// Splits block-mode `data` into 16-byte blocks, failing if it isn't
/// block-aligned (which [`ModeIv`] makes a precondition of [`Symmetric`]).
fn into_blocks(data: &mut [u8]) -> Result<InOutBuf<'_, '_, Block<aes::Aes128>>, CryptoError> {
    let (blocks, tail) = InOutBuf::from(data).into_chunks();
    if !tail.is_empty() {
        return Err(CryptoError::Internal);
    }
    Ok(blocks)
}

/// Applies a [`StreamCipherCore`] mode (`CTR` or `OFB`) to `data` and writes
/// the resulting chaining value back to `iv`.
fn stream_cipher<Core>(cipher: Core::Inner, iv: &mut [u8; BLOCK_SIZE], data: &mut [u8])
where
    Core: StreamCipherCore<BlockSize = U16> + InnerIvInit<IvSize = U16> + IvState<IvSize = U16>,
{
    let mut stream = StreamCipherCoreWrapper::from_core(Core::inner_iv_init(cipher, (&*iv).into()));
    stream.apply_keystream(data);
    *iv = stream.get_core().iv_state().into();
}

fn crypt<C>(cipher: C, mode: ModeIv<'_>, dir: Direction, data: &mut [u8]) -> Result<(), CryptoError>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
{
    match mode {
        // CTR and OFB are identical for encryption and decryption.
        ModeIv::Ctr(iv) => {
            stream_cipher::<ctr::CtrCore<C, ctr::flavors::Ctr128BE>>(cipher, iv, data);
        }
        ModeIv::Ofb(iv) => {
            stream_cipher::<ofb::OfbCore<C>>(cipher, iv, data);
        }
        ModeIv::Cfb(iv) => {
            let update_iv = |iv: &mut [u8; BLOCK_SIZE], ciphertext: &[u8]| {
                if let Some(last) = ciphertext.chunks(BLOCK_SIZE).next_back() {
                    iv[..last.len()].copy_from_slice(last);
                    iv[last.len()..].fill(0);
                }
            };
            match dir {
                Direction::Encrypt => {
                    cfb_mode::Encryptor::inner_iv_init(cipher, (&*iv).into()).encrypt(data);
                    update_iv(iv, data);
                }
                Direction::Decrypt => {
                    let init_iv = *iv;
                    update_iv(iv, data);
                    cfb_mode::Decryptor::inner_iv_init(cipher, (&init_iv).into()).decrypt(data);
                }
            }
        }
        ModeIv::Cbc(iv) => {
            let blocks = into_blocks(data)?;
            match dir {
                Direction::Encrypt => {
                    let mut mode = cbc::Encryptor::inner_iv_init(cipher, (&*iv).into());
                    mode.encrypt_blocks_inout(blocks);
                    *iv = mode.iv_state().into();
                }
                Direction::Decrypt => {
                    let mut mode = cbc::Decryptor::inner_iv_init(cipher, (&*iv).into());
                    mode.decrypt_blocks_inout(blocks);
                    *iv = mode.iv_state().into();
                }
            }
        }
        ModeIv::Ecb => {
            let blocks = into_blocks(data)?;
            match dir {
                Direction::Encrypt => cipher.encrypt_blocks_inout(blocks),
                Direction::Decrypt => cipher.decrypt_blocks_inout(blocks),
            }
        }
    }
    Ok(())
}

/// Symmetric cipher key wrapping a block cipher.
#[derive(Clone)]
pub struct AesKey<C>(pub(crate) C);

impl<C> State for AesKey<C> {}

impl<C: KeyInit + KeySizeUser, const N: usize> InitFrom<[u8; N]> for AesKey<C> {
    #[inline(never)]
    fn init_internal<'a>(
        slot: &'a mut MaybeUninit<Self>,
        key: &[u8; N],
    ) -> Result<Active<'a, Self>, CryptoError> {
        const { assert!(<C as KeySizeUser>::KeySize::USIZE == N) };
        let cipher = C::new_from_slice(key).map_err(|_| CryptoError::Internal)?;
        Ok(Active::new_internal(slot.write(Self(cipher))))
    }
}

impl<C> Crypt for AesKey<C>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    #[inline(never)]
    fn crypt_internal(
        &self,
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(self.0.clone(), mode, dir, data)
    }
}
