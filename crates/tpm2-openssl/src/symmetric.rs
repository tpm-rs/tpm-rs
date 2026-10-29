use openssl::symm::{Cipher, Crypter, Mode};
use tpm2::crypto::{
    Block, CryptoError, Direction,
    backend::{Symmetric, SymmetricState},
};

macro_rules! impl_symmetric {
    ($name:ident, $ecb:ident, $cbc:ident, $cfb:ident, $ofb:ident, $key_size:expr) => {
        pub struct $name {
            key: [u8; $key_size],
        }

        impl SymmetricState<$key_size> for $name {
            fn init(key: &[u8; $key_size]) -> Result<Self, CryptoError> {
                let mut k = [0u8; $key_size];
                k.copy_from_slice(key);
                Ok(Self { key: k })
            }

            fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let blocks = data.len().div_ceil(16);
                let mut ivs = Vec::with_capacity(blocks * 16);
                let mut current_iv = *iv;
                for _ in 0..blocks {
                    ivs.extend_from_slice(&current_iv);
                    let mut val = u128::from_be_bytes(current_iv);
                    val = val.wrapping_add(1);
                    current_iv = val.to_be_bytes();
                }
                *iv = current_iv;

                let mut ecb = Crypter::new(Cipher::$ecb(), Mode::Encrypt, &self.key, None)
                    .map_err(|_| CryptoError::Internal)?;
                ecb.pad(false);
                let mut keystream = vec![0u8; ivs.len() + 16];
                let n1 = ecb
                    .update(&ivs, &mut keystream)
                    .map_err(|_| CryptoError::Internal)?;
                let _ = ecb
                    .finalize(&mut keystream[n1..])
                    .map_err(|_| CryptoError::Internal)?;

                for i in 0..data.len() {
                    data[i] ^= keystream[i];
                }
                Ok(())
            }

            fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let mut c = Crypter::new(
                    Cipher::$ofb(),
                    Mode::Encrypt,
                    &self.key,
                    Some(iv.as_slice()),
                )
                .map_err(|_| CryptoError::Internal)?;
                c.pad(false);
                let mut out = vec![0u8; data.len() + 16];
                let count = c
                    .update(data, &mut out)
                    .map_err(|_| CryptoError::Internal)?;
                let rest = c
                    .finalize(&mut out[count..])
                    .map_err(|_| CryptoError::Internal)?;
                data.copy_from_slice(&out[..count + rest]);

                let blocks = data.len().div_ceil(16);
                let mut current_iv = *iv;
                let mut ecb = Crypter::new(Cipher::$ecb(), Mode::Encrypt, &self.key, None)
                    .map_err(|_| CryptoError::Internal)?;
                ecb.pad(false);
                for _ in 0..blocks {
                    let mut next_iv = [0u8; 32];
                    let n1 = ecb
                        .update(&current_iv, &mut next_iv)
                        .map_err(|_| CryptoError::Internal)?;
                    let _ = ecb
                        .finalize(&mut next_iv[n1..])
                        .map_err(|_| CryptoError::Internal)?;
                    current_iv.copy_from_slice(&next_iv[..16]);
                }
                *iv = current_iv;
                Ok(())
            }

            fn cbc(
                &self,
                dir: Direction,
                iv: &mut Block,
                data: &mut [Block],
            ) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let mode = match dir {
                    Direction::Encrypt => Mode::Encrypt,
                    Direction::Decrypt => Mode::Decrypt,
                };
                let last_ciphertext = if dir == Direction::Decrypt {
                    Some(data[data.len() - 1])
                } else {
                    None
                };

                let data_u8 = unsafe {
                    core::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u8, data.len() * 16)
                };

                let mut c = Crypter::new(Cipher::$cbc(), mode, &self.key, Some(iv.as_slice()))
                    .map_err(|_| CryptoError::Internal)?;
                c.pad(false);
                let mut out = vec![0u8; data_u8.len() + 16];
                let count = c
                    .update(data_u8, &mut out)
                    .map_err(|_| CryptoError::Internal)?;
                let rest = c
                    .finalize(&mut out[count..])
                    .map_err(|_| CryptoError::Internal)?;
                data_u8.copy_from_slice(&out[..count + rest]);

                if dir == Direction::Encrypt {
                    iv.copy_from_slice(&data_u8[data_u8.len() - 16..]);
                } else {
                    *iv = last_ciphertext.unwrap();
                }
                Ok(())
            }

            fn cfb(
                &self,
                dir: Direction,
                iv: &mut Block,
                data: &mut [u8],
            ) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let mode = match dir {
                    Direction::Encrypt => Mode::Encrypt,
                    Direction::Decrypt => Mode::Decrypt,
                };

                let mut saved_ct = vec![0u8; data.len()];
                if dir == Direction::Decrypt {
                    saved_ct.copy_from_slice(data);
                }

                let mut c = Crypter::new(Cipher::$cfb(), mode, &self.key, Some(iv.as_slice()))
                    .map_err(|_| CryptoError::Internal)?;
                c.pad(false);
                let mut out = vec![0u8; data.len() + 16];
                let count = c
                    .update(data, &mut out)
                    .map_err(|_| CryptoError::Internal)?;
                let rest = c
                    .finalize(&mut out[count..])
                    .map_err(|_| CryptoError::Internal)?;
                data.copy_from_slice(&out[..count + rest]);

                let ct = if dir == Direction::Encrypt {
                    data
                } else {
                    &mut saved_ct
                };
                let len = ct.len();
                let last_block_len = if len % 16 == 0 { 16 } else { len % 16 };
                let last_block_start = len - last_block_len;
                iv[..last_block_len].copy_from_slice(&ct[last_block_start..]);
                Ok(())
            }

            fn ecb(&self, dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let mode = match dir {
                    Direction::Encrypt => Mode::Encrypt,
                    Direction::Decrypt => Mode::Decrypt,
                };
                let data_u8 = unsafe {
                    core::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u8, data.len() * 16)
                };
                let mut c = Crypter::new(Cipher::$ecb(), mode, &self.key, None)
                    .map_err(|_| CryptoError::Internal)?;
                c.pad(false);
                let mut out = vec![0u8; data_u8.len() + 16];
                let count = c
                    .update(data_u8, &mut out)
                    .map_err(|_| CryptoError::Internal)?;
                let rest = c
                    .finalize(&mut out[count..])
                    .map_err(|_| CryptoError::Internal)?;
                data_u8.copy_from_slice(&out[..count + rest]);
                Ok(())
            }
        }
    };
}

impl_symmetric!(
    SymAes128,
    aes_128_ecb,
    aes_128_cbc,
    aes_128_cfb128,
    aes_128_ofb,
    16
);
impl_symmetric!(
    SymAes192,
    aes_192_ecb,
    aes_192_cbc,
    aes_192_cfb128,
    aes_192_ofb,
    24
);
impl_symmetric!(
    SymAes256,
    aes_256_ecb,
    aes_256_cbc,
    aes_256_cfb128,
    aes_256_ofb,
    32
);
impl_symmetric!(SymSm4_128, sm4_ecb, sm4_cbc, sm4_cfb128, sm4_ofb, 16);
impl_symmetric!(
    SymCamellia128,
    camellia_128_ecb,
    camellia_128_cbc,
    camellia_128_cfb128,
    camellia_128_ofb,
    16
);
impl_symmetric!(
    SymCamellia192,
    camellia_192_ecb,
    camellia_192_cbc,
    camellia_192_cfb128,
    camellia_192_ofb,
    24
);
impl_symmetric!(
    SymCamellia256,
    camellia_256_ecb,
    camellia_256_cbc,
    camellia_256_cfb128,
    camellia_256_ofb,
    32
);

impl Symmetric for super::OpensslBackend {
    type Aes128 = SymAes128;
    type Aes192 = SymAes192;
    type Aes256 = SymAes256;
    type Sm4_128 = SymSm4_128;
    type Camellia128 = SymCamellia128;
    type Camellia192 = SymCamellia192;
    type Camellia256 = SymCamellia256;
}
