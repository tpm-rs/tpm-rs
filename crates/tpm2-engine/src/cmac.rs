//! Portable, serializable CMAC state (`TPM_ALG_CMAC`, NIST SP 800-38B) over the block ciphers of
//! the TPM, for `TPM2_MAC` and the MAC sequences of `TPM2_MAC_Start` (which `TPM2_ContextSave`
//! must be able to save, so the state cannot be an opaque context of the crypto backend).
//!
//! The state is that of the TCG reference's `tpmCmacState_t` (`CryptCmac.c`): the chaining value
//! `iv`, into which the input is XORed, and the number of bytes of the current block in it. A
//! full block is only encrypted when more data follows, so that [`CmacState::finalize`] can apply
//! the subkey K1 (complete last block) or pad the block and apply K2 before the final encryption.
//!
//! The single-block encryption `E_K(x)` uses the backend's CFB mode (the mode every backend
//! implements): encrypting one zero block in CFB mode with the IV `x` yields `E_K(x)`.

use crate::self_test::Tested;
use tpm2::AlgSym;
use tpm2::crypto::{CipherInput, Crypto, CryptoError, Direction, SymmetricKey};

/// The block size of the TPM's block ciphers (`AlgSym::BLOCK_SIZE`).
const BLOCK: usize = AlgSym::BLOCK_SIZE;

/// The state of a CMAC computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmacState {
    /// The block cipher and key size (the `symmetric` of the SYMCIPHER key).
    pub alg: AlgSym,
    /// The key (the first `alg.key_bytes()` octets are used).
    key: [u8; AlgSym::MAX_KEY_BYTES],
    /// The chaining value with the XORed input of the current block.
    iv: [u8; BLOCK],
    /// The number of input bytes XORed into `iv` since its last encryption (`0..=16`).
    bcount: u8,
}

impl CmacState {
    /// The size of [`Self::serialize`]'s output.
    pub const SERIALIZED_SIZE: usize = 2 + 2 + AlgSym::MAX_KEY_BYTES + BLOCK + 1;

    /// Starts a CMAC with the block cipher `alg` and `key` (`CryptCmacStart()`), or `None` if
    /// `key` does not have the key size of `alg` (`CryptSmacStart()` fails then).
    pub fn new(alg: AlgSym, key: &[u8]) -> Option<Self> {
        if key.len() != alg.key_bytes() {
            return None;
        }
        let mut k = [0u8; AlgSym::MAX_KEY_BYTES];
        k[..key.len()].copy_from_slice(key);
        Some(Self {
            alg,
            key: k,
            iv: [0u8; BLOCK],
            bcount: 0,
        })
    }

    /// The key.
    fn key(&self) -> &[u8] {
        &self.key[..self.alg.key_bytes()]
    }

    /// `block = E_K(block)` with the crypto backend `s` (after the test of the block cipher).
    fn encrypt_block<C: Crypto>(
        &self,
        s: &Tested<'_, C>,
        block: &mut [u8; BLOCK],
    ) -> Result<(), CryptoError> {
        let key = SymmetricKey::new(self.alg, self.key()).ok_or(CryptoError::Internal)?;
        let mut iv = *block;
        block.fill(0);
        s.crypt(key, Direction::Encrypt, CipherInput::Cfb(&mut iv, block))
    }

    /// Adds `data` to the CMAC (`CryptCmacData()`).
    pub fn update<C: Crypto>(
        &mut self,
        s: &Tested<'_, C>,
        mut data: &[u8],
    ) -> Result<(), CryptoError> {
        while !data.is_empty() {
            if usize::from(self.bcount) == BLOCK {
                let mut iv = self.iv;
                self.encrypt_block(s, &mut iv)?;
                self.iv = iv;
                self.bcount = 0;
            }
            let start = usize::from(self.bcount);
            let take = data.len().min(BLOCK - start);
            for (dst, src) in self.iv[start..start + take].iter_mut().zip(&data[..take]) {
                *dst ^= src;
            }
            self.bcount += take as u8;
            data = &data[take..];
        }
        Ok(())
    }

    /// Completes the CMAC and returns the 16-octet MAC (`CryptCmacEnd()`).
    pub fn finalize<C: Crypto>(mut self, s: &Tested<'_, C>) -> Result<[u8; BLOCK], CryptoError> {
        // L = E_K(0^128); K1 = dbl(L); K2 = dbl(K1).
        let mut subkey = [0u8; BLOCK];
        self.encrypt_block(s, &mut subkey)?;
        double(&mut subkey);
        if usize::from(self.bcount) < BLOCK {
            // An incomplete (or empty) last block: pad it with 10* and use K2.
            self.iv[usize::from(self.bcount)] ^= 0x80;
            double(&mut subkey);
        }
        for (dst, k) in self.iv.iter_mut().zip(&subkey) {
            *dst ^= k;
        }
        let mut mac = self.iv;
        self.encrypt_block(s, &mut mac)?;
        Ok(mac)
    }

    /// Serializes the state ([`Self::SERIALIZED_SIZE`] octets): algorithm, key bits, key, chaining
    /// value and block count.
    pub fn serialize(&self, out: &mut [u8]) -> usize {
        out[..2].copy_from_slice(&self.alg.algorithm().id().to_be_bytes());
        out[2..4].copy_from_slice(&self.alg.key_bits().to_be_bytes());
        let mut offset = 4;
        out[offset..offset + AlgSym::MAX_KEY_BYTES].copy_from_slice(&self.key);
        offset += AlgSym::MAX_KEY_BYTES;
        out[offset..offset + BLOCK].copy_from_slice(&self.iv);
        offset += BLOCK;
        out[offset] = self.bcount;
        offset + 1
    }

    /// Deserializes a state written by [`Self::serialize`], or `None` if it is malformed.
    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SERIALIZED_SIZE {
            return None;
        }
        let algorithm = tpm2::Alg::new(u16::from_be_bytes([buf[0], buf[1]]));
        let key_bits = u16::from_be_bytes([buf[2], buf[3]]);
        let alg = AlgSym::from_parts(algorithm, key_bits).ok()?;
        let mut offset = 4;
        let mut key = [0u8; AlgSym::MAX_KEY_BYTES];
        key.copy_from_slice(&buf[offset..offset + AlgSym::MAX_KEY_BYTES]);
        offset += AlgSym::MAX_KEY_BYTES;
        let mut iv = [0u8; BLOCK];
        iv.copy_from_slice(&buf[offset..offset + BLOCK]);
        offset += BLOCK;
        let bcount = buf[offset];
        if usize::from(bcount) > BLOCK {
            return None;
        }
        Some(Self {
            alg,
            key,
            iv,
            bcount,
        })
    }

    /// The parts of the state as the TCG reference's `tpmCmacState_t` holds them: the key, the
    /// chaining value `iv` and the block count `bcount`.
    #[cfg_attr(not(feature = "cmac"), allow(dead_code))]
    pub(crate) fn parts(&self) -> (&[u8], &[u8; BLOCK], u8) {
        (self.key(), &self.iv, self.bcount)
    }

    /// A state from the parts of a `tpmCmacState_t` ([`Self::parts`]), or `None` if `key` does
    /// not have the key size of `alg` or `bcount` exceeds the block size.
    #[cfg_attr(not(feature = "cmac"), allow(dead_code))]
    pub(crate) fn from_parts(alg: AlgSym, key: &[u8], iv: [u8; BLOCK], bcount: u8) -> Option<Self> {
        if usize::from(bcount) > BLOCK {
            return None;
        }
        let mut state = Self::new(alg, key)?;
        state.iv = iv;
        state.bcount = bcount;
        Some(state)
    }
}

/// The doubling of SP 800-38B (`ShiftLeft()` and the XOR with `0x87` of `CryptCmacEnd()`):
/// `block << 1`, XORed with `R_128 = 0^120 || 10000111` if the most significant bit was set.
fn double(block: &mut [u8; BLOCK]) {
    let msb = block[0] & 0x80 != 0;
    for i in 0..BLOCK {
        let next = if i + 1 < BLOCK { block[i + 1] >> 7 } else { 0 };
        block[i] = (block[i] << 1) | next;
    }
    if msb {
        block[BLOCK - 1] ^= 0x87;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[cfg(feature = "dev_crypto_bssl")]
    use tpm2_crypto_bssl::BsslCryptoProvider as Provider;
    #[cfg(all(feature = "dev_crypto_crux", not(feature = "dev_crypto_bssl")))]
    use tpm2_crypto_crux::CruxCryptoProvider as Provider;
    #[cfg(all(
        feature = "dev_crypto_rust",
        not(any(feature = "dev_crypto_bssl", feature = "dev_crypto_crux"))
    ))]
    use tpm2_crypto_rust::RustCryptoProvider as Provider;

    use crate::self_test::SelfTestState;

    /// The 64-octet message of the SP 800-38B / RFC 4493 examples.
    const MESSAGE: [u8; 64] = hex!(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    );

    /// The AES-128 examples of SP 800-38B (D.1) / RFC 4493: lengths 0, 16, 40 and 64.
    #[test]
    fn aes128_matches_sp800_38b_examples() {
        let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let cases: [(usize, [u8; 16]); 4] = [
            (0, hex!("bb1d6929e95937287fa37d129b756746")),
            (16, hex!("070a16b46b4d4144f79bdd9dd04a287c")),
            (40, hex!("dfa66747de9ae63030ca32611497c827")),
            (64, hex!("51f0bebf7e3b9d92fc49741779363cfe")),
        ];
        let state = SelfTestState::default();
        let s = Tested::<Provider>::new(&state);
        for (len, expected) in cases {
            // One update, and one update per octet.
            let mut whole = CmacState::new(AlgSym::Aes128, &key).unwrap();
            whole.update(&s, &MESSAGE[..len]).unwrap();
            assert_eq!(whole.finalize(&s).unwrap(), expected, "len {len}");
            let mut bytewise = CmacState::new(AlgSym::Aes128, &key).unwrap();
            for b in &MESSAGE[..len] {
                bytewise.update(&s, core::slice::from_ref(b)).unwrap();
            }
            assert_eq!(bytewise.finalize(&s).unwrap(), expected, "len {len}");
        }
    }

    /// The AES-256 examples of SP 800-38B (D.3): lengths 0 and 64, split across a
    /// serialization round trip.
    #[test]
    fn aes256_matches_sp800_38b_examples_across_serialization() {
        let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let self_test = SelfTestState::default();
        let s = Tested::<Provider>::new(&self_test);
        let mut state = CmacState::new(AlgSym::Aes256, &key).unwrap();
        assert_eq!(
            state.finalize(&s).unwrap(),
            hex!("028962f61b7bf89efc6b551f4667d983")
        );
        state.update(&s, &MESSAGE[..23]).unwrap();
        let mut buf = [0u8; CmacState::SERIALIZED_SIZE];
        assert_eq!(state.serialize(&mut buf), CmacState::SERIALIZED_SIZE);
        let mut state = CmacState::deserialize(&buf).unwrap();
        state.update(&s, &MESSAGE[23..]).unwrap();
        assert_eq!(
            state.finalize(&s).unwrap(),
            hex!("e1992190549f6ed5696a2c056c315410")
        );
    }

    /// A key of the wrong size cannot start a CMAC.
    #[test]
    fn wrong_key_size_is_rejected() {
        assert!(CmacState::new(AlgSym::Aes128, &[0u8; 32]).is_none());
        assert!(CmacState::new(AlgSym::Aes256, &[0u8; 16]).is_none());
    }

    /// A serialized state with a block count beyond one block is malformed.
    #[test]
    fn malformed_serialization_is_rejected() {
        let state = CmacState::new(AlgSym::Aes128, &[0u8; 16]).unwrap();
        let mut buf = [0u8; CmacState::SERIALIZED_SIZE];
        state.serialize(&mut buf);
        buf[CmacState::SERIALIZED_SIZE - 1] = 17;
        assert!(CmacState::deserialize(&buf).is_none());
        assert!(CmacState::deserialize(&buf[..10]).is_none());
    }
}
