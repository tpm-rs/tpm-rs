//! [`Symmetric`] for [`CruxCryptoProvider`].
//!
//! AES-128, AES-192, AES-256 and Camellia-128, Camellia-192, Camellia-256 in the CTR, OFB, CBC,
//! CFB and ECB modes, with the mode code shared with the Rust backend
//! ([`tpm2_crypto_rust::RustCryptoCipher`], see [`tpm2_crypto_rust::symmetric`] for the IV
//! chaining).
//!
//! The other block cipher (SM4) is not supported (`!`).
//!
//! libcrux has no AES-CBC/CTR/OFB/ECB or Camellia, so the block ciphers are the RustCrypto
//! `aes` and `camellia` crates.

use crate::CruxCryptoProvider;
use tpm2::crypto::backend::Symmetric;
use tpm2_crypto_rust::RustCryptoCipher;

impl Symmetric for CruxCryptoProvider {
    type Aes128 = RustCryptoCipher<aes::Aes128>;
    type Aes192 = RustCryptoCipher<aes::Aes192>;
    type Aes256 = RustCryptoCipher<aes::Aes256>;
    type Sm4_128 = !;
    type Camellia128 = RustCryptoCipher<camellia::Camellia128>;
    type Camellia192 = RustCryptoCipher<camellia::Camellia192>;
    type Camellia256 = RustCryptoCipher<camellia::Camellia256>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use tpm2::AlgSym;
    use tpm2::TpmiAlgCipherMode;
    use tpm2::crypto::backend::SymmetricState;
    use tpm2::crypto::{CipherInput, CryptoError, Direction, SymmetricKey};

    /// NIST SP 800-38A, F.3.13 (CFB128-AES128.Encrypt): key.
    const KEY_128: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    /// NIST SP 800-38A, F.3.15 (CFB128-AES192.Encrypt): key.
    const KEY_192: [u8; 24] = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    /// NIST SP 800-38A, F.3.17 (CFB128-AES256.Encrypt): key.
    const KEY_256: [u8; 32] =
        hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    /// NIST SP 800-38A, F.3: IV shared by the CFB128 vectors.
    const IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
    /// NIST SP 800-38A, F.3: plaintext shared by the CFB128 vectors.
    const PLAINTEXT: [u8; 64] = hex!(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    );
    const CIPHERTEXT_128: [u8; 64] = hex!(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6"
    );
    const CIPHERTEXT_192: [u8; 64] = hex!(
        "cdc80d6fddf18cab34c25909c99a4174"
        "67ce7f7f81173621961a2b70171d3d7a"
        "2e1e8a1dd59b88b1c8e60fed1efac4c9"
        "c05f9f9ca9834fa042ae8fba584b09ff"
    );
    const CIPHERTEXT_256: [u8; 64] = hex!(
        "dc7e84bfda79164b7ecd8486985d3860"
        "39ffed143b28b1c832113c6331e5407b"
        "df10132415e54b92a13ed0a8267ae2f9"
        "75a385741ab9cef82031623d55b1e471"
    );

    /// Encrypts and decrypts with the CFB mode of `S` under `key` and checks the
    /// NIST vectors, including the final chaining value (the last ciphertext
    /// block).
    fn check_known_answer<S: SymmetricState<K>, const K: usize>(
        key: &[u8; K],
        ciphertext: &[u8; 64],
    ) {
        let state = S::init(key).unwrap();
        let mut iv = IV;
        let mut data = PLAINTEXT;
        state.cfb(Direction::Encrypt, &mut iv, &mut data).unwrap();
        assert_eq!(data, *ciphertext);
        assert_eq!(iv, ciphertext[48..]);

        let mut iv = IV;
        state.cfb(Direction::Decrypt, &mut iv, &mut data).unwrap();
        assert_eq!(data, PLAINTEXT);
        assert_eq!(iv, ciphertext[48..]);
    }

    #[test]
    fn aes_cfb_known_answers() {
        check_known_answer::<<CruxCryptoProvider as Symmetric>::Aes128, 16>(
            &KEY_128,
            &CIPHERTEXT_128,
        );
        check_known_answer::<<CruxCryptoProvider as Symmetric>::Aes192, 24>(
            &KEY_192,
            &CIPHERTEXT_192,
        );
        check_known_answer::<<CruxCryptoProvider as Symmetric>::Aes256, 32>(
            &KEY_256,
            &CIPHERTEXT_256,
        );
    }

    #[test]
    fn cfb_matches_cfb_mode_crate_for_every_length() {
        use aes::cipher::{AsyncStreamCipher as _, KeyIvInit as _};
        let key = SymmetricKey::new(AlgSym::Aes256, &KEY_256).unwrap();
        for len in 0..=PLAINTEXT.len() {
            let mut expected = PLAINTEXT;
            cfb_mode::Encryptor::<aes::Aes256>::new(&KEY_256.into(), &IV.into())
                .encrypt(&mut expected[..len]);

            let mut iv = IV;
            let mut data = PLAINTEXT;
            let input = CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut data[..len]);
            key.crypt::<CruxCryptoProvider>(Direction::Encrypt, input.unwrap())
                .unwrap();
            assert_eq!(data[..len], expected[..len], "len {len}");
            assert_eq!(data[len..], PLAINTEXT[len..], "len {len}");

            let mut iv = IV;
            let input = CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut data[..len]);
            key.crypt::<CruxCryptoProvider>(Direction::Decrypt, input.unwrap())
                .unwrap();
            assert_eq!(data, PLAINTEXT, "len {len}");
        }
    }

    /// After a partial final CFB block, the TPM's chaining value is the partial
    /// ciphertext padded with zeros.
    #[test]
    fn cfb_partial_block_iv_is_zero_padded() {
        let key = SymmetricKey::new(AlgSym::Aes128, &KEY_128).unwrap();
        let mut iv = IV;
        let mut data = PLAINTEXT;
        let input = CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut data[..21]);
        key.crypt::<CruxCryptoProvider>(Direction::Encrypt, input.unwrap())
            .unwrap();
        let mut expected_iv = [0u8; 16];
        expected_iv[..5].copy_from_slice(&CIPHERTEXT_128[16..21]);
        assert_eq!(iv, expected_iv);
    }

    /// The AES-128 modes other than CFB match the first block of NIST SP 800-38A F.1.1 (ECB),
    /// F.2.1 (CBC), F.4.1 (OFB) and F.5.1 (CTR), with the TCG reference's `ivOut`; SM4 is
    /// unsupported.
    #[test]
    fn other_modes_match_sp800_38a() {
        check_other_modes::<<CruxCryptoProvider as Symmetric>::Aes128>();
        assert!(matches!(
            <<CruxCryptoProvider as Symmetric>::Sm4_128 as SymmetricState<16>>::init(&KEY_128),
            Err(CryptoError::Unsupported)
        ));
    }

    fn check_other_modes<S: SymmetricState<16>>() {
        let state = S::init(&KEY_128).unwrap();
        let pt: [u8; 16] = PLAINTEXT[..16].try_into().unwrap();
        let mut data = [pt];
        state.ecb(Direction::Encrypt, &mut data).unwrap();
        assert_eq!(data[0], hex!("3ad77bb40d7a3660a89ecaf32466ef97"));
        let mut iv = IV;
        state.cbc(Direction::Decrypt, &mut iv, &mut data).unwrap();
        assert_eq!(iv, hex!("3ad77bb40d7a3660a89ecaf32466ef97"));
        let mut data = [pt];
        let mut iv = IV;
        state.cbc(Direction::Encrypt, &mut iv, &mut data).unwrap();
        assert_eq!(data[0], hex!("7649abac8119b246cee98e9b12e9197d"));
        assert_eq!(iv, data[0]);
        let mut data = pt;
        let mut iv = IV;
        state.ofb(&mut iv, &mut data).unwrap();
        assert_eq!(data, hex!("3b3fd92eb72dad20333449f8e83cfb4a"));
        assert_eq!(iv, hex!("50fe67cc996d32b6da0937e99bafec60"));
        let mut data = pt;
        let mut iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        state.ctr(&mut iv, &mut data).unwrap();
        assert_eq!(data, hex!("874d6191b620e3261bef6864990db6ce"));
        assert_eq!(iv, hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff00"));
    }

    /// Camellia-128 (RFC 3713, appendix A) in ECB mode.
    #[test]
    fn camellia_known_answer() {
        check_camellia::<<CruxCryptoProvider as Symmetric>::Camellia128>();
    }

    fn check_camellia<S: SymmetricState<16>>() {
        let key = hex!("0123456789abcdeffedcba9876543210");
        let state = S::init(&key).unwrap();
        let mut data = [key];
        state.ecb(Direction::Encrypt, &mut data).unwrap();
        assert_eq!(data[0], hex!("67673138549669730857065648eabe43"));
        state.ecb(Direction::Decrypt, &mut data).unwrap();
        assert_eq!(data[0], key);
    }
}
