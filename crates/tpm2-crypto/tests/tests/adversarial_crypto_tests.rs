use hex_literal::hex;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use tpm2::crypto::CryptoError;
use tpm2::crypto::asymmetric::Asymmetric;
use tpm2::crypto::ecc::Ecc;
use tpm2::crypto::{ModeIv, SymmetricKey};
use tpm2::errors::UnmarshalError;
use tpm2::{Alg, AlgSym, TpmiAlgCipherMode, TpmtSymDefObject};
use tpm2_crypto_tests::TestProvider;

#[test]
fn test_symmetric_invalid_key_sizes() {
    // Invalid key sizes: 0, 1, 15, 17, 31, 33, 64
    let invalid_keys = vec![
        vec![],
        vec![0u8; 1],
        vec![0u8; 15],
        vec![0u8; 17],
        vec![0u8; 31],
        vec![0u8; 33],
        vec![0u8; 64],
    ];

    for key in invalid_keys {
        // The key length is validated when the `SymmetricKey` is built, before any backend
        // call: no AES-128 key exists for a wrong length, so neither `encrypt` nor `decrypt`
        // can run with it (exp: both returned `CryptoError::InvalidData`).
        assert_eq!(SymmetricKey::new(AlgSym::Aes128, &key), None);
    }
}

#[test]
fn test_symmetric_invalid_iv_sizes() {
    // Invalid IV sizes: 0, 1, 15, 17, 32
    let mut invalid_ivs = vec![
        vec![],
        vec![0u8; 1],
        vec![0u8; 15],
        vec![0u8; 17],
        vec![0u8; 32],
    ];

    for iv in &mut invalid_ivs {
        // The IV length is validated when the `ModeIv` is built, before any backend call: no
        // CFB `ModeIv` exists for a wrong length, so neither `encrypt` nor `decrypt` can run
        // with it (exp: both returned `CryptoError::InvalidData`).
        assert_eq!(ModeIv::new(TpmiAlgCipherMode::Cfb, iv), None);
    }
}

#[test]
fn test_symmetric_unsupported_algorithms() {
    let provider = TestProvider;
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut data = [0u8; 16];

    // Null mode: `TPM_ALG_NULL` is not a block cipher mode, so it has no
    // `TpmiAlgCipherMode` (and thus no `ModeIv`) to encrypt with (exp: `encrypt` returned
    // `CryptoError::UnsupportedAlgorithm`).
    let null_mode = TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: None,
    };
    assert_eq!(
        TpmiAlgCipherMode::try_from(Alg::from(null_mode.mode)),
        Err(UnmarshalError::MODE)
    );

    // Unsupported mode (ECB)
    let res = tpm2::crypto::encrypt(
        &provider,
        SymmetricKey::Aes128(&key),
        ModeIv::new(TpmiAlgCipherMode::Ecb, &mut []).unwrap(),
        &mut data,
    );
    assert_eq!(res.unwrap_err(), CryptoError::Unsupported);
}

#[test]
fn test_symmetric_empty_data() {
    let provider = TestProvider;
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = [];
    let key = SymmetricKey::Aes128(&key);

    // CFB should support empty data as a no-op
    let res = tpm2::crypto::encrypt(&provider, key, ModeIv::Cfb(&mut iv), &mut data);
    assert!(res.is_ok());
    assert_eq!(data.len(), 0);

    let res_dec = tpm2::crypto::decrypt(&provider, key, ModeIv::Cfb(&mut iv), &mut data);
    assert!(res_dec.is_ok());
    assert_eq!(data.len(), 0);
}

#[test]
fn test_symmetric_non_block_aligned_data() {
    let provider = TestProvider;
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let original_iv = hex!("000102030405060708090a0b0c0d0e0f");
    let key = SymmetricKey::Aes128(&key);

    // CFB is a stream cipher mode, should handle non-block aligned sizes like 1, 7, 15, 16, 17, 31, 32, 33, 100
    let sizes = vec![1, 7, 15, 16, 17, 31, 32, 33, 100];
    for size in sizes {
        let mut original_data = vec![0u8; size];
        for (i, val) in original_data.iter_mut().enumerate() {
            *val = (i % 251) as u8;
        }

        let mut data = original_data.clone();
        let mut iv = original_iv;

        // Encrypt
        tpm2::crypto::encrypt(&provider, key, ModeIv::Cfb(&mut iv), &mut data).unwrap();

        // Decrypt
        let mut decrypted_data = data.clone();
        let mut iv_dec = original_iv;
        tpm2::crypto::decrypt(
            &provider,
            key,
            ModeIv::Cfb(&mut iv_dec),
            &mut decrypted_data,
        )
        .unwrap();

        assert_eq!(
            decrypted_data, original_data,
            "Decryption failed for size {}",
            size
        );
    }
}

#[test]
fn test_symmetric_iv_mutability() {
    let provider = TestProvider;
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let original_iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut iv = original_iv;
    let mut data = [0xAAu8; 32];

    tpm2::crypto::encrypt(
        &provider,
        SymmetricKey::Aes128(&key),
        ModeIv::Cfb(&mut iv),
        &mut data,
    )
    .unwrap();

    // Check if the IV buffer was modified in place.
    assert_ne!(original_iv, iv);
}

#[test]
fn test_cmac_invalid_key_sizes() {
    // Invalid key sizes: 0, 1, 15, 17, 31, 33, 64
    let invalid_keys = vec![
        vec![],
        vec![0u8; 1],
        vec![0u8; 15],
        vec![0u8; 17],
        vec![0u8; 31],
        vec![0u8; 33],
        vec![0u8; 64],
    ];

    for key in invalid_keys {
        // The key length is validated when the `SymmetricKey` is built, before any backend
        // call: no AES-128 CMAC key exists for a wrong length (exp: `cmac` returned
        // `CryptoError::InvalidData`).
        assert_eq!(SymmetricKey::new(AlgSym::Aes128, &key), None);
    }
}

#[test]
fn test_cmac_unsupported_algorithms() {
    let provider = TestProvider;
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let data = b"some data to mac";

    let mut mac = [0u8; 16];
    let res = tpm2::crypto::cmac(&provider, SymmetricKey::Sm4_128(&key), data, &mut mac);
    assert_eq!(res.unwrap_err(), CryptoError::Unsupported);
}

#[test]
fn test_cmac_empty_data() {
    let provider = TestProvider;
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");

    let mut mac = [0u8; 16];
    let res = tpm2::crypto::cmac(&provider, SymmetricKey::Aes128(&key), &[], &mut mac);
    assert!(res.is_ok());
}

#[test]
fn test_cmac_various_data_sizes() {
    let provider = TestProvider;
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");

    // CMAC works on messages of any size, from 0 to large sizes.
    let sizes = vec![0, 1, 15, 16, 17, 31, 32, 33, 100, 1000];
    let mut mac = [0u8; 16];
    for size in sizes {
        let data = vec![0x55u8; size];
        let res = tpm2::crypto::cmac(&provider, SymmetricKey::Aes128(&key), &data, &mut mac);
        assert!(res.is_ok());
    }
}

// ==========================================
// ADVERSARIAL & BOUNDARY TESTS FOR ASYMMETRIC, ECC, RNG (Milestone 5)
// ==========================================

#[test]
fn test_rsa_keygen_buffer_too_small() {
    use tpm2::crypto::asymmetric::TpmiRsaKeyBits;
    let provider = TestProvider;
    let mut public_key = [0u8; 10]; // too small
    let mut private_key = [0u8; 10]; // too small

    let res = provider.generate_key(
        Alg::RSA,
        Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
            1024,
        ))),
        &mut public_key,
        &mut private_key,
        None,
    );
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

#[test]
fn test_rsa_keygen_unsupported_scheme() {
    use tpm2::crypto::asymmetric::TpmiRsaKeyBits;
    let provider = TestProvider;
    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];

    let res = provider.generate_key(
        Alg::NULL, // Unsupported scheme for keygen
        Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
            2048,
        ))),
        &mut public_key,
        &mut private_key,
        None,
    );
    assert_eq!(res.unwrap_err(), CryptoError::Unsupported);
}

#[test]
fn test_ecc_keygen_buffer_too_small() {
    let provider = TestProvider;
    let mut public_key = [0u8; 63]; // ECC pubkey needs 64 bytes
    let mut private_key = [0u8; 32];

    let res = provider.generate_key(Alg::ECC, None, &mut public_key, &mut private_key, None);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);

    let mut public_key = [0u8; 64];
    let mut private_key = [0u8; 31]; // ECC privkey needs 32 bytes
    let res = provider.generate_key(Alg::ECC, None, &mut public_key, &mut private_key, None);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

#[test]
fn test_rsa_import_private_key_validation() {
    use tpm2::crypto::asymmetric::TpmiRsaKeyBits;
    let provider = TestProvider;
    let modulus = [0u8; 128];
    let prime_p = [0u8; 64];
    let mut private_key_out = [0u8; 1024];

    // p = 0
    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert_eq!(res, Ok(None));

    // p does not divide n
    let modulus = [0x0f; 128];
    let prime_p = [0x02; 64];
    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert_eq!(res, Ok(None));

    // exponent invalid (e.g. 0)
    // First generate a valid key to get modulus/prime
    let mut pub_key = [0u8; 1024];
    let mut priv_key = [0u8; 2048];
    let (_, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut pub_key,
            &mut priv_key,
            None,
        )
        .unwrap();

    use rsa::pkcs8::DecodePrivateKey as _;
    let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(&priv_key[..priv_len]).unwrap();
    let mod_bytes = rsa_key.n().to_bytes_be();
    let p_bytes = rsa_key.primes()[0].to_bytes_be();

    // Import with e = 0
    let res = provider.rsa_import_private_key(&mod_bytes, &p_bytes, 0, &mut private_key_out);
    assert_eq!(res, Ok(None));

    // Import with buffer too small
    let mut small_buf = [0u8; 10];
    let res = provider.rsa_import_private_key(&mod_bytes, &p_bytes, 65537, &mut small_buf);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

#[test]
fn test_rsa_decrypt_null_raw_padding_and_bounds() {
    use tpm2::crypto::asymmetric::TpmiRsaKeyBits;
    let provider = TestProvider;

    // Generate a valid RSA 1024 key
    let mut pub_key = [0u8; 1024];
    let mut priv_key = [0u8; 2048];
    let (_, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut pub_key,
            &mut priv_key,
            None,
        )
        .unwrap();

    // Null scheme (raw modpow)
    // ciphertext >= modulus
    use rsa::pkcs8::DecodePrivateKey as _;
    let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(&priv_key[..priv_len]).unwrap();
    let n = rsa_key.n();
    let mod_len = n.bits().div_ceil(8); // should be 128 for 1024-bit key

    // Ciphertext equal to modulus
    let c_bytes_equal = n.to_bytes_be();
    let mut plaintext = vec![0u8; mod_len];
    let res = provider.decrypt(
        Alg::NULL,
        Alg::NULL,
        &priv_key[..priv_len],
        &c_bytes_equal,
        &mut plaintext,
        &[],
    );
    assert_eq!(res, Ok(None));

    // Ciphertext greater than modulus
    let mut c_bytes_greater = c_bytes_equal.clone();
    c_bytes_greater.push(1);
    let res = provider.decrypt(
        Alg::NULL,
        Alg::NULL,
        &priv_key[..priv_len],
        &c_bytes_greater,
        &mut plaintext,
        &[],
    );
    assert_eq!(res, Ok(None));

    // Ciphertext is 0 (should return padded array of zeros)
    let c_zero = [0u8; 10];
    let res = provider
        .decrypt(
            Alg::NULL,
            Alg::NULL,
            &priv_key[..priv_len],
            &c_zero,
            &mut plaintext,
            &[],
        )
        .unwrap();
    assert_eq!(res, Some(mod_len));
    assert!(plaintext.iter().all(|&x| x == 0));

    // Ciphertext that decrypts to a small integer (should have leading zeros padding)
    // Let's compute c = 5^e mod n
    let m = rsa::BigUint::from(5u32);
    let c = m.modpow(rsa_key.e(), n);
    let c_bytes = c.to_bytes_be();
    let mut plaintext = vec![0u8; mod_len];
    let res = provider
        .decrypt(
            Alg::NULL,
            Alg::NULL,
            &priv_key[..priv_len],
            &c_bytes,
            &mut plaintext,
            &[],
        )
        .unwrap();
    assert_eq!(res, Some(mod_len));
    assert_eq!(plaintext[mod_len - 1], 5);
    assert!(plaintext[..mod_len - 1].iter().all(|&x| x == 0));

    // Decrypt with output buffer too small
    let mut small_plain = vec![0u8; mod_len - 1];
    let res = provider.decrypt(
        Alg::NULL,
        Alg::NULL,
        &priv_key[..priv_len],
        &c_bytes,
        &mut small_plain,
        &[],
    );
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

#[test]
fn test_ecc_point_multiply_unsupported_and_invalid() {
    let provider = TestProvider;

    let scalar = [1u8; 32];
    let mut out = [0u8; 64];

    // Scalar > group order P-256
    // Group order n = 0xffffffff00000000ffffffffffffffffbce6fa141fffffffffffffffffffffff
    // Let's pass 0xffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffff
    let large_scalar = [0xffu8; 32];
    let res = provider.point_multiply_generator(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &large_scalar,
        &mut out,
    );
    assert_eq!(res, Ok(None));

    // Scalar is 0
    let zero_scalar = [0u8; 32];
    let res = provider.point_multiply_generator(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &zero_scalar,
        &mut out,
    );
    assert_eq!(res, Ok(None));

    // point_multiply with invalid public point length
    let invalid_pt = [1u8; 63];
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &invalid_pt,
        &mut out,
    );
    assert_eq!(res, Ok(None));

    // point_multiply with invalid public point (not on curve)
    let not_on_curve = [0xffu8; 64];
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &not_on_curve,
        &mut out,
    );
    assert_eq!(res, Ok(None));
}
