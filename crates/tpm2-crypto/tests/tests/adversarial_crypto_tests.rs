use hex_literal::hex;
use tpm2::crypto::backend::{Cmac, CmacState, Symmetric, SymmetricState};
use tpm2::crypto::{
    CipherInput, CryptoError, Direction, EccPrivateKey, EccPublicKey, Random, RsaEncryptScheme,
    RsaPrivateKey, RsaPublicKey, SymmetricKey, ecc_mul_generator,
};
use tpm2::errors::UnmarshalError;
use tpm2::{
    Alg, AlgSym, Tpm2bEccParameter, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmEccCurve,
    TpmiAlgCipherMode, TpmiRsaKeyBits, TpmsEccPoint, TpmtSymDefObject,
};
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
        assert!(SymmetricKey::new(AlgSym::Aes128, &key).is_none());
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
        // The IV length is validated when the `CipherInput` is built, before any backend call:
        // no CFB `CipherInput` exists for a wrong length, so neither `encrypt` nor `decrypt`
        // can run with it (exp: both returned `CryptoError::InvalidData`).
        let mut data = [0u8; 16];
        assert!(CipherInput::new(TpmiAlgCipherMode::Cfb, iv, &mut data).is_none());
    }
}

#[test]
fn test_symmetric_unsupported_algorithms() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");

    // Null mode: `TPM_ALG_NULL` is not a block cipher mode, so it has no
    // `TpmiAlgCipherMode` (and thus no `CipherInput`) to encrypt with (exp: `encrypt` returned
    // `CryptoError::UnsupportedAlgorithm`).
    let null_mode = TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: None,
    };
    assert_eq!(
        TpmiAlgCipherMode::try_from(Alg::from(null_mode.mode)),
        Err(UnmarshalError::MODE)
    );

    // Unsupported cipher (SM4): every provider implements AES and Camellia only, so no SM4
    // key state can be created (and thus nothing can be encrypted with it).
    let res = <<TestProvider as Symmetric>::Sm4_128 as SymmetricState<16>>::init(&key);
    assert!(matches!(res, Err(CryptoError::Unsupported)));
}

#[test]
fn test_symmetric_empty_data() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let original_iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut iv = original_iv;
    let mut data = [];
    let key = SymmetricKey::Aes128(&key);

    // CFB should support empty data as a no-op (which leaves the IV unchanged)
    let res = key.crypt::<TestProvider>(Direction::Encrypt, CipherInput::Cfb(&mut iv, &mut data));
    assert!(res.is_ok());
    assert_eq!(data.len(), 0);
    assert_eq!(iv, original_iv);

    let res_dec =
        key.crypt::<TestProvider>(Direction::Decrypt, CipherInput::Cfb(&mut iv, &mut data));
    assert!(res_dec.is_ok());
    assert_eq!(data.len(), 0);
    assert_eq!(iv, original_iv);
}

#[test]
fn test_symmetric_non_block_aligned_data() {
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
        key.crypt::<TestProvider>(Direction::Encrypt, CipherInput::Cfb(&mut iv, &mut data))
            .unwrap();

        // Decrypt
        let mut decrypted_data = data.clone();
        let mut iv_dec = original_iv;
        key.crypt::<TestProvider>(
            Direction::Decrypt,
            CipherInput::Cfb(&mut iv_dec, &mut decrypted_data),
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
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let original_iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut iv = original_iv;
    let mut data = [0xAAu8; 32];

    SymmetricKey::Aes128(&key)
        .crypt::<TestProvider>(Direction::Encrypt, CipherInput::Cfb(&mut iv, &mut data))
        .unwrap();

    // Check if the IV buffer was modified in place.
    assert_ne!(original_iv, iv);
}

// CMAC is not part of the TPM's profile (the `cmac` feature of `tpm2`), so the CMAC tests use
// the providers' backend CMAC states directly.

/// The AES-128 CMAC state of the provider.
type CmacAes128 = <TestProvider as Cmac>::Aes128;

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
        // `CryptoError::InvalidData`). The backend CMAC states take `&[u8; 16]`, so a key of
        // another length can't reach them either.
        assert!(SymmetricKey::new(AlgSym::Aes128, &key).is_none());
        assert!(<&[u8; 16]>::try_from(key.as_slice()).is_err());
    }
}

#[test]
fn test_cmac_unsupported_algorithms() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");

    let res = <<TestProvider as Cmac>::Sm4_128 as CmacState<16>>::init(&key);
    assert!(matches!(res, Err(CryptoError::Unsupported)));
}

#[test]
fn test_cmac_empty_data() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");

    let mut mac = [0u8; 16];
    let res = <CmacAes128 as CmacState<16>>::cmac(&key, &[], &mut mac);
    assert!(res.is_ok());
    // RFC 4493, Example 1 (empty message).
    assert_eq!(mac, hex!("bb1d6929e95937287fa37d129b756746"));
}

#[test]
fn test_cmac_various_data_sizes() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");

    // CMAC works on messages of any size, from 0 to large sizes.
    let sizes = vec![0, 1, 15, 16, 17, 31, 32, 33, 100, 1000];
    let mut mac = [0u8; 16];
    for size in sizes {
        let data = vec![0x55u8; size];
        let res = <CmacAes128 as CmacState<16>>::cmac(&key, &[&data], &mut mac);
        assert!(res.is_ok());

        // Streaming (one byte at a time) gives the same tag.
        let mut state = <CmacAes128 as CmacState<16>>::init(&key).unwrap();
        for byte in &data {
            CmacState::<16>::update(&mut state, core::slice::from_ref(byte)).unwrap();
        }
        let mut streamed = [0u8; 16];
        CmacState::<16>::finalize(&mut state, &mut streamed).unwrap();
        assert_eq!(streamed, mac, "{size}");
    }
}

// ==========================================
// ADVERSARIAL & BOUNDARY TESTS FOR ASYMMETRIC, ECC, RNG (Milestone 5)
// ==========================================

/// Generates an RSA key of `bits` bits (with the default exponent) from the provider's RNG.
fn generate_rsa(bits: TpmiRsaKeyBits) -> RsaPrivateKey<TestProvider> {
    let mut rng = TestProvider::from_entropy().unwrap();
    RsaPrivateKey::<TestProvider>::generate(&mut rng, bits, 0).unwrap()
}

/// Loads the public key with `modulus` (and the default exponent).
fn rsa_public(bits: TpmiRsaKeyBits, modulus: &[u8]) -> RsaPublicKey<TestProvider> {
    RsaPublicKey::<TestProvider>::load(bits, 0, Tpm2bPublicKeyRsa::new(modulus).unwrap())
        .unwrap()
        .unwrap()
}

#[test]
fn test_rsa_keygen_buffer_too_small() {
    // Key generation no longer writes into caller buffers (exp: a too-small public or private
    // key buffer was `CryptoError::Internal`); the generated key is written out by `modulus`,
    // `prime_p` and `crt`, which return `CryptoError::Internal` for a too-small buffer.
    let key = generate_rsa(TpmiRsaKeyBits::Rsa1024);
    let mut small = [0u8; 10];
    assert_eq!(key.modulus(&mut small).unwrap_err(), CryptoError::Internal);
    assert_eq!(key.prime_p(&mut small).unwrap_err(), CryptoError::Internal);
    assert_eq!(key.crt(&mut small).unwrap_err(), CryptoError::Internal);

    // One byte short of the exact sizes is still too small; the exact sizes fit.
    let mut modulus = [0u8; 128];
    assert_eq!(
        key.modulus(&mut modulus[..127]).unwrap_err(),
        CryptoError::Internal
    );
    assert_eq!(key.modulus(&mut modulus).unwrap().as_slice().len(), 128);
    let mut prime = [0u8; 64];
    assert_eq!(
        key.prime_p(&mut prime[..63]).unwrap_err(),
        CryptoError::Internal
    );
    assert_eq!(key.prime_p(&mut prime).unwrap().as_slice().len(), 64);
}

#[test]
fn test_rsa_keygen_unsupported_scheme() {
    // There is no key-generation scheme argument anymore (exp: `Alg::NULL` was
    // `CryptoError::Unsupported`); the remaining unsupported key-generation parameters are
    // invalid public exponents (even, or below 3).
    let mut rng = TestProvider::from_entropy().unwrap();
    for exponent in [1, 2, 4, 65536] {
        let res =
            RsaPrivateKey::<TestProvider>::generate(&mut rng, TpmiRsaKeyBits::Rsa2048, exponent);
        assert!(matches!(res, Err(CryptoError::Unsupported)), "{exponent}");
    }
}

#[test]
fn test_ecc_keygen_buffer_too_small() {
    // Key generation no longer writes into caller buffers (exp: a 63-byte public or 31-byte
    // private key buffer was `CryptoError::Internal`); the generated key is written out by
    // `point` and `scalar`, which return `CryptoError::Internal` for a too-small buffer.
    let mut rng = TestProvider::from_entropy().unwrap();
    let key =
        EccPrivateKey::<TestProvider>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();

    let (mut x, mut y) = ([0u8; 31], [0u8; 32]); // P-256 coordinates need 32 bytes
    assert_eq!(
        key.point(&mut x, &mut y).unwrap_err(),
        CryptoError::Internal
    );
    let (mut x, mut y) = ([0u8; 32], [0u8; 31]);
    assert_eq!(
        key.point(&mut x, &mut y).unwrap_err(),
        CryptoError::Internal
    );

    let mut d = [0u8; 31]; // the P-256 private key needs 32 bytes
    assert_eq!(key.scalar(&mut d).unwrap_err(), CryptoError::Internal);

    // The exact sizes fit.
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    let point = key.point(&mut x, &mut y).unwrap();
    assert_eq!(point.x.as_slice().len(), 32);
    assert_eq!(point.y.as_slice().len(), 32);
    let mut d = [0u8; 32];
    assert_eq!(key.scalar(&mut d).unwrap().as_slice().len(), 32);
}

#[test]
fn test_rsa_import_private_key_validation() {
    let bits = TpmiRsaKeyBits::Rsa1024;

    // n = 0 (and any modulus without its top bit, or even) is not a valid public key.
    let modulus = [0u8; 128];
    let res =
        RsaPublicKey::<TestProvider>::load(bits, 65537, Tpm2bPublicKeyRsa::new(&modulus).unwrap());
    assert!(matches!(res, Ok(None)));
    let modulus = [0x0f; 128];
    let res =
        RsaPublicKey::<TestProvider>::load(bits, 65537, Tpm2bPublicKeyRsa::new(&modulus).unwrap());
    assert!(matches!(res, Ok(None)));

    // A valid key to get a modulus/prime.
    let key = generate_rsa(bits);
    let mut n_buf = [0u8; 128];
    let n = key.modulus(&mut n_buf).unwrap().as_slice().to_vec();
    let mut p_buf = [0u8; 64];
    let p = key.prime_p(&mut p_buf).unwrap().as_slice().to_vec();

    // p = 0
    let prime_p = [0u8; 64];
    let res = RsaPrivateKey::load(
        rsa_public(bits, &n),
        Tpm2bPrivateKeyRsa::new(&prime_p).unwrap(),
    );
    assert!(matches!(res, Ok(None)));

    // p does not divide n
    let prime_p = [0x02; 64];
    let res = RsaPrivateKey::load(
        rsa_public(bits, &n),
        Tpm2bPrivateKeyRsa::new(&prime_p).unwrap(),
    );
    assert!(matches!(res, Ok(None)));

    // p is empty, or longer than the prime size (one byte more, even if it is a leading zero)
    let mut long_p = vec![0u8];
    long_p.extend_from_slice(&p);
    for prime_p in [&[][..], &long_p] {
        let res = RsaPrivateKey::load(
            rsa_public(bits, &n),
            Tpm2bPrivateKeyRsa::new(prime_p).unwrap(),
        );
        assert!(matches!(res, Ok(None)), "{}", prime_p.len());
    }

    // exponent invalid: `0` now means the default 65537 (so it loads the key), while even
    // exponents and exponents below 3 are rejected.
    let res = RsaPublicKey::<TestProvider>::load(bits, 0, Tpm2bPublicKeyRsa::new(&n).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(res.exponent(), 65537);
    let res = RsaPrivateKey::load(res, Tpm2bPrivateKeyRsa::new(&p).unwrap()).unwrap();
    assert!(res.is_some());
    for exponent in [1, 2, 65536] {
        let res =
            RsaPublicKey::<TestProvider>::load(bits, exponent, Tpm2bPublicKeyRsa::new(&n).unwrap());
        assert!(matches!(res, Ok(None)), "{exponent}");
    }

    // Import with the modulus of a key of another size (a 1024-bit modulus as a 2048-bit key)
    let res = RsaPublicKey::<TestProvider>::load(
        TpmiRsaKeyBits::Rsa2048,
        65537,
        Tpm2bPublicKeyRsa::new(&n).unwrap(),
    );
    assert!(matches!(res, Ok(None)));
}

#[test]
fn test_rsa_decrypt_null_raw_padding_and_bounds() {
    // Generate a valid RSA 1024 key
    let key = generate_rsa(TpmiRsaKeyBits::Rsa1024);
    let mut rng = TestProvider::from_entropy().unwrap();
    let mut n_buf = [0u8; 128];
    let n_bytes = key.modulus(&mut n_buf).unwrap().as_slice().to_vec();
    let n = rsa::BigUint::from_bytes_be(&n_bytes);
    let mod_len = n.bits().div_ceil(8); // should be 128 for 1024-bit key
    assert_eq!(mod_len, 128);

    // Null scheme (raw modpow)
    // ciphertext >= modulus

    // Ciphertext equal to modulus
    let c_bytes_equal = n_bytes.clone();
    let mut plaintext = vec![0u8; mod_len];
    let res = key.decrypt(
        &mut rng,
        RsaEncryptScheme::Raw,
        &c_bytes_equal,
        &mut plaintext,
    );
    assert!(matches!(res, Ok(None)));

    // Ciphertext greater than modulus (of the modulus size, and longer than the modulus)
    let c_bytes_greater = vec![0xffu8; mod_len];
    let res = key.decrypt(
        &mut rng,
        RsaEncryptScheme::Raw,
        &c_bytes_greater,
        &mut plaintext,
    );
    assert!(matches!(res, Ok(None)));
    let mut c_bytes_longer = c_bytes_equal.clone();
    c_bytes_longer.push(1);
    let res = key.decrypt(
        &mut rng,
        RsaEncryptScheme::Raw,
        &c_bytes_longer,
        &mut plaintext,
    );
    assert!(matches!(res, Ok(None)));

    // Ciphertext shorter than the modulus: ciphertexts must have exactly the modulus size
    let c_short = [0u8; 10];
    let res = key.decrypt(&mut rng, RsaEncryptScheme::Raw, &c_short, &mut plaintext);
    assert!(matches!(res, Ok(None)));

    // Ciphertext is 0 (should return padded array of zeros)
    let c_zero = vec![0u8; mod_len];
    let res = key
        .decrypt(&mut rng, RsaEncryptScheme::Raw, &c_zero, &mut plaintext)
        .unwrap()
        .unwrap();
    assert_eq!(res.as_slice().len(), mod_len);
    assert!(res.as_slice().iter().all(|&x| x == 0));

    // Ciphertext that decrypts to a small integer (should have leading zeros padding)
    // Let's compute c = 5^e mod n
    let m = rsa::BigUint::from(5u32);
    let c = m.modpow(&rsa::BigUint::from(key.exponent()), &n);
    let mut c_bytes = vec![0u8; mod_len];
    let c_be = c.to_bytes_be();
    c_bytes[mod_len - c_be.len()..].copy_from_slice(&c_be);
    let mut plaintext = vec![0u8; mod_len];
    let res = key
        .decrypt(&mut rng, RsaEncryptScheme::Raw, &c_bytes, &mut plaintext)
        .unwrap()
        .unwrap();
    let res = res.as_slice();
    assert_eq!(res.len(), mod_len);
    assert_eq!(res[mod_len - 1], 5);
    assert!(res[..mod_len - 1].iter().all(|&x| x == 0));

    // Decrypt with output buffer too small
    let mut small_plain = vec![0u8; mod_len - 1];
    let res = key.decrypt(&mut rng, RsaEncryptScheme::Raw, &c_bytes, &mut small_plain);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

/// Builds a [`TpmsEccPoint`] from big-endian coordinates.
fn point<'a>(x: &'a [u8], y: &'a [u8]) -> TpmsEccPoint<'a> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::new(x).unwrap(),
        y: Tpm2bEccParameter::new(y).unwrap(),
    }
}

#[test]
fn test_ecc_point_multiply_unsupported_and_invalid() {
    let curve = TpmEccCurve::NistP256;
    let scalar = [1u8; 32];
    let (mut out_x, mut out_y) = ([0u8; 32], [0u8; 32]);

    // Scalar > group order P-256
    // Group order n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    // Let's pass 0xffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffff
    let large_scalar = [0xffu8; 32];
    let res = ecc_mul_generator::<TestProvider>(curve, &large_scalar, &mut out_x, &mut out_y);
    assert!(matches!(res, Ok(None)));

    // Scalar is n (the smallest scalar outside [1, n - 1])
    let order = hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let res = ecc_mul_generator::<TestProvider>(curve, &order, &mut out_x, &mut out_y);
    assert!(matches!(res, Ok(None)));

    // Scalar is 0
    let zero_scalar = [0u8; 32];
    let res = ecc_mul_generator::<TestProvider>(curve, &zero_scalar, &mut out_x, &mut out_y);
    assert!(matches!(res, Ok(None)));

    // Scalar is empty, or longer than the curve size
    let res = ecc_mul_generator::<TestProvider>(curve, &[], &mut out_x, &mut out_y);
    assert!(matches!(res, Ok(None)));
    let res = ecc_mul_generator::<TestProvider>(curve, &[1u8; 33], &mut out_x, &mut out_y);
    assert!(matches!(res, Ok(None)));

    // Points are validated when the public key is loaded, before any point multiplication
    // (exp: `point_multiply` returned `Ok(None)` for an invalid point).

    // invalid public point length: an empty coordinate, or one longer than the curve size
    let res = EccPublicKey::<TestProvider>::load(curve, None, point(&[1u8; 32], &[]));
    assert!(matches!(res, Ok(None)));
    let res = EccPublicKey::<TestProvider>::load(curve, None, point(&[1u8; 33], &[1u8; 32]));
    assert!(matches!(res, Ok(None)));

    // invalid public point (not on curve)
    let res = EccPublicKey::<TestProvider>::load(curve, None, point(&[0xffu8; 32], &[0xffu8; 32]));
    assert!(matches!(res, Ok(None)));

    // `mul_point` on a valid point (G = [1]G) rejects the same invalid scalars.
    let (mut gx, mut gy) = ([0u8; 32], [0u8; 32]);
    let g = ecc_mul_generator::<TestProvider>(curve, &[1], &mut gx, &mut gy)
        .unwrap()
        .unwrap();
    let g = EccPublicKey::<TestProvider>::load(curve, None, g)
        .unwrap()
        .unwrap();
    for k in [&large_scalar[..], &order, &zero_scalar, &[], &[1u8; 33]] {
        let res = g.mul_point(k, &mut out_x, &mut out_y);
        assert!(matches!(res, Ok(None)), "{k:02x?}");
    }

    // A valid scalar gives the same point as `ecc_mul_generator`.
    let (mut ex, mut ey) = ([0u8; 32], [0u8; 32]);
    let expected = ecc_mul_generator::<TestProvider>(curve, &scalar, &mut ex, &mut ey)
        .unwrap()
        .unwrap();
    let res = g
        .mul_point(&scalar, &mut out_x, &mut out_y)
        .unwrap()
        .unwrap();
    assert_eq!(res.x.as_slice(), expected.x.as_slice());
    assert_eq!(res.y.as_slice(), expected.y.as_slice());

    // Output buffers too small for the curve
    let mut small = [0u8; 31];
    let res = ecc_mul_generator::<TestProvider>(curve, &scalar, &mut small, &mut out_y);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
    let res = g.mul_point(&scalar, &mut out_x, &mut small);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}
