use hex_literal::hex;
use tpm2::Alg;
use tpm2::crypto::CryptoError;
use tpm2::crypto::asymmetric::{Asymmetric, AsymmetricSign, TpmiRsaKeyBits};
use tpm2::crypto::ecc::Ecc;
use tpm2::crypto::rng::Rng;
use tpm2_crypto_tests::TestProvider;

#[test]
fn test_rsa_import_modulus_zero() {
    let provider = TestProvider;
    let modulus = [0u8; 128];
    let prime_p = [0u8; 64];
    let mut private_key_out = [0u8; 1024];

    // Modulus and p are zero
    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_rsa_import_p_equals_n() {
    let provider = TestProvider;
    // Let's use 35 as n, 35 as p (n % p == 0, n / p == 1). Both are not prime, but we want to see if p == n works/fails.
    let modulus = [35u8];
    let prime_p = [35u8];
    let mut private_key_out = [0u8; 1024];

    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert!(res.is_err(), "Importing p == n should fail, got {:?}", res);
}

#[test]
fn test_rsa_import_p_equals_one() {
    let provider = TestProvider;
    let modulus = [35u8];
    let prime_p = [1u8];
    let mut private_key_out = [0u8; 1024];

    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert!(res.is_err(), "Importing p == 1 should fail, got {:?}", res);
}

#[test]
fn test_rsa_import_composite_non_primes() {
    let provider = TestProvider;
    // n = 32, p = 4. q = 8. (4 * 8 == 32, 32 % 4 == 0). Neither is prime.
    let modulus = [32u8];
    let prime_p = [4u8];
    let mut private_key_out = [0u8; 1024];

    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert!(
        res.is_err(),
        "Importing composite numbers should fail, got {:?}",
        res
    );
}

#[test]
fn test_rsa_import_exponent_invalid() {
    let provider = TestProvider;
    // First generate key to get standard modulus, primes, etc.
    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (_pub_len, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let orig_priv_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key[..priv_len]).unwrap();

    let modulus = orig_priv_key.n().to_bytes_be();
    let prime_p = orig_priv_key.primes()[0].to_bytes_be();

    let mut imported_private_key = [0u8; 2048];
    // Try with invalid exponent = 0
    let res = provider.rsa_import_private_key(&modulus, &prime_p, 0, &mut imported_private_key);
    assert!(
        res.is_err(),
        "Importing exponent = 0 should fail, got {:?}",
        res
    );

    // Try with invalid exponent = 1
    let res = provider.rsa_import_private_key(&modulus, &prime_p, 1, &mut imported_private_key);
    assert!(
        res.is_err(),
        "Importing exponent = 1 should fail, got {:?}",
        res
    );
}

#[test]
fn test_ecc_scalar_zero() {
    let provider = TestProvider;
    let scalar = [0u8; 32];
    let mut public_key_out = [0u8; 64];

    // 0 is not a valid private scalar
    let res = provider.point_multiply_generator(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &mut public_key_out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    let pt = hex!(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );
    let mut out_point = [0u8; 64];
    let res_mult = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &pt,
        &mut out_point,
    );
    assert_eq!(res_mult.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_ecc_scalar_too_large() {
    let provider = TestProvider;
    // Order of P-256 is ~ 1.1579208921035624876269744694940757353008090692179611295775678292847764947233e77
    // Order n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FA14 86200347 52C2DEC8 0249236D
    // Let's use FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
    let scalar = [0xFFu8; 32];
    let mut public_key_out = [0u8; 64];

    let res = provider.point_multiply_generator(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &mut public_key_out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_ecc_scalar_empty() {
    let provider = TestProvider;
    let scalar = [];
    let mut public_key_out = [0u8; 64];

    let res = provider.point_multiply_generator(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &mut public_key_out,
    );
    // Since empty scalar resolves to zero scalar, it should fail
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_ecc_point_multiply_small_buffer() {
    let provider = TestProvider;
    let mut small_buf = [0u8; 63]; // 1 byte short of 64

    let mut pub_a = [0u8; 64];
    let mut priv_a = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut pub_a,
            &mut priv_a,
            None,
        )
        .unwrap();

    // Check point_multiply_generator handles small buffer without panicking
    let res_gen = provider.point_multiply_generator(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &priv_a,
        &mut small_buf,
    );
    assert_eq!(res_gen.unwrap_err(), CryptoError::BufferTooSmall);

    // Let's check point_multiply behavior
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &priv_a,
        &pub_a,
        &mut small_buf,
    );
    assert_eq!(res.unwrap_err(), CryptoError::BufferTooSmall);
}

#[test]
fn test_rsa_decrypt_null_large_ciphertext() {
    let provider = TestProvider;
    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (_, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    // Ciphertext is larger than modulus (e.g. 128 bytes of 0xFF)
    let ciphertext = [0xFFu8; 128];
    let mut plaintext = [0u8; 128];

    let res = provider.decrypt(
        Alg::NULL,
        Alg::NULL,
        &private_key[..priv_len],
        &ciphertext,
        &mut plaintext,
        &[],
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_rsa_decrypt_null_empty_ciphertext() {
    let provider = TestProvider;
    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (_, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    let ciphertext = [];
    let mut plaintext = [0u8; 128];

    let res = provider.decrypt(
        Alg::NULL,
        Alg::NULL,
        &private_key[..priv_len],
        &ciphertext,
        &mut plaintext,
        &[],
    );
    assert!(res.is_ok());
    let dec_len = res.unwrap();
    assert_eq!(dec_len, 128);
    assert!(plaintext.iter().all(|&x| x == 0));
}

#[test]
fn test_rsa_decrypt_oaep_non_utf8_label() {
    let provider = TestProvider;
    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (_, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    // Label with non-UTF-8 bytes
    let invalid_label = b"\xFF\xFE\xFD";
    let ciphertext = [0u8; 128];
    let mut plaintext = [0u8; 128];

    let res = provider.decrypt(
        Alg::OAEP,
        Alg::SHA256,
        &private_key[..priv_len],
        &ciphertext,
        &mut plaintext,
        invalid_label,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_rsa_sign_mismatched_digest_size() {
    let provider = TestProvider;
    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (_, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    // Digest size is 10 bytes instead of 32 (for SHA-256). TpmtHa rejects it at construction.
    let digest = [0u8; 10];
    assert!(tpm2::TpmtHa::new(tpm2::TpmiAlgHash::Sha256, &digest).is_none());

    let mut signature = [0u8; 128];
    let sm3_digest = [0u8; 32];
    let res = provider.sign_inner(
        Alg::RSAPSS,
        &private_key[..priv_len],
        tpm2::TpmtHa::Sm3_256(&sm3_digest),
        &mut signature,
    );
    assert!(res.is_err());
}

#[test]
fn test_rsa_keygen_small_buffers() {
    let provider = TestProvider;
    let mut public_key = [0u8; 1];
    let mut private_key = [0u8; 1];

    let res = provider.generate_key(
        Alg::RSA,
        Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
            1024,
        ))),
        &mut public_key,
        &mut private_key,
        None,
    );
    assert_eq!(res.unwrap_err(), CryptoError::BufferTooSmall);
}

#[test]
fn test_rng_limits() {
    let provider = TestProvider;
    let mut buf = [0u8; 1024 * 1024]; // 1MB buffer
    let res = provider.get_random(&mut buf);
    assert!(res.is_ok());
}
