use rsa::traits::PublicKeyParts as _;
use tpm2::Alg;
use tpm2::crypto::CryptoError;
use tpm2::crypto::asymmetric::{Asymmetric, AsymmetricSign, TpmiRsaKeyBits};
use tpm2::crypto::ecc::Ecc;
use tpm2_crypto_tests::TestProvider;

#[test]
fn test_rsa_import_private_key_bounds() {
    let provider = TestProvider;
    let mut private_key_out = [0u8; 2048];

    // 1. Zero modulus, zero p
    let res = provider.rsa_import_private_key(&[0], &[0], 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 2. Zero p, non-zero modulus
    let res = provider.rsa_import_private_key(&[15], &[0], 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 3. p = 1
    let res = provider.rsa_import_private_key(&[15], &[1], 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 4. p > n (so q = 0)
    let res = provider.rsa_import_private_key(&[15], &[16], 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 5. p = n (so q = 1)
    let res = provider.rsa_import_private_key(&[15], &[15], 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 6. n not divisible by p
    let res = provider.rsa_import_private_key(&[15], &[4], 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 7. Invalid exponents (0, 1, 2)
    // First get a valid key parameters to test exponent validation
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

    use rsa::pkcs8::DecodePrivateKey as _;
    let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key[..priv_len]).unwrap();
    use rsa::traits::PrivateKeyParts as _;
    let modulus = rsa_key.n().to_bytes_be();
    let prime_p = rsa_key.primes()[0].to_bytes_be();

    // Exponent 0
    let res = provider.rsa_import_private_key(&modulus, &prime_p, 0, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // Exponent 1
    let res = provider.rsa_import_private_key(&modulus, &prime_p, 1, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // Exponent 2 (even exponent should fail for RSA)
    let res = provider.rsa_import_private_key(&modulus, &prime_p, 2, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 8. Extreme/garbage values
    let res = provider.rsa_import_private_key(
        b"garbage modulus",
        b"garbage p",
        65537,
        &mut private_key_out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_ecc_point_multiply_buffer_sizes() {
    let provider = TestProvider;
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

    // 1. Output buffer sizes for point_multiply
    for size in [0, 1, 10, 32, 63] {
        let mut buf = vec![0u8; size];
        let res = provider.point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_a,
            &pub_a,
            &mut buf,
        );
        assert_eq!(res.unwrap_err(), CryptoError::BufferTooSmall);
    }

    // Output buffer size 64 (succeeds)
    let mut buf_64 = [0u8; 64];
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_a,
            &pub_a,
            &mut buf_64,
        )
        .unwrap();

    // Output buffer size 100 (succeeds)
    let mut buf_100 = [0u8; 100];
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_a,
            &pub_a,
            &mut buf_100,
        )
        .unwrap();
    // Verification that only 64 bytes were written or handled correctly
    assert_ne!(buf_100[..64], [0u8; 64]);
    assert_eq!(buf_100[64..], [0u8; 36]);

    // 2. Output buffer sizes for point_multiply_generator
    for size in [0, 1, 10, 32, 63] {
        let mut buf = vec![0u8; size];
        let res = provider.point_multiply_generator(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_a,
            &mut buf,
        );
        assert_eq!(res.unwrap_err(), CryptoError::BufferTooSmall);
    }

    let mut buf_64 = [0u8; 64];
    provider
        .point_multiply_generator(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_a,
            &mut buf_64,
        )
        .unwrap();

    let mut buf_100 = [0u8; 100];
    provider
        .point_multiply_generator(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_a,
            &mut buf_100,
        )
        .unwrap();
    assert_ne!(buf_100[..64], [0u8; 64]);
    assert_eq!(buf_100[64..], [0u8; 36]);
}

#[test]
fn test_bn_p256_fallback() {
    let provider = TestProvider;

    // BN_P256 curve point: (1, 2)
    // Coordinates must be 32 bytes each
    let mut bn_point = [0u8; 64];
    bn_point[31] = 1; // X = 1
    bn_point[63] = 2; // Y = 2

    // 1. Validate point (1, 2) on BN_P256
    provider
        .validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &bn_point)
        .unwrap();

    // 2. Validate point (1, 3) is NOT on BN_P256
    let mut invalid_bn_point = [0u8; 64];
    invalid_bn_point[31] = 1; // X = 1
    invalid_bn_point[63] = 3; // Y = 3
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &invalid_bn_point);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 3. Point multiplication with scalar = 1 (should return same point)
    let mut scalar_1 = [0u8; 32];
    scalar_1[31] = 1;
    let mut out_point = [0u8; 64];
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::BNP256,
            &scalar_1,
            &bn_point,
            &mut out_point,
        )
        .unwrap();
    assert_eq!(out_point, bn_point);

    // 4. Point multiplication with scalar = 2 (should return a valid point on the curve)
    let mut scalar_2 = [0u8; 32];
    scalar_2[31] = 2;
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::BNP256,
            &scalar_2,
            &bn_point,
            &mut out_point,
        )
        .unwrap();
    // Output point must be on the curve
    provider
        .validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &out_point)
        .unwrap();

    // 5. Point multiplication with scalar = 0 (should fail)
    let scalar_0 = [0u8; 32];
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
        &scalar_0,
        &bn_point,
        &mut out_point,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 6. Point multiplication with large scalar
    let mut scalar_large = [0u8; 32];
    scalar_large[0] = 0x01; // some arbitrary non-zero scalar
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::BNP256,
            &scalar_large,
            &bn_point,
            &mut out_point,
        )
        .unwrap();
    provider
        .validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &out_point)
        .unwrap();
}

#[test]
fn test_bn_p256_coordinate_range_validation() {
    let provider = TestProvider;

    // p = fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013
    // Let's create X = p + 1, Y = 2
    let bn_point = hex_literal::hex!(
        "fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33014" // X = p + 1
        "0000000000000000000000000000000000000000000000000000000000000002" // Y = 2
    );

    // If coordinates >= p are strictly rejected, this should fail with InvalidData
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &bn_point);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_ecc_curve_isolation_and_boundaries() {
    let provider = TestProvider;

    // NIST P-256 prime: p = ffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    let nist_p_bytes =
        hex_literal::hex!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

    // 1. NIST P-256: Coordinate X = p, Y = 1
    let mut nist_p_equal_x = [0u8; 64];
    nist_p_equal_x[..32].copy_from_slice(&nist_p_bytes);
    nist_p_equal_x[63] = 1;
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &nist_p_equal_x);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    let mut out = [0u8; 64];
    let scalar = [1u8; 32];
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &nist_p_equal_x,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 2. NIST P-256: Coordinate X = p + 1, Y = 1
    let mut nist_p_greater_x = [0u8; 64];
    // p + 1 = ffffffff00000001000000000000000000000001000000000000000000000000
    let nist_p_plus_1_bytes =
        hex_literal::hex!("ffffffff00000001000000000000000000000001000000000000000000000000");
    nist_p_greater_x[..32].copy_from_slice(&nist_p_plus_1_bytes);
    nist_p_greater_x[63] = 1;
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &nist_p_greater_x);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &nist_p_greater_x,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 3. NIST P-256: Coordinate X = 1, Y = p
    let mut nist_p_equal_y = [0u8; 64];
    nist_p_equal_y[31] = 1;
    nist_p_equal_y[32..].copy_from_slice(&nist_p_bytes);
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &nist_p_equal_y);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &nist_p_equal_y,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 4. BN_P256: Coordinate X = p, Y = 1
    let bn_p_bytes =
        hex_literal::hex!("fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013");
    let mut bn_p_equal_x = [0u8; 64];
    bn_p_equal_x[..32].copy_from_slice(&bn_p_bytes);
    bn_p_equal_x[63] = 1;
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &bn_p_equal_x);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
        &scalar,
        &bn_p_equal_x,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 5. BN_P256: Coordinate X = 1, Y = p
    let mut bn_p_equal_y = [0u8; 64];
    bn_p_equal_y[31] = 1;
    bn_p_equal_y[32..].copy_from_slice(&bn_p_bytes);
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &bn_p_equal_y);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
        &scalar,
        &bn_p_equal_y,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 6. Curve Isolation: Valid BN_P256 point (1, 2) validated/multiplied on NIST P-256
    let mut bn_valid_point = [0u8; 64];
    bn_valid_point[31] = 1;
    bn_valid_point[63] = 2;
    // Verify it is indeed valid on BN_P256
    provider
        .validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &bn_valid_point)
        .unwrap();
    // Validate on NIST P-256 should fail
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &bn_valid_point);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    // Multiply on NIST P-256 should fail
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &bn_valid_point,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 7. Curve Isolation: Valid NIST P-256 point validated/multiplied on BN_P256
    let mut nist_pub = [0u8; 64];
    let mut nist_priv = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut nist_pub,
            &mut nist_priv,
            None,
        )
        .unwrap();
    // Verify it is indeed valid on NIST P-256
    provider
        .validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &nist_pub)
        .unwrap();
    // Validate on BN_P256 should fail
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &nist_pub);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    // Multiply on BN_P256 should fail
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
        &scalar,
        &nist_pub,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 8. NIST P-256: Coordinate X = 1, Y = p + 1
    let mut nist_p_plus_1_y = [0u8; 64];
    nist_p_plus_1_y[31] = 1;
    nist_p_plus_1_y[32..].copy_from_slice(&nist_p_plus_1_bytes);
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &nist_p_plus_1_y);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &nist_p_plus_1_y,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 9. BN_P256: Coordinate X = p + 1, Y = 2
    let mut bn_p_plus_1_x = [0u8; 64];
    let mut bn_p_plus_1_bytes = bn_p_bytes;
    bn_p_plus_1_bytes[31] = 0x14;
    bn_p_plus_1_x[..32].copy_from_slice(&bn_p_plus_1_bytes);
    bn_p_plus_1_x[63] = 2;
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
        &scalar,
        &bn_p_plus_1_x,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 10. BN_P256: Coordinate X = 1, Y = p + 1
    let mut bn_p_plus_1_y = [0u8; 64];
    bn_p_plus_1_y[31] = 1;
    bn_p_plus_1_y[32..].copy_from_slice(&bn_p_plus_1_bytes);
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &bn_p_plus_1_y);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
        &scalar,
        &bn_p_plus_1_y,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 11. Point with all 0xFF coordinates
    let all_ff = [0xffu8; 64];
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &all_ff);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &all_ff,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &all_ff);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
        &scalar,
        &all_ff,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

    // 12. Point with all 0x00 coordinates (0, 0)
    let all_zero = [0u8; 64];
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &all_zero);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar,
        &all_zero,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &all_zero);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
        &scalar,
        &all_zero,
        &mut out,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn adv_test_rsa_keygen_with_seed() {
    let provider = TestProvider;
    let seed1 = b"deterministic seed 1";
    let seed2 = b"deterministic seed 2";

    let mut pub1 = [0u8; 1024];
    let mut priv1 = [0u8; 2048];
    let (pub1_len, priv1_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut pub1,
            &mut priv1,
            Some(seed1),
        )
        .unwrap();

    // Generate again with same seed, must be identical
    let mut pub1_bis = [0u8; 1024];
    let mut priv1_bis = [0u8; 2048];
    let (pub1_bis_len, priv1_bis_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut pub1_bis,
            &mut priv1_bis,
            Some(seed1),
        )
        .unwrap();

    assert_eq!(pub1_len, pub1_bis_len);
    assert_eq!(priv1_len, priv1_bis_len);
    assert_eq!(&pub1[..pub1_len], &pub1_bis[..pub1_bis_len]);
    assert_eq!(&priv1[..priv1_len], &priv1_bis[..priv1_bis_len]);

    // Generate with different seed, must be different
    let mut pub2 = [0u8; 1024];
    let mut priv2 = [0u8; 2048];
    let (_pub2_len, priv2_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut pub2,
            &mut priv2,
            Some(seed2),
        )
        .unwrap();

    assert_ne!(&priv1[..priv1_len], &priv2[..priv2_len]);
}

#[test]
fn adv_test_ecc_keygen_with_seed() {
    let provider = TestProvider;
    let seed1 = b"deterministic ecc seed 1";
    let seed2 = b"deterministic ecc seed 2";

    let mut pub1 = [0u8; 64];
    let mut priv1 = [0u8; 32];
    let (pub1_len, priv1_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut pub1,
            &mut priv1,
            Some(seed1),
        )
        .unwrap();

    let mut pub1_bis = [0u8; 64];
    let mut priv1_bis = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut pub1_bis,
            &mut priv1_bis,
            Some(seed1),
        )
        .unwrap();

    assert_eq!(&pub1[..pub1_len], &pub1_bis[..pub1_len]);
    assert_eq!(&priv1[..priv1_len], &priv1_bis[..priv1_len]);

    let mut pub2 = [0u8; 64];
    let mut priv2 = [0u8; 32];
    let (_pub2_len, priv2_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut pub2,
            &mut priv2,
            Some(seed2),
        )
        .unwrap();

    assert_ne!(&priv1[..priv1_len], &priv2[..priv2_len]);
}

#[test]
fn adv_test_rsa_signatures_all_hashes() {
    let provider = TestProvider;

    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (pub_len, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                2048,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    let test_cases = vec![
        (Alg::RSASSA, Alg::SHA1, 20),
        (Alg::RSASSA, Alg::SHA256, 32),
        (Alg::RSASSA, Alg::SHA384, 48),
        (Alg::RSASSA, Alg::SHA512, 64),
        (Alg::RSAPSS, Alg::SHA1, 20),
        (Alg::RSAPSS, Alg::SHA256, 32),
        (Alg::RSAPSS, Alg::SHA384, 48),
        (Alg::RSAPSS, Alg::SHA512, 64),
    ];

    for (sign_alg, hash_alg, digest_len) in test_cases {
        let digest = vec![0xABu8; digest_len];
        let mut signature = [0u8; 256];

        // Sign
        let sig_len = provider
            .sign_inner(
                sign_alg,
                &private_key[..priv_len],
                tpm2::TpmtHa::from_alg(hash_alg, &digest).unwrap(),
                &mut signature,
            )
            .unwrap();

        // Verify using rsa crate directly
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&public_key[..pub_len]),
            rsa::BigUint::from(65537u32),
        )
        .unwrap();
        match sign_alg {
            Alg::RSASSA => match hash_alg {
                Alg::SHA1 => pub_key
                    .verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new::<sha1::Sha1>(),
                        &digest,
                        &signature[..sig_len],
                    )
                    .unwrap(),
                Alg::SHA256 => pub_key
                    .verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        &digest,
                        &signature[..sig_len],
                    )
                    .unwrap(),
                Alg::SHA384 => pub_key
                    .verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha384>(),
                        &digest,
                        &signature[..sig_len],
                    )
                    .unwrap(),
                Alg::SHA512 => pub_key
                    .verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(),
                        &digest,
                        &signature[..sig_len],
                    )
                    .unwrap(),
                _ => unreachable!(),
            },
            Alg::RSAPSS => match hash_alg {
                Alg::SHA1 => pub_key
                    .verify(
                        rsa::pss::Pss::new::<sha1::Sha1>(),
                        &digest,
                        &signature[..sig_len],
                    )
                    .unwrap(),
                Alg::SHA256 => pub_key
                    .verify(
                        rsa::pss::Pss::new::<sha2::Sha256>(),
                        &digest,
                        &signature[..sig_len],
                    )
                    .unwrap(),
                Alg::SHA384 => pub_key
                    .verify(
                        rsa::pss::Pss::new::<sha2::Sha384>(),
                        &digest,
                        &signature[..sig_len],
                    )
                    .unwrap(),
                Alg::SHA512 => pub_key
                    .verify(
                        rsa::pss::Pss::new::<sha2::Sha512>(),
                        &digest,
                        &signature[..sig_len],
                    )
                    .unwrap(),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}

#[test]
fn adv_test_rsa_oaep_decrypt_all_hashes() {
    let provider = TestProvider;

    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (pub_len, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                2048,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&public_key[..pub_len]),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    let mut rng_thread = rsa::rand_core::OsRng;
    let plaintext = b"hello world hashes";

    let hash_cases = vec![
        (Alg::SHA1, rsa::Oaep::new::<sha1::Sha1>()),
        (Alg::SHA256, rsa::Oaep::new::<sha2::Sha256>()),
        (Alg::SHA384, rsa::Oaep::new::<sha2::Sha384>()),
        (Alg::SHA512, rsa::Oaep::new::<sha2::Sha512>()),
    ];

    for (hash_alg, oaep) in hash_cases {
        let c = pub_key.encrypt(&mut rng_thread, oaep, plaintext).unwrap();

        let mut decrypted = [0u8; 128];
        let dec_len = provider
            .decrypt(
                Alg::OAEP,
                hash_alg,
                &private_key[..priv_len],
                &c,
                &mut decrypted,
                &[],
            )
            .unwrap();

        assert_eq!(&decrypted[..dec_len], plaintext);
    }
}

#[test]
fn adv_test_rsa_keygen_3072() {
    let provider = TestProvider;

    let mut public_key = [0u8; 2048];
    let mut private_key = [0u8; 4096];
    let (pub_len, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                3072,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    assert!(pub_len > 0);
    assert!(priv_len > 0);
}

#[test]
fn adv_test_rsa_keygen_4096() {
    let provider = TestProvider;

    let mut public_key = [0u8; 2048];
    let mut private_key = [0u8; 4096];
    let (pub_len, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                4096,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    assert!(pub_len > 0);
    assert!(priv_len > 0);
}

#[test]
fn adv_test_ecc_bn_p256_keygen_and_multiply_generator() {
    let provider = TestProvider;

    let mut public_key = [0u8; 64];
    let mut private_key = [0u8; 32];
    let (pub_len, priv_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::BNP256,
            )),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    assert_eq!(pub_len, 64);
    assert_eq!(priv_len, 32);

    // Validate the generated point on BN_P256
    provider
        .validate_point(
            tpm2::crypto::ecc::TpmEccCurve::BNP256,
            &public_key[..pub_len],
        )
        .unwrap();

    // Multiply the generator with the private scalar using point_multiply_generator
    let mut public_key_regen = [0u8; 64];
    provider
        .point_multiply_generator(
            tpm2::crypto::ecc::TpmEccCurve::BNP256,
            &private_key[..priv_len],
            &mut public_key_regen,
        )
        .unwrap();

    // Verify it yields the same public key
    assert_eq!(public_key, public_key_regen);
}

#[test]
fn adv_test_ecc_validate_point_invalid_lengths() {
    let provider = TestProvider;

    for curve in [
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        tpm2::crypto::ecc::TpmEccCurve::BNP256,
    ] {
        for len in [0, 1, 32, 63, 65, 100] {
            let invalid_point = vec![0u8; len];
            let res = provider.validate_point(curve, &invalid_point);
            assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
        }
    }
}

#[test]
fn adv_test_ecc_bn_p256_keygen_with_seed() {
    let provider = TestProvider;
    let seed1 = b"bn256 deterministic seed 1";
    let seed2 = b"bn256 deterministic seed 2";

    let mut pub1 = [0u8; 64];
    let mut priv1 = [0u8; 32];
    let (pub1_len, priv1_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::BNP256,
            )),
            &mut pub1,
            &mut priv1,
            Some(seed1),
        )
        .unwrap();

    assert_eq!(pub1_len, 64);
    assert_eq!(priv1_len, 32);

    // Verify it is on the curve
    provider
        .validate_point(tpm2::crypto::ecc::TpmEccCurve::BNP256, &pub1)
        .unwrap();

    // Re-generate with the same seed, must be identical
    let mut pub1_bis = [0u8; 64];
    let mut priv1_bis = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::BNP256,
            )),
            &mut pub1_bis,
            &mut priv1_bis,
            Some(seed1),
        )
        .unwrap();

    assert_eq!(pub1, pub1_bis);
    assert_eq!(priv1, priv1_bis);

    // Generate with a different seed, must be different
    let mut pub2 = [0u8; 64];
    let mut priv2 = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::BNP256,
            )),
            &mut pub2,
            &mut priv2,
            Some(seed2),
        )
        .unwrap();

    assert_ne!(priv1, priv2);
}

#[test]
fn adv_test_keygen_empty_seed() {
    let provider = TestProvider;

    // RSA with empty seed
    let mut pub1 = [0u8; 1024];
    let mut priv1 = [0u8; 2048];
    let (pub1_len, priv1_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut pub1,
            &mut priv1,
            Some(&[]),
        )
        .unwrap();

    // Re-generate with empty seed, must be identical
    let mut pub1_bis = [0u8; 1024];
    let mut priv1_bis = [0u8; 2048];
    let (pub1_bis_len, priv1_bis_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                1024,
            ))),
            &mut pub1_bis,
            &mut priv1_bis,
            Some(&[]),
        )
        .unwrap();

    assert_eq!(&pub1[..pub1_len], &pub1_bis[..pub1_bis_len]);
    assert_eq!(&priv1[..priv1_len], &priv1_bis[..priv1_bis_len]);
}

#[test]
fn adv_test_rsa_keygen_fallback_params() {
    let provider = TestProvider;

    // 1. params is None -> should fall back to 2048 bits
    let mut pub_none = [0u8; 1024];
    let mut priv_none = [0u8; 2048];
    let (_pub_len, priv_len) = provider
        .generate_key(Alg::RSA, None, &mut pub_none, &mut priv_none, None)
        .unwrap();

    // Verify it is a valid 2048-bit key
    use rsa::pkcs8::DecodePrivateKey as _;
    let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(&priv_none[..priv_len]).unwrap();
    assert_eq!(rsa_key.n().bits(), 2048);

    // 2. params is ECC -> should fall back to 2048 bits
    let mut pub_ecc_param = [0u8; 1024];
    let mut priv_ecc_param = [0u8; 2048];
    let (_pub_len_2, priv_len_2) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut pub_ecc_param,
            &mut priv_ecc_param,
            None,
        )
        .unwrap();

    let rsa_key_2 = rsa::RsaPrivateKey::from_pkcs8_der(&priv_ecc_param[..priv_len_2]).unwrap();
    assert_eq!(rsa_key_2.n().bits(), 2048);
}

#[test]
fn adv_test_rsa_oaep_decrypt_with_label() {
    let provider = TestProvider;

    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (pub_len, priv_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                2048,
            ))),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&public_key[..pub_len]),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    let mut rng_thread = rsa::rand_core::OsRng;
    let plaintext = b"secure message with label";
    let label = b"my_secure_label";

    // Encrypt with label
    let oaep = rsa::Oaep::new_with_label::<sha2::Sha256, _>("my_secure_label");
    let c = pub_key.encrypt(&mut rng_thread, oaep, plaintext).unwrap();

    // Decrypt with correct label
    let mut decrypted = [0u8; 128];
    let dec_len = provider
        .decrypt(
            Alg::OAEP,
            Alg::SHA256,
            &private_key[..priv_len],
            &c,
            &mut decrypted,
            label,
        )
        .unwrap();
    assert_eq!(&decrypted[..dec_len], plaintext);

    // Decrypt with incorrect label -> should fail (HardwareFailure)
    let bad_label = b"wrong_label";
    let mut decrypted_bad = [0u8; 128];
    let res = provider.decrypt(
        Alg::OAEP,
        Alg::SHA256,
        &private_key[..priv_len],
        &c,
        &mut decrypted_bad,
        bad_label,
    );
    assert_eq!(res.unwrap_err(), CryptoError::HardwareFailure);

    // Decrypt with empty label -> should fail
    let res_empty = provider.decrypt(
        Alg::OAEP,
        Alg::SHA256,
        &private_key[..priv_len],
        &c,
        &mut decrypted_bad,
        &[],
    );
    assert_eq!(res_empty.unwrap_err(), CryptoError::HardwareFailure);
}

#[test]
fn adv_test_ecc_invalid_scalar_len() {
    let provider = TestProvider;
    let scalar_too_large = [1u8; 33];
    let mut out = [0u8; 64];

    // NIST P-256
    let res1 = provider.point_multiply_generator(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar_too_large,
        &mut out,
    );
    assert_eq!(res1.unwrap_err(), CryptoError::InvalidData);

    let pt = [0u8; 64];
    let res2 = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &scalar_too_large,
        &pt,
        &mut out,
    );
    assert_eq!(res2.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn adv_test_rsa_sign_buffer_too_small() {
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

    let digest = [0xAAu8; 32];
    // Output signature buffer size for 1024-bit RSA key is 128 bytes.
    // Let's pass 127 bytes buffer.
    let mut signature = [0u8; 127];

    let res = provider.sign_inner(
        Alg::RSAPSS,
        &private_key[..priv_len],
        tpm2::TpmtHa::Sha256(&digest),
        &mut signature,
    );
    assert_eq!(res.unwrap_err(), CryptoError::BufferTooSmall);
}

#[test]
fn adv_test_signature_verification_edge_cases() {
    let provider = TestProvider;

    // 1. RSA setup
    let mut rsa_pub1 = [0u8; 1024];
    let mut rsa_priv1 = [0u8; 2048];
    let (rsa_pub1_len, rsa_priv1_len) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                2048,
            ))),
            &mut rsa_pub1,
            &mut rsa_priv1,
            None,
        )
        .unwrap();

    let mut rsa_pub2 = [0u8; 1024];
    let mut rsa_priv2 = [0u8; 2048];
    let (rsa_pub2_len, _) = provider
        .generate_key(
            Alg::RSA,
            Some(tpm2::crypto::asymmetric::KeyParams::Rsa(TpmiRsaKeyBits(
                2048,
            ))),
            &mut rsa_pub2,
            &mut rsa_priv2,
            None,
        )
        .unwrap();

    let digest = [0xBCu8; 32];
    let mut signature = [0u8; 256];

    // Sign with RSASSA SHA256
    let sig_len = provider
        .sign_inner(
            Alg::RSASSA,
            &rsa_priv1[..rsa_priv1_len],
            tpm2::TpmtHa::Sha256(&digest),
            &mut signature,
        )
        .unwrap();

    // Verify successfully
    provider
        .verify_inner(
            Alg::RSASSA,
            &rsa_pub1[..rsa_pub1_len],
            tpm2::TpmtHa::Sha256(&digest),
            &signature[..sig_len],
        )
        .unwrap();

    // Challenge 1: Corrupted RSA signature
    {
        let mut corrupted_sig = signature;
        corrupted_sig[sig_len / 2] ^= 0xFF;
        let res = provider.verify_inner(
            Alg::RSASSA,
            &rsa_pub1[..rsa_pub1_len],
            tpm2::TpmtHa::Sha256(&digest),
            &corrupted_sig[..sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    }

    // Challenge 2: Wrong hash algorithm for RSA signature verification
    {
        let digest_sha384 = [0xBCu8; 48];
        let res = provider.verify_inner(
            Alg::RSASSA,
            &rsa_pub1[..rsa_pub1_len],
            tpm2::TpmtHa::Sha384(&digest_sha384),
            &signature[..sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    }

    // Challenge 3: Mismatched keys (verify using public key 2)
    {
        let res = provider.verify_inner(
            Alg::RSASSA,
            &rsa_pub2[..rsa_pub2_len],
            tpm2::TpmtHa::Sha256(&digest),
            &signature[..sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    }

    // Challenge 4: Unsupported scheme (e.g. verify using Alg::ECDSA with RSA public key/signature sizes)
    {
        let res = provider.verify_inner(
            Alg::ECDSA,
            &rsa_pub1[..rsa_pub1_len],
            tpm2::TpmtHa::Sha256(&digest),
            &signature[..sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::InvalidData); // because public_key.len() != 64 or signature.len() != 64
    }

    // 2. ECC setup
    let mut ecc_pub1 = [0u8; 64];
    let mut ecc_priv1 = [0u8; 32];
    let (ecc_pub1_len, ecc_priv1_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut ecc_pub1,
            &mut ecc_priv1,
            None,
        )
        .unwrap();

    let mut ecc_pub2 = [0u8; 64];
    let mut ecc_priv2 = [0u8; 32];
    let (ecc_pub2_len, _) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut ecc_pub2,
            &mut ecc_priv2,
            None,
        )
        .unwrap();

    let ecc_digest = [0xDEu8; 32];
    let mut ecc_signature = [0u8; 64];

    // Sign with ECDSA (implies SHA256)
    let ecc_sig_len = provider
        .sign_inner(
            Alg::ECDSA,
            &ecc_priv1[..ecc_priv1_len],
            tpm2::TpmtHa::Sha256(&ecc_digest),
            &mut ecc_signature,
        )
        .unwrap();
    assert_eq!(ecc_sig_len, 64);

    // Verify successfully
    provider
        .verify_inner(
            Alg::ECDSA,
            &ecc_pub1[..ecc_pub1_len],
            tpm2::TpmtHa::Sha256(&ecc_digest),
            &ecc_signature[..ecc_sig_len],
        )
        .unwrap();

    // Challenge 5: Corrupted ECC signature
    {
        let mut corrupted_sig = ecc_signature;
        corrupted_sig[ecc_sig_len / 2] ^= 0xFF;
        let res = provider.verify_inner(
            Alg::ECDSA,
            &ecc_pub1[..ecc_pub1_len],
            tpm2::TpmtHa::Sha256(&ecc_digest),
            &corrupted_sig[..ecc_sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    }

    // Challenge 6: Wrong digest / hash algorithm for ECC signature verification
    {
        let ecc_digest_sha384 = [0xBCu8; 48];
        let res = provider.verify_inner(
            Alg::ECDSA,
            &ecc_pub1[..ecc_pub1_len],
            tpm2::TpmtHa::Sha384(&ecc_digest_sha384),
            &ecc_signature[..ecc_sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    }

    // Challenge 7: Mismatched ECC keys
    {
        let res = provider.verify_inner(
            Alg::ECDSA,
            &ecc_pub2[..ecc_pub2_len],
            tpm2::TpmtHa::Sha256(&ecc_digest),
            &ecc_signature[..ecc_sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
    }

    // Challenge 8: Invalid ECC buffer sizes (length != 64)
    {
        let res = provider.verify_inner(
            Alg::ECDSA,
            &ecc_pub1[..ecc_pub1_len - 1],
            tpm2::TpmtHa::Sha256(&ecc_digest),
            &ecc_signature[..ecc_sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::InvalidData);

        let res2 = provider.verify_inner(
            Alg::ECDSA,
            &ecc_pub1[..ecc_pub1_len],
            tpm2::TpmtHa::Sha256(&ecc_digest),
            &ecc_signature[..ecc_sig_len - 1],
        );
        assert_eq!(res2.unwrap_err(), CryptoError::InvalidData);
    }

    // Challenge 9: Completely unsupported algorithms
    {
        let res = provider.verify_inner(
            Alg::AES,
            &ecc_pub1[..ecc_pub1_len],
            tpm2::TpmtHa::Sha256(&ecc_digest),
            &ecc_signature[..ecc_sig_len],
        );
        assert_eq!(res.unwrap_err(), CryptoError::UnsupportedAlgorithm);

        let mut out = [0u8; 256];
        // With an ECC key, sign_inner(Alg::AES) fails matching scheme -> UnsupportedAlgorithm
        let res2 = provider.sign_inner(
            Alg::AES,
            &ecc_priv1[..ecc_priv1_len],
            tpm2::TpmtHa::Sha256(&ecc_digest),
            &mut out[..64],
        );
        assert_eq!(res2.unwrap_err(), CryptoError::UnsupportedAlgorithm);

        // With an RSA key, sign_inner(Alg::AES) parses key successfully but fails matching scheme -> UnsupportedAlgorithm
        let res3 = provider.sign_inner(
            Alg::AES,
            &rsa_priv1[..rsa_priv1_len],
            tpm2::TpmtHa::Sha256(&digest),
            &mut out,
        );
        assert_eq!(res3.unwrap_err(), CryptoError::UnsupportedAlgorithm);
    }
}
