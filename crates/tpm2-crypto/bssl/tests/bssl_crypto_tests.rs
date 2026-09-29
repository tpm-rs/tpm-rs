#![forbid(unsafe_code)]

use hex_literal::hex;
use tpm2::crypto::ecc::{Ecc, EccCurve};
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::{TpmEccCurve, TpmiAlgHash, TpmtHa};
use tpm2_crypto_bssl::*;

// =========================================================================
// Tests from src/asymmetric.rs
// =========================================================================

#[test]
fn test_nist_p224_keygen_and_ecdsa_sign_verify() {
    let provider = BsslCryptoProvider;
    let mut pub_key = [0u8; 56];
    let mut priv_key = [0u8; 28];
    let (pub_len, priv_len) = provider
        .ecc_generate_key(TpmEccCurve::NistP224, &mut pub_key, &mut priv_key, None)
        .unwrap();
    assert_eq!(pub_len, 56);
    assert_eq!(priv_len, 28);

    // Sign with SHA-256 digest
    let digest_bytes = [0x42u8; 32];
    let digest_ha = TpmtHa::new(TpmiAlgHash::Sha256, &digest_bytes).unwrap();
    let mut sig = [0u8; 56];
    let sig_len = provider
        .ecdsa_sign(&priv_key[..priv_len], digest_ha, &mut sig)
        .unwrap();
    assert_eq!(sig_len, 56);

    // Verify valid signature
    provider
        .ecdsa_verify(&pub_key[..pub_len], digest_ha, &sig[..sig_len])
        .unwrap();

    // Verify that corrupted signature fails
    let mut bad_sig = sig;
    bad_sig[0] ^= 0x01;
    assert!(
        provider
            .ecdsa_verify(&pub_key[..pub_len], digest_ha, &bad_sig[..sig_len])
            .is_err()
    );

    // Verify that corrupted digest fails
    let bad_digest = [0x43u8; 32];
    let bad_ha = TpmtHa::new(TpmiAlgHash::Sha256, &bad_digest).unwrap();
    assert!(
        provider
            .ecdsa_verify(&pub_key[..pub_len], bad_ha, &sig[..sig_len])
            .is_err()
    );
}

#[test]
fn test_ecdsa_cross_hash_algorithms() {
    let provider = BsslCryptoProvider;

    // 1. NIST P-224 with SHA-1 and SHA-256
    let mut pub_p224 = [0u8; 56];
    let mut priv_p224 = [0u8; 28];
    let (pub_len, priv_len) = provider
        .ecc_generate_key(TpmEccCurve::NistP224, &mut pub_p224, &mut priv_p224, None)
        .unwrap();

    for hash_alg in [TpmiAlgHash::Sha1, TpmiAlgHash::Sha256] {
        let digest_bytes = [0x5Au8; 64];
        let digest_size = hash_alg.digest_size();
        let digest_ha = TpmtHa::new(hash_alg, &digest_bytes[..digest_size]).unwrap();
        let mut sig = [0u8; 56];
        let sig_len = provider
            .ecdsa_sign(&priv_p224[..priv_len], digest_ha, &mut sig)
            .unwrap();
        assert_eq!(sig_len, 56);
        provider
            .ecdsa_verify(&pub_p224[..pub_len], digest_ha, &sig[..sig_len])
            .unwrap();
    }

    // 2. NIST P-256 with SHA-1, SHA-256, SHA-384, SHA-512 (verifying fix for cross-hash ECDSA)
    let mut pub_p256 = [0u8; 64];
    let mut priv_p256 = [0u8; 32];
    let (pub_len, priv_len) = provider
        .ecc_generate_key(TpmEccCurve::NistP256, &mut pub_p256, &mut priv_p256, None)
        .unwrap();

    for hash_alg in [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ] {
        let digest_bytes = [0x6Bu8; 64];
        let digest_size = hash_alg.digest_size();
        let digest_ha = TpmtHa::new(hash_alg, &digest_bytes[..digest_size]).unwrap();
        let mut sig = [0u8; 64];
        let sig_len = provider
            .ecdsa_sign(&priv_p256[..priv_len], digest_ha, &mut sig)
            .unwrap();
        assert_eq!(sig_len, 64);
        provider
            .ecdsa_verify(&pub_p256[..pub_len], digest_ha, &sig[..sig_len])
            .unwrap();
    }

    // 3. NIST P-384 with SHA-256, SHA-384, SHA-512
    let mut pub_p384 = [0u8; 96];
    let mut priv_p384 = [0u8; 48];
    let (pub_len, priv_len) = provider
        .ecc_generate_key(TpmEccCurve::NistP384, &mut pub_p384, &mut priv_p384, None)
        .unwrap();

    for hash_alg in [
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ] {
        let digest_bytes = [0x7Cu8; 64];
        let digest_size = hash_alg.digest_size();
        let digest_ha = TpmtHa::new(hash_alg, &digest_bytes[..digest_size]).unwrap();
        let mut sig = [0u8; 96];
        let sig_len = provider
            .ecdsa_sign(&priv_p384[..priv_len], digest_ha, &mut sig)
            .unwrap();
        assert_eq!(sig_len, 96);
        provider
            .ecdsa_verify(&pub_p384[..pub_len], digest_ha, &sig[..sig_len])
            .unwrap();
    }
}

// =========================================================================
// Tests from src/ecc.rs
// =========================================================================

#[test]
fn test_bssl_ecc_nist_p224_operations() {
    let provider = BsslCryptoProvider;
    let ctx = provider.nist_p224().unwrap();

    // 1. Point multiplication with generator using scalar = 1 (generator point G)
    let mut scalar_one = [0u8; 28];
    scalar_one[27] = 1;
    let mut gx = [0u8; 28];
    let mut gy = [0u8; 28];
    ctx.point_multiply_generator(&scalar_one, &mut gx, &mut gy)
        .unwrap();

    // 2. Validate generator point G
    ctx.validate_point(&gx, &gy).unwrap();

    // 3. Point multiplication G * 1 == G
    let mut mx = [0u8; 28];
    let mut my = [0u8; 28];
    ctx.point_multiply(&scalar_one, &gx, &gy, &mut mx, &mut my)
        .unwrap();
    assert_eq!(mx, gx);
    assert_eq!(my, gy);

    // 4. Point multiplication with generator using scalar = 2
    let mut scalar_two = [0u8; 28];
    scalar_two[27] = 2;
    let mut g2x = [0u8; 28];
    let mut g2y = [0u8; 28];
    ctx.point_multiply_generator(&scalar_two, &mut g2x, &mut g2y)
        .unwrap();
    ctx.validate_point(&g2x, &g2y).unwrap();
    assert_ne!(g2x, gx);

    // 5. Point multiplication G * 2 == 2*G
    let mut g2_from_g_x = [0u8; 28];
    let mut g2_from_g_y = [0u8; 28];
    ctx.point_multiply(&scalar_two, &gx, &gy, &mut g2_from_g_x, &mut g2_from_g_y)
        .unwrap();
    assert_eq!(g2_from_g_x, g2x);
    assert_eq!(g2_from_g_y, g2y);

    // 6. Invalid point validation returns error
    let invalid_x = [0xFFu8; 28];
    let invalid_y = [0xFFu8; 28];
    assert!(ctx.validate_point(&invalid_x, &invalid_y).is_err());
}

#[test]
fn test_bssl_ecc_nist_p256_ecdaa_sign() {
    let provider = BsslCryptoProvider;
    let ctx = provider.nist_p256().unwrap();

    let commit_r = [0x05u8; 32];
    let private_key_d = [0x07u8; 32];
    let digest = [0x42u8; 32];
    let mut nonce_k = [0u8; 32];
    let mut s = [0u8; 32];

    // 1. Basic ECDAA sign without commit_x and commit_p1
    ctx.ecdaa_sign(
        &commit_r,
        &[],
        &[],
        &private_key_d,
        &digest,
        &mut nonce_k,
        &mut s,
    )
    .unwrap();

    assert!(!nonce_k.iter().all(|&b| b == 0));
    assert!(!s.iter().all(|&b| b == 0));

    // 2. ECDAA sign with commit_p1 matching 42*G
    let mut s42 = [0u8; 32];
    s42[31] = 42;
    let mut p42_x = [0u8; 32];
    let mut p42_y = [0u8; 32];
    ctx.point_multiply_generator(&s42, &mut p42_x, &mut p42_y)
        .unwrap();

    let mut s_p42 = [0u8; 32];
    ctx.ecdaa_sign(
        &commit_r,
        &[],
        &p42_x,
        &private_key_d,
        &digest,
        &mut nonce_k,
        &mut s_p42,
    )
    .unwrap();

    assert_ne!(s, s_p42);

    // 3. ECDAA sign with commit_p1 matching 55*G
    let mut s55 = [0u8; 32];
    s55[31] = 55;
    let mut p55_x = [0u8; 32];
    let mut p55_y = [0u8; 32];
    ctx.point_multiply_generator(&s55, &mut p55_x, &mut p55_y)
        .unwrap();

    let mut s_p55 = [0u8; 32];
    ctx.ecdaa_sign(
        &commit_r,
        &[],
        &p55_x,
        &private_key_d,
        &digest,
        &mut nonce_k,
        &mut s_p55,
    )
    .unwrap();

    assert_ne!(s, s_p55);
    assert_ne!(s_p42, s_p55);

    // 4. ECDAA sign with commit_p1 matching d*G (public key)
    let mut pq_x = [0u8; 32];
    let mut pq_y = [0u8; 32];
    ctx.point_multiply_generator(&private_key_d, &mut pq_x, &mut pq_y)
        .unwrap();

    let mut s_pq = [0u8; 32];
    ctx.ecdaa_sign(
        &commit_r,
        &[],
        &pq_x,
        &private_key_d,
        &digest,
        &mut nonce_k,
        &mut s_pq,
    )
    .unwrap();

    assert_ne!(s, s_pq);

    // 5. Verify exact mathematical test vector with commit_x
    let mut e_x_custom = [0u8; 32];
    e_x_custom[30] = 0x30;
    e_x_custom[31] = 0x39; // 12345
    let mut nonce_k_exact = [0u8; 32];
    let mut s_exact = [0u8; 32];
    ctx.ecdaa_sign(
        &commit_r,
        &e_x_custom,
        &[],
        &private_key_d,
        &digest,
        &mut nonce_k_exact,
        &mut s_exact,
    )
    .unwrap();

    assert_eq!(
        nonce_k_exact,
        hex!("425ed4e4a36b30ea21b90e21c712c649e8214c29b7eaf68089d1039c6e55384c")
    );
    assert_eq!(
        s_exact,
        hex!("e4e3d7cb096c11649b1d5b96a16100cc6ab4b3923d2a77dd79b96cd734296154")
    );

    // 6. Verify exact mathematical test vector with commit_p1 matching 42*G
    let mut s_42_exact = [0u8; 32];
    ctx.ecdaa_sign(
        &commit_r,
        &e_x_custom,
        &p42_x,
        &private_key_d,
        &digest,
        &mut nonce_k_exact,
        &mut s_42_exact,
    )
    .unwrap();
    assert_eq!(
        s_42_exact,
        hex!("8d6167748bbada5c72d106b679ea219334433ae4e28dc11ebe918d2014759313")
    );

    // 7. Verify exact mathematical test vector with commit_p1 matching 55*G
    let mut s_55_exact = [0u8; 32];
    ctx.ecdaa_sign(
        &commit_r,
        &e_x_custom,
        &p55_x,
        &private_key_d,
        &digest,
        &mut nonce_k_exact,
        &mut s_55_exact,
    )
    .unwrap();
    assert_eq!(
        s_55_exact,
        hex!("2cf35cd00637bc6c534ead5cabd72bf7c49c992e289a6922804692e9e5e9c48b")
    );

    // 8. Verify exact mathematical test vector with commit_p1 matching d*G
    let mut s_d_exact = [0u8; 32];
    ctx.ecdaa_sign(
        &commit_r,
        &e_x_custom,
        &pq_x,
        &private_key_d,
        &digest,
        &mut nonce_k_exact,
        &mut s_d_exact,
    )
    .unwrap();
    assert_eq!(
        s_d_exact,
        hex!("1f25073ae2645b970d15e5fcb76c130da3417881580fd73e355769e851c3fb6c")
    );

    // 9. Invalid private key (zero scalar) returns error
    let zero_scalar = [0u8; 32];
    assert!(
        ctx.ecdaa_sign(
            &commit_r,
            &[],
            &[],
            &zero_scalar,
            &digest,
            &mut nonce_k,
            &mut s,
        )
        .is_err()
    );
}

// =========================================================================
// Tests from src/bssl.rs
// =========================================================================

#[test]
fn test_hmac_sha1_rfc2202() {
    // RFC 2202 Test Case 1
    let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let expected = hex!("b617318655057264e28bc0b6fb378c8ef146be00");

    let mut ctx = HmacSha1::new_from_slice(&key).unwrap();
    ctx.update(&data[..3]).unwrap();
    let ctx_clone = ctx.clone();
    ctx.update(&data[3..]).unwrap();
    let mut out = [0u8; 20];
    ctx.finalize(&mut out).unwrap();
    assert_eq!(out, expected);

    // Verify cloned context produces identical output
    let mut ctx2 = ctx_clone;
    ctx2.update(&data[3..]).unwrap();
    let mut out2 = [0u8; 20];
    ctx2.finalize(&mut out2).unwrap();
    assert_eq!(out2, expected);
}

#[test]
fn test_hmac_sha1_empty_key_and_data() {
    let mut ctx = HmacSha1::new_from_slice(&[]).unwrap();
    ctx.update(&[]).unwrap();
    let mut out = [0u8; 20];
    ctx.finalize(&mut out).unwrap();
    assert_eq!(out, hex!("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"));
}

#[test]
fn test_cmac_aes_nist_vectors() {
    // NIST SP 800-38B AES-128-CMAC empty message
    let key128 = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut cmac128 = CmacAes128::new(&key128).unwrap();
    cmac128.update(&[]).unwrap();
    let mut out = [0u8; 16];
    cmac128.finalize(&mut out).unwrap();
    assert_eq!(out, hex!("bb1d6929e95937287fa37d129b756746"));

    // NIST SP 800-38B AES-192-CMAC 16-byte message
    let key192 = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    let msg = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut cmac192 = CmacAes192::new(&key192).unwrap();
    cmac192.update(&msg[..5]).unwrap();
    let cmac192_clone = cmac192.clone();
    cmac192.update(&msg[5..]).unwrap();
    cmac192.finalize(&mut out).unwrap();
    assert_eq!(out, hex!("9e99a7bf31e710900662f65e617c5184"));

    let mut cmac192_2 = cmac192_clone;
    cmac192_2.update(&msg[5..]).unwrap();
    let mut out2 = [0u8; 16];
    cmac192_2.finalize(&mut out2).unwrap();
    assert_eq!(out2, hex!("9e99a7bf31e710900662f65e617c5184"));

    // NIST SP 800-38B AES-256-CMAC 16-byte message
    let key256 = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut cmac256 = CmacAes256::new(&key256).unwrap();
    cmac256.update(&msg).unwrap();
    cmac256.finalize(&mut out).unwrap();
    assert_eq!(out, hex!("22c2ef5b01082373365b34de01a7de91"));
}

#[test]
fn test_aes_cfb128_nist_vectors_and_streaming() {
    // NIST SP 800-38A CFB128-AES128
    let key128 = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex!("000102030405060708090a0b0c0d0e0f");
    let pt = hex!(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    );
    let expected_ct = hex!(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
    );

    // Test streaming chunk sizes: 3, 13, 5, 11 bytes
    let mut buf = pt;
    let mut enc = Aes128Cfb::new_encrypt(&key128, &iv).unwrap();
    enc.update(&mut buf[0..3]).unwrap();
    enc.update(&mut buf[3..16]).unwrap();
    enc.update(&mut buf[16..21]).unwrap();
    enc.update(&mut buf[21..32]).unwrap();
    let mut iv_out = [0u8; 16];
    enc.finalize(&mut iv_out).unwrap();
    assert_eq!(buf, expected_ct);
    assert_eq!(iv_out, expected_ct[16..32]);

    // Decrypt with different chunk sizes: 7, 10, 15 bytes
    let mut dec = Aes128Cfb::new_decrypt(&key128, &iv).unwrap();
    dec.update(&mut buf[0..7]).unwrap();
    dec.update(&mut buf[7..17]).unwrap();
    dec.update(&mut buf[17..32]).unwrap();
    let mut dec_iv_out = [0u8; 16];
    dec.finalize(&mut dec_iv_out).unwrap();
    assert_eq!(buf, pt);
    assert_eq!(dec_iv_out, expected_ct[16..32]);

    // NIST SP 800-38A CFB128-AES192
    let key192 = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    let mut block192 = hex!("6bc1bee22e409f96e93d7e117393172a");
    let expected_ct192 = hex!("cdc80d6fddf18cab34c25909c99a4174");
    let mut enc192 = Aes192Cfb::new_encrypt(&key192, &iv).unwrap();
    enc192.update(&mut block192).unwrap();
    enc192.finalize(&mut iv_out).unwrap();
    assert_eq!(block192, expected_ct192);

    // NIST SP 800-38A CFB128-AES256
    let key256 = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut block256 = hex!("6bc1bee22e409f96e93d7e117393172a");
    let expected_ct256 = hex!("b5a8a1747ed889ebce581f4ea2a5646e");
    let mut enc256 = Aes256Cfb::new_encrypt(&key256, &iv).unwrap();
    enc256.update(&mut block256).unwrap();
    enc256.finalize(&mut iv_out).unwrap();
    assert_eq!(block256, expected_ct256);
}

#[test]
fn test_aes_cfb_partial_block_iv_and_cloning() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let iv0 = hex!("000102030405060708090a0b0c0d0e0f");

    // Encrypt 21 bytes (1 full block of 16 bytes + 5 partial bytes)
    let pt = [0x42u8; 21];
    let mut ct_oneshot = pt;
    let mut enc1 = Aes128Cfb::new_encrypt(&key, &iv0).unwrap();
    enc1.update(&mut ct_oneshot).unwrap();
    let mut iv_out_1 = [0u8; 16];
    enc1.finalize(&mut iv_out_1).unwrap();

    // Expected iv_out for 21 bytes:
    // first 5 bytes are ct[16..21], remaining 11 bytes are ct[5..16] (from the previous block's IV)
    let mut expected_iv_out = [0u8; 16];
    expected_iv_out[..5].copy_from_slice(&ct_oneshot[16..21]);
    expected_iv_out[5..].copy_from_slice(&ct_oneshot[5..16]);
    assert_eq!(iv_out_1, expected_iv_out);

    // Encrypt 1 byte at a time and test cloning mid-stream
    let mut ct_byte_by_byte = pt;
    let mut enc2 = Aes128Cfb::new_encrypt(&key, &iv0).unwrap();
    for i in 0..10 {
        enc2.update(&mut ct_byte_by_byte[i..i + 1]).unwrap();
    }
    let mut enc2_clone = enc2.clone();
    let mut ct_clone_branch = ct_byte_by_byte;

    for i in 10..21 {
        enc2.update(&mut ct_byte_by_byte[i..i + 1]).unwrap();
        enc2_clone.update(&mut ct_clone_branch[i..i + 1]).unwrap();
    }
    let mut iv_out_2 = [0u8; 16];
    enc2.finalize(&mut iv_out_2).unwrap();
    let mut iv_out_clone = [0u8; 16];
    enc2_clone.finalize(&mut iv_out_clone).unwrap();

    assert_eq!(ct_byte_by_byte, ct_oneshot);
    assert_eq!(ct_clone_branch, ct_oneshot);
    assert_eq!(iv_out_2, expected_iv_out);
    assert_eq!(iv_out_clone, expected_iv_out);

    // Decrypt 1 byte at a time and verify iv_out matches encryption iv_out
    let mut dec_buf = ct_oneshot;
    let mut dec = Aes128Cfb::new_decrypt(&key, &iv0).unwrap();
    for i in 0..21 {
        dec.update(&mut dec_buf[i..i + 1]).unwrap();
    }
    let mut dec_iv_out = [0u8; 16];
    dec.finalize(&mut dec_iv_out).unwrap();
    assert_eq!(dec_buf, pt);
    assert_eq!(dec_iv_out, expected_iv_out);
}

#[test]
fn test_rsa_sign_verify_and_encrypt_decrypt() {
    // Test both random (`seed = None`) and deterministic (`seed = Some(...)`) 1024-bit RSA key generation
    let mut pub_bytes = [0u8; 128];
    let mut priv_der = [0u8; 1024];
    let (pub_len, priv_len) = rsa_generate_key(1024, &mut pub_bytes, &mut priv_der, None).unwrap();
    assert_eq!(pub_len, 128);
    assert!(priv_len > 0);

    // Verify deterministic keygen produces identical keys for the same seed
    let mut det_pub1 = [0u8; 128];
    let mut det_priv1 = [0u8; 1024];
    let mut det_pub2 = [0u8; 128];
    let mut det_priv2 = [0u8; 1024];
    let (dp1_len, dpr1_len) =
        rsa_generate_key(1024, &mut det_pub1, &mut det_priv1, Some(b"test_seed")).unwrap();
    let (dp2_len, dpr2_len) =
        rsa_generate_key(1024, &mut det_pub2, &mut det_priv2, Some(b"test_seed")).unwrap();
    assert_eq!(&det_pub1[..dp1_len], &det_pub2[..dp2_len]);
    assert_eq!(&det_priv1[..dpr1_len], &det_priv2[..dpr2_len]);
    let mut det_sig = [0u8; 128];
    rsa_sign_pkcs1v15(
        &det_priv1[..dpr1_len],
        TpmiAlgHash::Sha256,
        &[0x33u8; 32],
        &mut det_sig,
    )
    .unwrap();
    rsa_verify_pkcs1v15(
        &det_pub1[..dp1_len],
        TpmiAlgHash::Sha256,
        &[0x33u8; 32],
        &det_sig,
    )
    .unwrap();

    let priv_der_slice = &priv_der[..priv_len];
    let digest = [0x11u8; 32];
    let mut sig = [0u8; 128];

    // RSASSA PKCS#1 v1.5
    let sig_len =
        rsa_sign_pkcs1v15(priv_der_slice, TpmiAlgHash::Sha256, &digest, &mut sig).unwrap();
    assert_eq!(sig_len, 128);
    rsa_verify_pkcs1v15(&pub_bytes, TpmiAlgHash::Sha256, &digest, &sig).unwrap();

    // RSAPSS
    let sig_len = rsa_sign_pss(priv_der_slice, TpmiAlgHash::Sha256, &digest, &mut sig).unwrap();
    assert_eq!(sig_len, 128);
    rsa_verify_pss(&pub_bytes, TpmiAlgHash::Sha256, &digest, &sig).unwrap();

    // RSAES PKCS#1 v1.5
    let msg = b"Hello RSAES!";
    let mut ct = [0u8; 128];
    let ct_len = rsa_encrypt_pkcs1v15(&pub_bytes, msg, &mut ct).unwrap();
    assert_eq!(ct_len, 128);
    let mut pt = [0u8; 64]; // Intentionally smaller than modulus (128)
    let pt_len = rsa_decrypt_pkcs1v15(priv_der_slice, &ct, &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], msg);

    // RSA-OAEP with label
    let label = b"DUPLICATE\0";
    let ct_len = rsa_encrypt_oaep(TpmiAlgHash::Sha256, &pub_bytes, msg, label, &mut ct).unwrap();
    assert_eq!(ct_len, 128);
    let pt_len =
        rsa_decrypt_oaep(TpmiAlgHash::Sha256, priv_der_slice, &ct, label, &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], msg);

    // RSA-NULL
    let raw_msg = [0x01u8; 32];
    let mut raw_ct = [0u8; 128];
    let raw_ct_len = rsa_encrypt_null(&pub_bytes, &raw_msg, &mut raw_ct).unwrap();
    assert_eq!(raw_ct_len, 128);
    let mut raw_pt = [0u8; 128];
    let raw_pt_len = rsa_decrypt_null(priv_der_slice, &raw_ct, &mut raw_pt).unwrap();
    assert_eq!(raw_pt_len, 128);
    assert_eq!(&raw_pt[128 - 32..], &raw_msg);

    // RSA Import / Export prime p
    let mut prime_p_buf = [0u8; 64];
    let p_len = rsa_private_key_to_prime_p(priv_der_slice, &mut prime_p_buf).unwrap();
    let mut imported_der = [0u8; 1024];
    let imp_len =
        rsa_import_private_key(&pub_bytes, &prime_p_buf[..p_len], 65537, &mut imported_der)
            .unwrap();
    let mut dec_pt = [0u8; 64];
    let dec_len = rsa_decrypt_oaep(
        TpmiAlgHash::Sha256,
        &imported_der[..imp_len],
        &ct,
        label,
        &mut dec_pt,
    )
    .unwrap();
    assert_eq!(&dec_pt[..dec_len], msg);
}

#[test]
fn test_ecc_p224_p256_p384_p521_bnp256_operations() {
    for group in [
        EcGroup::P224,
        EcGroup::P256,
        EcGroup::P384,
        EcGroup::P521,
        EcGroup::BnP256,
    ] {
        let mut rng = BsslRng;
        let coord_len = group.coord_len();
        let mut pub_key = [0u8; 132];
        let mut priv_key = [0u8; 66];
        let (pub_len, priv_len) = ec_generate_key(
            group,
            &mut rng,
            &mut pub_key[..2 * coord_len],
            &mut priv_key[..coord_len],
        )
        .unwrap();
        assert_eq!(pub_len, 2 * coord_len);
        assert_eq!(priv_len, coord_len);

        let x = &pub_key[..coord_len];
        let y = &pub_key[coord_len..2 * coord_len];
        ec_validate_point(group, x, y).unwrap();

        // Verify generator multiplication matches public key
        let mut gx = [0u8; 66];
        let mut gy = [0u8; 66];
        ec_point_multiply_generator(
            group,
            &priv_key[..coord_len],
            &mut gx[..coord_len],
            &mut gy[..coord_len],
        )
        .unwrap();
        assert_eq!(&gx[..coord_len], x);
        assert_eq!(&gy[..coord_len], y);

        // Arbitrary point multiplication: 1 * Q == Q
        let mut one = [0u8; 66];
        one[coord_len - 1] = 1;
        let mut mx = [0u8; 66];
        let mut my = [0u8; 66];
        ec_point_multiply(
            group,
            &one[..coord_len],
            x,
            y,
            &mut mx[..coord_len],
            &mut my[..coord_len],
        )
        .unwrap();
        assert_eq!(&mx[..coord_len], x);
        assert_eq!(&my[..coord_len], y);

        // ECDSA sign and verify
        let digest = [0x22u8; 64];
        let digest_len = coord_len.min(64);
        let mut sig = [0u8; 132];
        let sig_len = ecdsa_sign(
            group,
            &priv_key[..coord_len],
            &digest[..digest_len],
            &mut sig[..2 * coord_len],
        )
        .unwrap();
        assert_eq!(sig_len, 2 * coord_len);
        ecdsa_verify(
            group,
            &pub_key[..2 * coord_len],
            &digest[..digest_len],
            &sig[..2 * coord_len],
        )
        .unwrap();
    }
}

#[test]
fn test_p256_ecdaa_sign() {
    let commit_r = [0x01u8; 32];
    let private_key_d = [0x02u8; 32];
    let digest = [0x03u8; 32];
    let mut nonce_k = [0u8; 32];
    let mut s = [0u8; 32];

    // Basic sign without commit_x / commit_p1
    p256_ecdaa_sign(
        &commit_r,
        &[],
        &[],
        &private_key_d,
        &digest,
        &mut nonce_k,
        &mut s,
    )
    .unwrap();

    assert!(!nonce_k.iter().all(|&b| b == 0));
    assert!(!s.iter().all(|&b| b == 0));

    // Sign with commit_p1 matching 42*G
    let mut s42 = [0u8; 32];
    s42[31] = 42;
    let mut p42_x = [0u8; 32];
    let mut p42_y = [0u8; 32];
    ec_point_multiply_generator(EcGroup::P256, &s42, &mut p42_x, &mut p42_y).unwrap();

    let mut s_with_p42 = [0u8; 32];
    p256_ecdaa_sign(
        &commit_r,
        &[],
        &p42_x,
        &private_key_d,
        &digest,
        &mut nonce_k,
        &mut s_with_p42,
    )
    .unwrap();

    assert_ne!(s, s_with_p42);
}
