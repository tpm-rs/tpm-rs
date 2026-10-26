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
        .unwrap()
        .unwrap();
    assert_eq!(sig_len, 56);

    // Verify valid signature
    assert_eq!(
        provider.ecdsa_verify(&pub_key[..pub_len], digest_ha, &sig[..sig_len]),
        Ok(true)
    );

    // Verify that corrupted signature fails
    let mut bad_sig = sig;
    bad_sig[0] ^= 0x01;
    assert_eq!(
        provider.ecdsa_verify(&pub_key[..pub_len], digest_ha, &bad_sig[..sig_len]),
        Ok(false)
    );

    // Verify that corrupted digest fails
    let bad_digest = [0x43u8; 32];
    let bad_ha = TpmtHa::new(TpmiAlgHash::Sha256, &bad_digest).unwrap();
    assert_eq!(
        provider.ecdsa_verify(&pub_key[..pub_len], bad_ha, &sig[..sig_len]),
        Ok(false)
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
            .unwrap()
            .unwrap();
        assert_eq!(sig_len, 56);
        assert_eq!(
            provider.ecdsa_verify(&pub_p224[..pub_len], digest_ha, &sig[..sig_len]),
            Ok(true)
        );
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
            .unwrap()
            .unwrap();
        assert_eq!(sig_len, 64);
        assert_eq!(
            provider.ecdsa_verify(&pub_p256[..pub_len], digest_ha, &sig[..sig_len]),
            Ok(true)
        );
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
            .unwrap()
            .unwrap();
        assert_eq!(sig_len, 96);
        assert_eq!(
            provider.ecdsa_verify(&pub_p384[..pub_len], digest_ha, &sig[..sig_len]),
            Ok(true)
        );
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
    assert_eq!(
        ctx.point_multiply_generator(&scalar_one, &mut gx, &mut gy),
        Ok(Some(()))
    );

    // 2. Validate generator point G
    assert_eq!(ctx.validate_point(&gx, &gy), Ok(true));

    // 3. Point multiplication G * 1 == G
    let mut mx = [0u8; 28];
    let mut my = [0u8; 28];
    assert_eq!(
        ctx.point_multiply(&scalar_one, &gx, &gy, &mut mx, &mut my),
        Ok(Some(()))
    );
    assert_eq!(mx, gx);
    assert_eq!(my, gy);

    // 4. Point multiplication with generator using scalar = 2
    let mut scalar_two = [0u8; 28];
    scalar_two[27] = 2;
    let mut g2x = [0u8; 28];
    let mut g2y = [0u8; 28];
    assert_eq!(
        ctx.point_multiply_generator(&scalar_two, &mut g2x, &mut g2y),
        Ok(Some(()))
    );
    assert_eq!(ctx.validate_point(&g2x, &g2y), Ok(true));
    assert_ne!(g2x, gx);

    // 5. Point multiplication G * 2 == 2*G
    let mut g2_from_g_x = [0u8; 28];
    let mut g2_from_g_y = [0u8; 28];
    assert_eq!(
        ctx.point_multiply(&scalar_two, &gx, &gy, &mut g2_from_g_x, &mut g2_from_g_y),
        Ok(Some(()))
    );
    assert_eq!(g2_from_g_x, g2x);
    assert_eq!(g2_from_g_y, g2y);

    // 6. Invalid point validation returns `Ok(false)`
    let invalid_x = [0xFFu8; 28];
    let invalid_y = [0xFFu8; 28];
    assert_eq!(ctx.validate_point(&invalid_x, &invalid_y), Ok(false));
}

#[test]
fn test_bssl_ecc_nist_p256_ecdaa_sign() {
    // ECDAA signing is implemented in tpm2-impl (it needs the scheme hash); the provider
    // primitive reports that it is not supported instead of producing non-spec signatures.
    let provider = BsslCryptoProvider;
    let ctx = provider.nist_p256().unwrap();
    let mut nonce_k = [0u8; 32];
    let mut s = [0u8; 32];
    assert_eq!(
        ctx.ecdaa_sign(
            &[0x05u8; 32],
            &[],
            &[],
            &[0x07u8; 32],
            &[0x42u8; 32],
            &mut nonce_k,
            &mut s,
        ),
        Err(tpm2::crypto::CryptoError::Unsupported)
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
        0,
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
    rsa_verify_pkcs1v15(&pub_bytes, 0, TpmiAlgHash::Sha256, &digest, &sig).unwrap();

    // RSAPSS
    let sig_len = rsa_sign_pss(priv_der_slice, TpmiAlgHash::Sha256, &digest, &mut sig).unwrap();
    assert_eq!(sig_len, 128);
    rsa_verify_pss(&pub_bytes, 0, TpmiAlgHash::Sha256, &digest, &sig).unwrap();

    // RSAES PKCS#1 v1.5
    let msg = b"Hello RSAES!";
    let mut ct = [0u8; 128];
    let ct_len = rsa_encrypt_pkcs1v15(&pub_bytes, 0, msg, &mut ct).unwrap();
    assert_eq!(ct_len, 128);
    let mut pt = [0u8; 64]; // Intentionally smaller than modulus (128)
    let pt_len = rsa_decrypt_pkcs1v15(priv_der_slice, &ct, &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], msg);

    // RSA-OAEP with label
    let label = b"DUPLICATE\0";
    let ct_len = rsa_encrypt_oaep(TpmiAlgHash::Sha256, &pub_bytes, 0, msg, label, &mut ct).unwrap();
    assert_eq!(ct_len, 128);
    let pt_len =
        rsa_decrypt_oaep(TpmiAlgHash::Sha256, priv_der_slice, &ct, label, &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], msg);

    // RSA-NULL
    let raw_msg = [0x01u8; 32];
    let mut raw_ct = [0u8; 128];
    let raw_ct_len = rsa_encrypt_null(&pub_bytes, 0, &raw_msg, &mut raw_ct).unwrap();
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

// =========================================================================
// Tests of the `tpm2::crypto` trait conventions (merged crypto API)
// =========================================================================

#[test]
fn test_provider_symmetric_cfb_matches_nist_vectors_and_updates_iv() {
    use tpm2::AlgSym;
    use tpm2::crypto::{ModeIv, SymmetricKey, decrypt, encrypt};

    // NIST SP 800-38A CFB128-AES128
    let provider = BsslCryptoProvider;
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let iv0 = hex!("000102030405060708090a0b0c0d0e0f");
    let pt = hex!(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    );
    let expected_ct = hex!(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
    );
    let sym_key = SymmetricKey::new(AlgSym::Aes128, &key).unwrap();

    let mut buf = pt;
    let mut iv = iv0;
    encrypt(&provider, sym_key, ModeIv::Cfb(&mut iv), &mut buf).unwrap();
    assert_eq!(buf, expected_ct);
    // The IV is updated in place with the final chaining value (`ivOut`).
    assert_eq!(iv, expected_ct[16..32]);

    let mut iv = iv0;
    decrypt(&provider, sym_key, ModeIv::Cfb(&mut iv), &mut buf).unwrap();
    assert_eq!(buf, pt);
    assert_eq!(iv, expected_ct[16..32]);

    // Chaining two calls through the updated IV equals one call.
    let mut chained = pt;
    let mut iv = iv0;
    let (first, second) = chained.split_at_mut(16);
    encrypt(&provider, sym_key, ModeIv::Cfb(&mut iv), first).unwrap();
    encrypt(&provider, sym_key, ModeIv::Cfb(&mut iv), second).unwrap();
    assert_eq!(chained, expected_ct);

    // NIST SP 800-38A CFB128-AES192 and CFB128-AES256 (first block)
    let key192 = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    let mut block = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut iv = iv0;
    let sym_key = SymmetricKey::new(AlgSym::Aes192, &key192).unwrap();
    encrypt(&provider, sym_key, ModeIv::Cfb(&mut iv), &mut block).unwrap();
    assert_eq!(block, hex!("cdc80d6fddf18cab34c25909c99a4174"));

    let key256 = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut block = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut iv = iv0;
    let sym_key = SymmetricKey::new(AlgSym::Aes256, &key256).unwrap();
    encrypt(&provider, sym_key, ModeIv::Cfb(&mut iv), &mut block).unwrap();
    assert_eq!(block, hex!("b5a8a1747ed889ebce581f4ea2a5646e"));
}

#[test]
fn test_provider_symmetric_rejects_unsupported_modes_and_ciphers() {
    use tpm2::AlgSym;
    use tpm2::crypto::{CryptoError, Direction, ModeIv, SymmetricKey, encrypt_decrypt};

    let provider = BsslCryptoProvider;
    let key = [0x11u8; 16];
    let aes = SymmetricKey::new(AlgSym::Aes128, &key).unwrap();
    let mut data = [0u8; 16];
    let mut iv = [0u8; 16];
    assert_eq!(
        encrypt_decrypt(&provider, aes, ModeIv::Ecb, Direction::Encrypt, &mut data),
        Err(CryptoError::Unsupported)
    );
    assert_eq!(
        encrypt_decrypt(
            &provider,
            aes,
            ModeIv::Cbc(&mut iv),
            Direction::Decrypt,
            &mut data
        ),
        Err(CryptoError::Unsupported)
    );
    let sm4 = SymmetricKey::new(AlgSym::Sm4_128, &key).unwrap();
    assert_eq!(
        encrypt_decrypt(
            &provider,
            sm4,
            ModeIv::Cfb(&mut iv),
            Direction::Encrypt,
            &mut data
        ),
        Err(CryptoError::Unsupported)
    );
}

#[test]
fn test_provider_hash_hmac_and_cmac_vectors() {
    use tpm2::AlgSym;
    use tpm2::crypto::{CryptoError, HashStream, SymmetricKey, cmac, hash, hmac};

    let provider = BsslCryptoProvider;
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

    // FIPS 180-2 SHA-256("abc")
    let digest = hash(&provider, TpmiAlgHash::Sha256, b"abc", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );

    // Streaming gives the same digest.
    let mut stream = HashStream::new(&provider, TpmiAlgHash::Sha256).unwrap();
    stream.update(b"a").unwrap();
    stream.update(b"bc").unwrap();
    let mut out2 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    assert_eq!(stream.finalize(&mut out2).unwrap(), digest);

    // RFC 4231 test case 1 (HMAC-SHA-256) and RFC 2202 test case 1 (HMAC-SHA-1)
    let key = [0x0bu8; 20];
    let mac = hmac(&provider, TpmiAlgHash::Sha256, &key, b"Hi There", &mut out).unwrap();
    assert_eq!(
        mac.digest(),
        hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    let mac = hmac(&provider, TpmiAlgHash::Sha1, &key, b"Hi There", &mut out).unwrap();
    assert_eq!(
        mac.digest(),
        hex!("b617318655057264e28bc0b6fb378c8ef146be00")
    );

    // SM3 is not implemented by this provider.
    assert_eq!(
        hash(&provider, TpmiAlgHash::Sm3_256, b"abc", &mut out),
        Err(CryptoError::Unsupported)
    );

    // NIST SP 800-38B AES-128-CMAC (empty message)
    let key128 = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut tag = [0u8; 16];
    cmac(
        &provider,
        SymmetricKey::new(AlgSym::Aes128, &key128).unwrap(),
        &[],
        &mut tag,
    )
    .unwrap();
    assert_eq!(tag, hex!("bb1d6929e95937287fa37d129b756746"));
}

#[test]
fn test_provider_random_and_constant_time_eq() {
    use tpm2::crypto::{ConstantTimeEq, CryptoError, CryptoProvider, Random};

    let provider = BsslCryptoProvider;
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    provider.get_random(&mut a).unwrap();
    provider.get_random(&mut b).unwrap();
    assert_ne!(a, [0u8; 32]);
    assert_ne!(a, b);
    assert_eq!(provider.stir_random(b"additional entropy"), Ok(()));

    // The provider has no `Rng` factory.
    assert!(matches!(provider.rng(), Err(CryptoError::Unsupported)));
    assert!(matches!(
        provider.rng_seeded(b"seed"),
        Err(CryptoError::Unsupported)
    ));

    assert!(provider.constant_time_eq(&a, &a));
    let mut c = a;
    c[31] ^= 0x80;
    assert!(!provider.constant_time_eq(&a, &c));
    assert!(provider.constant_time_eq::<0>(&[], &[]));
}

#[test]
fn test_provider_rsa_semantic_failures_are_ok_none_or_false() {
    use tpm2::{Alg, TpmiRsaKeyBits};

    let provider = BsslCryptoProvider;
    let mut pub_key = [0u8; 128];
    let mut priv_key = [0u8; 1024];
    let (pub_len, priv_len) = provider
        .rsa_generate_key(
            TpmiRsaKeyBits(1024),
            &mut pub_key,
            &mut priv_key,
            Some(b"semantic failures"),
        )
        .unwrap();
    let (pub_key, priv_key) = (&pub_key[..pub_len], &priv_key[..priv_len]);

    // OAEP round trip, then a wrong label and a corrupted ciphertext.
    let msg = b"secret";
    let mut ct = [0u8; 128];
    let ct_len = provider
        .oaep_encrypt(TpmiAlgHash::Sha256, pub_key, 0, msg, b"LABEL\0", &mut ct)
        .unwrap()
        .unwrap();
    let mut pt = [0u8; 128];
    let pt_len = provider
        .oaep_decrypt(
            TpmiAlgHash::Sha256,
            priv_key,
            &ct[..ct_len],
            b"LABEL\0",
            &mut pt,
        )
        .unwrap()
        .unwrap();
    assert_eq!(&pt[..pt_len], msg);
    assert_eq!(
        provider.oaep_decrypt(
            TpmiAlgHash::Sha256,
            priv_key,
            &ct[..ct_len],
            b"OTHER\0",
            &mut pt
        ),
        Ok(None)
    );
    let mut bad_ct = ct;
    bad_ct[5] ^= 0x01;
    assert_eq!(
        provider.oaep_decrypt(
            TpmiAlgHash::Sha256,
            priv_key,
            &bad_ct[..ct_len],
            b"LABEL\0",
            &mut pt
        ),
        Ok(None)
    );

    // Messages too large for the padding scheme.
    assert_eq!(
        provider.rsaes_encrypt(pub_key, 0, &[0x42u8; 118], &mut ct),
        Ok(None)
    );
    assert_eq!(
        provider.oaep_encrypt(TpmiAlgHash::Sha256, pub_key, 0, &[0x42u8; 63], &[], &mut ct),
        Ok(None)
    );
    // Raw RSA requires `m < n`.
    assert_eq!(
        provider.rsa_null_encrypt(pub_key, 0, &[0xFFu8; 128], &mut ct),
        Ok(None)
    );

    // Signatures: a 1024-bit key cannot hold a SHA-512 PSS signature with a digest-sized salt.
    let digest = [0x11u8; 64];
    let digest_ha = TpmtHa::new(TpmiAlgHash::Sha512, &digest).unwrap();
    let mut sig = [0u8; 128];
    assert_eq!(
        provider.rsapss_sign(priv_key, digest_ha, &mut sig),
        Ok(None)
    );
    let digest_ha = TpmtHa::new(TpmiAlgHash::Sha256, &digest[..32]).unwrap();
    let sig_len = provider
        .rsassa_sign(priv_key, digest_ha, &mut sig)
        .unwrap()
        .unwrap();
    assert_eq!(
        provider.verify_inner(Alg::RSASSA, pub_key, 0, digest_ha, &sig[..sig_len]),
        Ok(true)
    );
    sig[0] ^= 0x01;
    assert_eq!(
        provider.verify_inner(Alg::RSASSA, pub_key, 0, digest_ha, &sig[..sig_len]),
        Ok(false)
    );

    // Invalid private keys and inconsistent key components.
    assert_eq!(
        provider.rsassa_sign(&[0u8; 8], digest_ha, &mut sig),
        Ok(None)
    );
    let mut prime_p = [0u8; 64];
    assert_eq!(
        provider.rsa_private_key_to_prime_p(&[0u8; 8], &mut prime_p),
        Ok(None)
    );
    let mut imported = [0u8; 1024];
    assert_eq!(
        provider.rsa_import_private_key(pub_key, &[0x03], 65537, &mut imported),
        Ok(None)
    );
}

#[test]
fn test_provider_ecc_dispatch_conventions() {
    use tpm2::crypto::{CryptoError, point_multiply, point_multiply_generator, validate_point};

    let provider = BsslCryptoProvider;
    let curve = TpmEccCurve::NistP256;

    // [1]G through the dispatch helpers: `Some(2N)` bytes written.
    let mut g = [0u8; 64];
    assert_eq!(
        point_multiply_generator(&provider, curve, &[1], &mut g),
        Ok(Some(64))
    );
    assert_eq!(validate_point(&provider, curve, &g), Ok(true));
    let mut out = [0u8; 64];
    assert_eq!(
        point_multiply(&provider, curve, &[2], &g, &mut out),
        Ok(Some(64))
    );
    let mut g2 = [0u8; 64];
    assert_eq!(
        point_multiply_generator(&provider, curve, &[2], &mut g2),
        Ok(Some(64))
    );
    assert_eq!(out, g2);

    // Semantic failures: a zero scalar, an off-curve point, a wrong point length.
    assert_eq!(
        point_multiply_generator(&provider, curve, &[0], &mut out),
        Ok(None)
    );
    let mut off_curve = g;
    off_curve[63] ^= 0x01;
    assert_eq!(validate_point(&provider, curve, &off_curve), Ok(false));
    assert_eq!(
        point_multiply(&provider, curve, &[2], &off_curve, &mut out),
        Ok(None)
    );
    assert_eq!(validate_point(&provider, curve, &g[..63]), Ok(false));

    // Output buffers that are too small are internal errors.
    assert_eq!(
        point_multiply(&provider, curve, &[2], &g, &mut out[..63]),
        Err(CryptoError::Internal)
    );

    // Unsupported curves and key sizes.
    assert!(matches!(
        provider.nist_p192(),
        Err(CryptoError::Unsupported)
    ));
    assert_eq!(
        validate_point(&provider, TpmEccCurve::None, &g),
        Err(CryptoError::Unsupported)
    );
    let mut pub_key = [0u8; 132];
    let mut priv_key = [0u8; 66];
    assert_eq!(
        provider.ecc_generate_key(TpmEccCurve::None, &mut pub_key, &mut priv_key, None),
        Err(CryptoError::Unsupported)
    );
    let digest_ha = TpmtHa::new(TpmiAlgHash::Sha256, &[0x22u8; 32]).unwrap();
    let mut sig = [0u8; 132];
    assert_eq!(
        provider.ecdsa_sign(&[0x01u8; 31], digest_ha, &mut sig),
        Ok(None)
    );
    assert_eq!(
        provider.ecdsa_verify(&g[..63], digest_ha, &sig[..64]),
        Ok(false)
    );
}

/// RSA public-key operations use the given public exponent (`0` for the default 65537): raw RSA
/// of a message `m` with `m^3 < n` under exponent 3 is exactly `m^3`.
#[test]
fn test_provider_rsa_public_exponent() {
    let provider = BsslCryptoProvider;
    let mut n = [0u8; 128];
    let mut private_key = [0u8; 1024];
    let (n_len, _) = rsa_generate_key(1024, &mut n, &mut private_key, None).unwrap();
    let n = &n[..n_len];

    let m = [0x01, 0x00]; // 2^8
    let raw = |exponent: u32| {
        let mut ciphertext = [0u8; 128];
        assert_eq!(
            provider.rsa_null_encrypt(n, exponent, &m, &mut ciphertext),
            Ok(Some(128))
        );
        ciphertext
    };
    let mut cubed = [0u8; 128];
    cubed[124] = 0x01; // 2^24
    assert_eq!(raw(3), cubed);
    assert_eq!(raw(0), raw(65537));
    assert_ne!(raw(0), cubed);

    // An even exponent is not a valid RSA public exponent.
    let mut ciphertext = [0u8; 128];
    assert_eq!(
        provider.rsa_null_encrypt(n, 4, &m, &mut ciphertext),
        Ok(None)
    );
}
