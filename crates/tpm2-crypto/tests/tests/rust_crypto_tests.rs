use hex_literal::hex;
use tpm2::crypto::CryptoError;
use tpm2::crypto::asymmetric::{Asymmetric, AsymmetricSign, TpmiRsaKeyBits};
use tpm2::crypto::ecc::{Ecc, TpmEccCurve};
use tpm2::crypto::rng::Rng;
use tpm2::crypto::{Finalize as _, Hash as _, Update as _};
use tpm2::{Alg, TpmiAlgHash, TpmiAlgSymMode, TpmtHa, TpmtSymDefObject};
use tpm2_crypto_tests::TestProvider;

// ==========================================
// FEATURE 1: Hash (SHA-1, SHA-256, SHA-384, SHA-512)
// ==========================================

#[test]
fn test_sha1_kat() {
    let provider = TestProvider;
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];

    // Empty input
    let digest = tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha1, b"", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        &hex!("da39a3ee5e6b4b0d3255bfef95601890afd80709")[..]
    );

    // Standard vector "abc"
    let digest = tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha1, b"abc", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        &hex!("a9993e364706816aba3e25717850c26c9cd0d89d")[..]
    );
}

#[test]
fn test_sha256_kat() {
    let provider = TestProvider;
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];

    // Empty input
    let digest = tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha256, b"", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        &hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")[..]
    );

    // Standard vector "abc"
    let digest =
        tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha256, b"abc", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        &hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")[..]
    );
}

#[test]
fn test_sha384_kat() {
    let provider = TestProvider;
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];

    // Empty input
    let digest = tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha384, b"", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        &hex!(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        )[..]
    );

    // Standard vector "abc"
    let digest =
        tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha384, b"abc", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        &hex!(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )[..]
    );
}

#[test]
fn test_sha512_kat() {
    let provider = TestProvider;
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];

    // Empty input
    let digest = tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha512, b"", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        &hex!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )[..]
    );

    // Standard vector "abc"
    let digest =
        tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha512, b"abc", &mut out).unwrap();
    assert_eq!(
        digest.digest(),
        &hex!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )[..]
    );
}

#[test]
fn test_hash_incremental() {
    let provider = TestProvider;

    // Incremental hashing of "abcdefghijklmnopqrstuvwxyz"
    let mut state = provider.sha256().unwrap();
    state.update(b"abcdefg").unwrap();
    state.update(b"hijklmnop").unwrap();
    state.update(b"qrstuvwxyz").unwrap();
    let mut digest = [0u8; 32];
    state.finalize(&mut digest).unwrap();

    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected = tpm2::crypto::hash(
        &provider,
        tpm2::TpmiAlgHash::Sha256,
        b"abcdefghijklmnopqrstuvwxyz",
        &mut out,
    )
    .unwrap();
    assert_eq!(&digest[..], expected.digest());
}

#[test]
fn test_hash_large_buffer() {
    let provider = TestProvider;

    let mut large_buf = [0u8; 64 * 1024];
    // Fill with dummy deterministic pattern
    for (i, val) in large_buf.iter_mut().enumerate() {
        *val = (i % 251) as u8;
    }

    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest =
        tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha256, &large_buf, &mut out).unwrap();

    // Verify against standard implementation
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(large_buf);
    let expected_hash = hasher.finalize();
    assert_eq!(digest.digest(), &expected_hash[..]);
}

// ==========================================
// FEATURE 2: Hmac (HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512)
// ==========================================

#[test]
fn test_hmac_sha1_kat() {
    let provider = TestProvider;

    // RFC 2202 Case 1
    let key = [0x0b; 20];
    let data = b"Hi There";
    let expected = hex!("b617318655057264e28bc0b6fb378c8ef146be00");

    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha1, &key, data, &mut out).unwrap();
    assert_eq!(mac.digest(), &expected[..]);
}

#[test]
fn test_hmac_sha256_kat() {
    let provider = TestProvider;

    // RFC 4231 Case 1
    let key = [0x0b; 20];
    let data = b"Hi There";
    let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha256, &key, data, &mut out).unwrap();
    assert_eq!(mac.digest(), &expected[..]);
}

#[test]
fn test_hmac_sha384_kat() {
    let provider = TestProvider;

    // RFC 4231 Case 1
    let key = [0x0b; 20];
    let data = b"Hi There";
    let expected = hex!(
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
    );

    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha384, &key, data, &mut out).unwrap();
    assert_eq!(mac.digest(), &expected[..]);
}

#[test]
fn test_hmac_sha512_kat() {
    let provider = TestProvider;

    // RFC 4231 Case 1
    let key = [0x0b; 20];
    let data = b"Hi There";
    let expected = hex!(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    );

    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha512, &key, data, &mut out).unwrap();
    assert_eq!(mac.digest(), &expected[..]);
}

#[test]
fn test_hmac_key_longer_than_block() {
    let provider = TestProvider;

    // RFC 4231 Case 3
    let key = [0xaa; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let expected = hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha256, &key, data, &mut out).unwrap();
    assert_eq!(mac.digest(), &expected[..]);
}

#[test]
fn test_hmac_incremental() {
    let provider = TestProvider;

    let key = b"secret_key_data";
    let mut ctx = tpm2::crypto::HmacCtx::new(&provider, TpmiAlgHash::Sha256, key).unwrap();
    ctx.update(b"hello ").unwrap();
    ctx.update(b"world!").unwrap();
    let mut out1 = [0u8; 64];
    let mac = ctx.finalize(&mut out1).unwrap();

    let mut out2 = [0u8; 64];
    let expected = tpm2::crypto::hmac(
        &provider,
        TpmiAlgHash::Sha256,
        key,
        b"hello world!",
        &mut out2,
    )
    .unwrap();
    assert_eq!(mac.digest(), expected.digest());
}

#[test]
fn test_hmac_empty_key() {
    let provider = TestProvider;

    let key = [];
    let data = b"some data";
    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha256, &key, data, &mut out);
    assert!(mac.is_ok());
}

#[test]
fn test_hmac_empty_data() {
    let provider = TestProvider;

    let key = b"mykey";
    let data = [];
    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha256, key, &data, &mut out);
    assert!(mac.is_ok());
}

#[test]
fn test_hmac_large_data() {
    let provider = TestProvider;

    let key = b"key";
    let mut data = [0u8; 32 * 1024];
    for (i, val) in data.iter_mut().enumerate() {
        *val = (i % 251) as u8;
    }
    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha256, key, &data, &mut out);
    assert!(mac.is_ok());
}

// ==========================================
// FEATURE 3: Symmetric (AES-128, AES-256 in CFB mode)
// ==========================================

#[test]
fn test_aes128_cfb_encrypt_decrypt() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB));

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = *b"plaintext_16byte";

    // Encrypt
    tpm2::crypto::encrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    let ciphertext = data;

    // Reset IV
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    // Decrypt
    tpm2::crypto::decrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    assert_eq!(&data[..], b"plaintext_16byte");
    assert_ne!(ciphertext, data);
}

#[test]
fn test_aes128_cfb_multi_block() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB));

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = [0xAAu8; 48];
    let original = data;

    tpm2::crypto::encrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    let ciphertext = data;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    tpm2::crypto::decrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    assert_eq!(data, original);
    assert_ne!(ciphertext, original);
}

#[test]
fn test_aes256_cfb_encrypt_decrypt() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB));

    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = *b"plaintext_16byte";

    tpm2::crypto::encrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    let ciphertext = data;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    tpm2::crypto::decrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    assert_eq!(&data[..], b"plaintext_16byte");
    assert_ne!(ciphertext, data);
}

#[test]
fn test_aes256_cfb_multi_block() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB));

    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = [0x55u8; 80];
    let original = data;

    tpm2::crypto::encrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    let ciphertext = data;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    tpm2::crypto::decrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    assert_eq!(data, original);
    assert_ne!(ciphertext, original);
}

#[test]
fn test_aes_cfb_non_zero_iv() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB));

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv1 = hex!("000102030405060708090a0b0c0d0e0f");
    let mut iv2 = hex!("ffeeddccbbaa99887766554433221100");
    let mut data1 = *b"plaintext_16byte";
    let mut data2 = *b"plaintext_16byte";

    tpm2::crypto::encrypt(&provider, alg, &key, &mut iv1, &mut data1).unwrap();
    tpm2::crypto::encrypt(&provider, alg, &key, &mut iv2, &mut data2).unwrap();

    // Verify dependency on IV (outputs must be different)
    assert_ne!(data1, data2);
}

#[test]
fn test_aes_empty_data() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB));

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = [];

    let res = tpm2::crypto::encrypt(&provider, alg, &key, &mut iv, &mut data);
    assert!(res.is_ok());
}

#[test]
fn test_aes_key_too_small() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB));

    let key = [0u8; 10]; // too small
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = [0u8; 16];

    let res = tpm2::crypto::encrypt(&provider, alg, &key, &mut iv, &mut data);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_aes_iv_too_small() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB));

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = [0u8; 10]; // too small
    let mut data = [0u8; 16];

    let res = tpm2::crypto::encrypt(&provider, alg, &key, &mut iv, &mut data);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_aes_corrupted_ciphertext() {
    let provider = TestProvider;
    let alg = TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB));

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = *b"plaintext_16byte";

    tpm2::crypto::encrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    // Corrupt ciphertext
    data[5] ^= 0xFF;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    tpm2::crypto::decrypt(&provider, alg, &key, &mut iv, &mut data).unwrap();
    // Verify it decrypts to garbage (not matching original plaintext)
    assert_ne!(&data[..], b"plaintext_16byte");
}

// ==========================================
// FEATURE 4: Cmac (AES-128-CMAC, AES-256-CMAC)
// ==========================================

#[test]
fn test_cmac_aes128_empty() {
    let provider = TestProvider;

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut mac = [0u8; 16];
    tpm2::crypto::cmac(
        &provider,
        tpm2::TpmtSymDefObject::Aes128(None),
        &key,
        b"",
        &mut mac,
    )
    .unwrap();
    assert_eq!(&mac[..], &hex!("bb1d6929e95937287fa37d129b756746")[..]);
}

#[test]
fn test_cmac_aes128_16bytes() {
    let provider = TestProvider;

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let data = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut mac = [0u8; 16];
    tpm2::crypto::cmac(
        &provider,
        tpm2::TpmtSymDefObject::Aes128(None),
        &key,
        &data,
        &mut mac,
    )
    .unwrap();
    assert_eq!(&mac[..], &hex!("070a16b46b4d4144f79bdd9dd04a287c")[..]);
}

#[test]
fn test_cmac_aes128_40bytes() {
    let provider = TestProvider;

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let data =
        hex!("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    let mut mac = [0u8; 16];
    tpm2::crypto::cmac(
        &provider,
        tpm2::TpmtSymDefObject::Aes128(None),
        &key,
        &data,
        &mut mac,
    )
    .unwrap();
    assert_eq!(&mac[..], &hex!("dfa66747de9ae63030ca32611497c827")[..]);
}

#[test]
fn test_cmac_aes256_empty() {
    let provider = TestProvider;

    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut mac = [0u8; 16];
    tpm2::crypto::cmac(
        &provider,
        tpm2::TpmtSymDefObject::Aes256(None),
        &key,
        b"",
        &mut mac,
    )
    .unwrap();
    assert_eq!(&mac[..], &hex!("5f6844eb8d79e76cd244c07ad1003bce")[..]);
}

#[test]
fn test_cmac_aes256_16bytes() {
    let provider = TestProvider;

    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let data = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut mac = [0u8; 16];
    tpm2::crypto::cmac(
        &provider,
        tpm2::TpmtSymDefObject::Aes256(None),
        &key,
        &data,
        &mut mac,
    )
    .unwrap();
    assert_eq!(&mac[..], &hex!("22c2ef5b01082373365b34de01a7de91")[..]);
}

#[test]
fn test_cmac_key_too_small() {
    let provider = TestProvider;

    let key = [0u8; 10]; // too small
    let mut mac = [0u8; 16];
    let res = tpm2::crypto::cmac(
        &provider,
        tpm2::TpmtSymDefObject::Aes128(None),
        &key,
        b"",
        &mut mac,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_cmac_large_message() {
    let provider = TestProvider;

    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut data = [0u8; 16 * 1024];
    for (i, val) in data.iter_mut().enumerate() {
        *val = (i % 251) as u8;
    }
    let mut mac = [0u8; 16];
    let res = tpm2::crypto::cmac(
        &provider,
        tpm2::TpmtSymDefObject::Aes128(None),
        &key,
        &data,
        &mut mac,
    );
    assert!(res.is_ok());
}

// ==========================================
// FEATURE 5: Asymmetric (RSA)
// ==========================================

#[test]

fn test_rsa_keygen_1024() {
    let provider = TestProvider;

    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (pub_len, priv_len) = provider
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

    assert!(pub_len > 0);
    assert!(priv_len > 0);
}

#[test]

fn test_rsa_keygen_2048() {
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

    assert!(pub_len > 0);
    assert!(priv_len > 0);
}

#[test]

fn test_rsa_oaep_encrypt_decrypt() {
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

    let plaintext = b"hello world";
    let mut ciphertext = [0u8; 256];

    // Let's encrypt using the provider
    let enc_len = provider
        .encrypt(
            Alg::OAEP,
            Alg::SHA256,
            &public_key[..pub_len],
            plaintext,
            &mut ciphertext,
            &[],
        )
        .unwrap();

    // Decrypt using provider
    let mut decrypted = [0u8; 128];
    let dec_len = provider
        .decrypt(
            Alg::OAEP,
            Alg::SHA256,
            &private_key[..priv_len],
            &ciphertext[..enc_len],
            &mut decrypted,
            &[],
        )
        .unwrap();

    assert_eq!(&decrypted[..dec_len], plaintext);
}

#[test]

fn test_rsa_pss_sign_verify() {
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

    let digest = [0xAAu8; 32];
    let mut signature = [0u8; 256];

    // Sign
    let sig_len = provider
        .sign_inner(
            Alg::RSAPSS,
            &private_key[..priv_len],
            TpmtHa::Sha256(&digest),
            &mut signature,
        )
        .unwrap();

    // provider.verify_inner should succeed
    let res = provider.verify_inner(
        Alg::RSAPSS,
        &public_key[..pub_len],
        TpmtHa::Sha256(&digest),
        &signature[..sig_len],
    );
    assert!(res.is_ok());

    // Verify using rsa crate directly
    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&public_key[..pub_len]),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    pub_key
        .verify(
            rsa::pss::Pss::new::<sha2::Sha256>(),
            &digest,
            &signature[..sig_len],
        )
        .unwrap();
}

#[test]

fn test_rsa_pkcs1v15_sign_verify() {
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

    let digest = [0x55u8; 32];
    let mut signature = [0u8; 256];

    // Sign
    let sig_len = provider
        .sign_inner(
            Alg::RSASSA,
            &private_key[..priv_len],
            TpmtHa::Sha256(&digest),
            &mut signature,
        )
        .unwrap();

    // provider.verify_inner should succeed
    let res = provider.verify_inner(
        Alg::RSASSA,
        &public_key[..pub_len],
        TpmtHa::Sha256(&digest),
        &signature[..sig_len],
    );
    assert!(res.is_ok());

    // Verify using rsa crate directly
    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&public_key[..pub_len]),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    pub_key
        .verify(
            rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
            &digest,
            &signature[..sig_len],
        )
        .unwrap();
}

#[test]

fn test_rsa_import_and_raw_decrypt() {
    let provider = TestProvider;

    // First generate key to get standard modulus, primes, etc.
    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (_pub_len, priv_len) = provider
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

    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let orig_priv_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key[..priv_len]).unwrap();

    let modulus = orig_priv_key.n().to_bytes_be();
    let prime_p = orig_priv_key.primes()[0].to_bytes_be();
    let exponent = 65537u32;

    let mut imported_private_key = [0u8; 2048];
    let imported_len = provider
        .rsa_import_private_key(&modulus, &prime_p, exponent, &mut imported_private_key)
        .unwrap();

    // Raw decrypt using imported private key
    let m = rsa::BigUint::from(42u32);
    let c = m.modpow(orig_priv_key.e(), orig_priv_key.n());
    let ciphertext = c.to_bytes_be();

    let mut plaintext = [0u8; 256];
    let decrypted_len = provider
        .decrypt(
            Alg::NULL,
            Alg::NULL,
            &imported_private_key[..imported_len],
            &ciphertext,
            &mut plaintext,
            &[],
        )
        .unwrap();

    assert_eq!(decrypted_len, 256);
    let mut expected_plaintext = [0u8; 256];
    expected_plaintext[255] = 42;
    assert_eq!(&plaintext[..], &expected_plaintext[..]);
}

#[test]

fn test_rsa_import_p_zero() {
    let provider = TestProvider;

    let modulus = [0u8; 128];
    let prime_p = [0u8; 64];
    let mut private_key_out = [0u8; 1024];

    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_rsa_import_modulus_zero_p_nonzero() {
    let provider = TestProvider;

    let modulus = [0u8; 128];
    let prime_p = [2u8; 64];
    let mut private_key_out = [0u8; 1024];

    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]

fn test_rsa_import_invalid_primes() {
    let provider = TestProvider;

    let modulus = [0x0f; 128];
    let prime_p = [0x02; 64]; // modulus is odd, prime_p is even.
    let mut private_key_out = [0u8; 1024];

    let res = provider.rsa_import_private_key(&modulus, &prime_p, 65537, &mut private_key_out);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]

fn test_rsa_oaep_decrypt_corrupted() {
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

    // Encrypt
    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&public_key[..pub_len]),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    let mut rng_thread = rsa::rand_core::OsRng;
    let oaep = rsa::Oaep::new::<sha2::Sha256>();
    let mut c = pub_key.encrypt(&mut rng_thread, oaep, b"secret").unwrap();

    // Corrupt ciphertext
    c[10] ^= 0xFF;

    let mut decrypted = [0u8; 128];
    let res = provider.decrypt(
        Alg::OAEP,
        Alg::SHA256,
        &private_key[..priv_len],
        &c,
        &mut decrypted,
        &[],
    );
    assert_eq!(res.unwrap_err(), CryptoError::HardwareFailure);
}

#[test]

fn test_rsa_pss_verify_corrupted() {
    let provider = TestProvider;

    // Since verify_inner is supported, checking corrupted signature should return InvalidData.
    let public_key = [0u8; 256];
    let digest = [0u8; 32];
    let signature = [0u8; 256];

    let res = provider.verify_inner(
        Alg::RSAPSS,
        &public_key,
        TpmtHa::Sha256(&digest),
        &signature,
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]

fn test_rsa_decrypt_buffer_too_small() {
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
    let oaep = rsa::Oaep::new::<sha2::Sha256>();
    let c = pub_key.encrypt(&mut rng_thread, oaep, b"secret").unwrap();

    // Output buffer too small (plaintext is 6 bytes, let's pass a 5-byte buffer)
    let mut decrypted = [0u8; 5];
    let res = provider.decrypt(
        Alg::OAEP,
        Alg::SHA256,
        &private_key[..priv_len],
        &c,
        &mut decrypted,
        &[],
    );
    assert_eq!(res.unwrap_err(), CryptoError::BufferTooSmall);
}

// ==========================================
// FEATURE 6: Ecc (ECDSA P256, ECDH P256)
// ==========================================

#[test]

fn test_ecc_keygen_p256() {
    let provider = TestProvider;

    let mut public_key = [0u8; 64];
    let mut private_key = [0u8; 32];
    let (pub_len, priv_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    assert_eq!(pub_len, 64);
    assert_eq!(priv_len, 32);
}

#[test]
fn test_ecdsa_sign_verify() {
    let provider = TestProvider;

    let mut ecc_pub = [0u8; 64];
    let mut ecc_priv = [0u8; 32];
    let (ecc_pub_len, ecc_priv_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                TpmEccCurve::NistP256,
            )),
            &mut ecc_pub,
            &mut ecc_priv,
            None,
        )
        .unwrap();

    let digest = [0u8; 32];
    let mut signature = [0u8; 64];

    let sig_len = provider
        .sign_inner(
            Alg::ECDSA,
            &ecc_priv[..ecc_priv_len],
            TpmtHa::Sha256(&digest),
            &mut signature,
        )
        .unwrap();
    assert_eq!(sig_len, 64);

    provider
        .verify_inner(
            Alg::ECDSA,
            &ecc_pub[..ecc_pub_len],
            TpmtHa::Sha256(&digest),
            &signature[..sig_len],
        )
        .unwrap();
}

#[test]

fn test_ecc_validate_point() {
    let provider = TestProvider;

    let mut public_key = [0u8; 64];
    let mut private_key = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    // Validate generated key
    provider
        .validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &public_key)
        .unwrap();

    // Uncompressed generator point (X and Y coordinates, 64 bytes)
    let generator_uncompressed = hex!(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );
    provider
        .validate_point(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &generator_uncompressed,
        )
        .unwrap();
}

#[test]

fn test_ecdh_shared_secret() {
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

    let mut pub_b = [0u8; 64];
    let mut priv_b = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut pub_b,
            &mut priv_b,
            None,
        )
        .unwrap();

    let mut secret_a = [0u8; 64];
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_a,
            &pub_b,
            &mut secret_a,
        )
        .unwrap();

    let mut secret_b = [0u8; 64];
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_b,
            &pub_a,
            &mut secret_b,
        )
        .unwrap();

    assert_eq!(secret_a, secret_b);
}

#[test]
fn test_ecdsa_verify_corrupted_signature() {
    let provider = TestProvider;

    let mut ecc_pub = [0u8; 64];
    let mut ecc_priv = [0u8; 32];
    let (ecc_pub_len, ecc_priv_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                TpmEccCurve::NistP256,
            )),
            &mut ecc_pub,
            &mut ecc_priv,
            None,
        )
        .unwrap();

    let digest = [0u8; 32];
    let mut signature = [0u8; 64];

    let sig_len = provider
        .sign_inner(
            Alg::ECDSA,
            &ecc_priv[..ecc_priv_len],
            TpmtHa::Sha256(&digest),
            &mut signature,
        )
        .unwrap();

    // Corrupt signature
    signature[0] ^= 1;

    let res = provider.verify_inner(
        Alg::ECDSA,
        &ecc_pub[..ecc_pub_len],
        TpmtHa::Sha256(&digest),
        &signature[..sig_len],
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]
fn test_ecdsa_verify_mismatched_key() {
    let provider = TestProvider;

    let mut ecc_pub_a = [0u8; 64];
    let mut ecc_priv_a = [0u8; 32];
    let (ecc_pub_len_a, ecc_priv_len_a) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                TpmEccCurve::NistP256,
            )),
            &mut ecc_pub_a,
            &mut ecc_priv_a,
            None,
        )
        .unwrap();

    let mut ecc_pub_b = [0u8; 64];
    let mut ecc_priv_b = [0u8; 32];
    let _ = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                TpmEccCurve::NistP256,
            )),
            &mut ecc_pub_b,
            &mut ecc_priv_b,
            None,
        )
        .unwrap();

    let digest = [0u8; 32];
    let mut signature = [0u8; 64];

    let sig_len = provider
        .sign_inner(
            Alg::ECDSA,
            &ecc_priv_a[..ecc_priv_len_a],
            TpmtHa::Sha256(&digest),
            &mut signature,
        )
        .unwrap();

    let res = provider.verify_inner(
        Alg::ECDSA,
        &ecc_pub_b[..ecc_pub_len_a],
        TpmtHa::Sha256(&digest),
        &signature[..sig_len],
    );
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]

fn test_ecc_validate_invalid_point() {
    let provider = TestProvider;

    // All zeros
    let pt = [0u8; 64];
    let res = provider.validate_point(tpm2::crypto::ecc::TpmEccCurve::NistP256, &pt);
    assert_eq!(res.unwrap_err(), CryptoError::InvalidData);
}

#[test]

fn test_ecdh_output_buffer_too_small() {
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

    let mut pub_b = [0u8; 64];
    let mut priv_b = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut pub_b,
            &mut priv_b,
            None,
        )
        .unwrap();

    let mut small_secret = [0u8; 32];
    let res = provider.point_multiply(
        tpm2::crypto::ecc::TpmEccCurve::NistP256,
        &priv_a,
        &pub_b,
        &mut small_secret,
    );
    assert_eq!(res.unwrap_err(), CryptoError::BufferTooSmall);
}

// ==========================================
// FEATURE 7: Rng
// ==========================================

#[test]
fn test_rng_get_random() {
    let provider = TestProvider;

    let mut buf1 = [0u8; 16];
    let mut buf2 = [0u8; 16];
    provider.get_random(&mut buf1).unwrap();
    provider.get_random(&mut buf2).unwrap();

    assert_ne!(buf1, buf2);
}

#[test]
fn test_rng_large_request() {
    let provider = TestProvider;

    let mut buf = [0u8; 1024];
    provider.get_random(&mut buf).unwrap();
}

#[test]
fn test_rng_non_zero() {
    let provider = TestProvider;

    let mut buf = [0u8; 64];
    provider.get_random(&mut buf).unwrap();

    let is_all_zero = buf.iter().all(|&x| x == 0);
    assert!(!is_all_zero);
}

#[test]
fn test_rng_zero_bytes() {
    let provider = TestProvider;

    let mut buf = [];
    let res = provider.get_random(&mut buf);
    assert!(res.is_ok());
}

#[test]
fn test_rng_multiple_requests() {
    let provider = TestProvider;

    let mut bufs = [[0u8; 8]; 10];
    for buf in &mut bufs {
        provider.get_random(buf).unwrap();
    }

    for i in 0..10 {
        for j in i + 1..10 {
            assert_ne!(bufs[i], bufs[j]);
        }
    }
}

// ==========================================
// TIER 3: Cross-Feature Combinations
// ==========================================

#[test]

fn test_combo_rsa_keygen_sign_verify() {
    let provider = TestProvider;

    // 1. Generate RSA key
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

    // 2. Hash message
    let message = b"combo test message for RSA";
    let mut ctx = provider.sha256().unwrap();
    ctx.update(message).unwrap();
    let mut digest_bytes = [0u8; 32];
    ctx.finalize(&mut digest_bytes).unwrap();

    // 3. Sign digest
    let mut signature = [0u8; 256];
    let sig_len = provider
        .sign_inner(
            Alg::RSAPSS,
            &private_key[..priv_len],
            TpmtHa::Sha256(&digest_bytes),
            &mut signature,
        )
        .unwrap();

    // 4. Verify signature using rsa crate directly
    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&public_key[..pub_len]),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    pub_key
        .verify(
            rsa::pss::Pss::new::<sha2::Sha256>(),
            &digest_bytes,
            &signature[..sig_len],
        )
        .unwrap();
}

#[test]

fn test_combo_ecc_keygen_sign_verify() {
    let provider = TestProvider;

    // 1. Generate ECC key
    let mut public_key = [0u8; 64];
    let mut private_key = [0u8; 32];
    let (pub_len, priv_len) = provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut public_key,
            &mut private_key,
            None,
        )
        .unwrap();

    // 2. Hash message
    let message = b"combo test message for ECC";
    let mut ctx = provider.sha256().unwrap();
    ctx.update(message).unwrap();
    let mut digest_bytes = [0u8; 32];
    ctx.finalize(&mut digest_bytes).unwrap();

    // 3. Sign digest
    let mut signature = [0u8; 64];
    let sig_len = provider
        .sign_inner(
            Alg::ECDSA,
            &private_key[..priv_len],
            TpmtHa::Sha256(&digest_bytes),
            &mut signature,
        )
        .unwrap();

    // 4. Verify signature
    provider
        .verify_inner(
            Alg::ECDSA,
            &public_key[..pub_len],
            TpmtHa::Sha256(&digest_bytes),
            &signature[..sig_len],
        )
        .unwrap();
}

#[test]

fn test_combo_ecdh_exchange_aes_cfb() {
    let provider = TestProvider;

    // 1. Perform ECDH exchange
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

    let mut pub_b = [0u8; 64];
    let mut priv_b = [0u8; 32];
    provider
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                tpm2::crypto::ecc::TpmEccCurve::NistP256,
            )),
            &mut pub_b,
            &mut priv_b,
            None,
        )
        .unwrap();

    let mut secret_a = [0u8; 64];
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_a,
            &pub_b,
            &mut secret_a,
        )
        .unwrap();

    let mut secret_b = [0u8; 64];
    provider
        .point_multiply(
            tpm2::crypto::ecc::TpmEccCurve::NistP256,
            &priv_b,
            &pub_a,
            &mut secret_b,
        )
        .unwrap();
    assert_eq!(secret_a, secret_b);

    // 2. Derive AES key from shared secret (using first 32 bytes)
    let aes_key = &secret_a[..32];

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = *b"super_secret_payload_from_ecdh_kdf_etc.";
    let original = data;
    let alg = TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB));

    tpm2::crypto::encrypt(&provider, alg, aes_key, &mut iv, &mut data).unwrap();
    let ciphertext = data;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    tpm2::crypto::decrypt(&provider, alg, aes_key, &mut iv, &mut data).unwrap();

    assert_eq!(data, original);
    assert_ne!(ciphertext, original);
}

#[test]

fn test_combo_keygen_save_load() {
    let provider = TestProvider;

    // Generate keys
    let mut public_key = [0u8; 1024];
    let mut private_key = [0u8; 2048];
    let (_pub_len, priv_len) = provider
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

    // Save/Serialize: they are already serialized in DER in private_key/public_key arrays.
    let saved_priv = private_key[..priv_len].to_vec();

    // Import/Load key
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let orig_priv_key = rsa::RsaPrivateKey::from_pkcs8_der(&saved_priv).unwrap();

    let modulus = orig_priv_key.n().to_bytes_be();
    let prime_p = orig_priv_key.primes()[0].to_bytes_be();
    let exponent = 65537u32;

    let mut imported_private_key = [0u8; 2048];
    let imported_len = provider
        .rsa_import_private_key(&modulus, &prime_p, exponent, &mut imported_private_key)
        .unwrap();

    // Perform decrypt with loaded key
    let m = rsa::BigUint::from(123456u32);
    let c = m.modpow(orig_priv_key.e(), orig_priv_key.n());
    let ciphertext = c.to_bytes_be();

    let mut plaintext = [0u8; 256];
    let decrypted_len = provider
        .decrypt(
            Alg::NULL,
            Alg::NULL,
            &imported_private_key[..imported_len],
            &ciphertext,
            &mut plaintext,
            &[],
        )
        .unwrap();

    assert_eq!(decrypted_len, 256);
    let mut expected_plaintext = [0u8; 256];
    expected_plaintext[255] = (123456u32 % 256u32) as u8;
    expected_plaintext[254] = ((123456u32 / 256u32) % 256u32) as u8;
    expected_plaintext[253] = (123456u32 / 65536u32) as u8;
    assert_eq!(&plaintext[..], &expected_plaintext[..]);
}

// ==========================================
// FEATURE 8: Differential/Stress Testing of TestProvider
// ==========================================

fn generate_deterministic_data(size: usize, seed: u8) -> Vec<u8> {
    let mut data = vec![0u8; size];
    for (i, val) in data.iter_mut().enumerate() {
        *val = ((i ^ (seed as usize)).wrapping_mul(17).wrapping_add(3)) as u8;
    }
    data
}

fn oracle_hash(alg: Alg, data: &[u8]) -> Vec<u8> {
    match alg {
        Alg::SHA1 => {
            use sha1::Digest as _;
            let mut hasher = sha1::Sha1::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        Alg::SHA256 => {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        Alg::SHA384 => {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        Alg::SHA512 => {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        _ => panic!("unsupported hash alg"),
    }
}

fn oracle_hmac(alg: Alg, key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::Mac as _;
    match alg {
        Alg::SHA1 => {
            let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Alg::SHA256 => {
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Alg::SHA384 => {
            let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Alg::SHA512 => {
            let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        _ => panic!("unsupported hmac alg"),
    }
}

#[test]
fn test_rust_crypto_provider_hash_differential() {
    let provider = TestProvider;
    let sizes = [0, 1, 2, 10, 63, 64, 65, 127, 128, 129, 1024, 4096, 10000];
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];

    // Test SHA-1
    for &size in &sizes {
        let data = generate_deterministic_data(size, 0x11);
        let digest =
            tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha1, &data, &mut out).unwrap();
        let expected = oracle_hash(Alg::SHA1, &data);
        assert_eq!(
            digest.digest(),
            &expected[..],
            "SHA1 mismatch at size {}",
            size
        );

        // Incremental test
        let mut state = provider.sha1().unwrap();
        if size > 0 {
            let half = size / 2;
            state.update(&data[..half]).unwrap();
            state.update(&data[half..]).unwrap();
        }
        let mut digest_inc = [0u8; 20];
        state.finalize(&mut digest_inc).unwrap();
        assert_eq!(
            &digest_inc[..],
            &expected[..],
            "SHA1 incremental mismatch at size {}",
            size
        );
    }

    // Test SHA-256
    for &size in &sizes {
        let data = generate_deterministic_data(size, 0x22);
        let digest =
            tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha256, &data, &mut out).unwrap();
        let expected = oracle_hash(Alg::SHA256, &data);
        assert_eq!(
            digest.digest(),
            &expected[..],
            "SHA256 mismatch at size {}",
            size
        );

        // Incremental test
        let mut state = provider.sha256().unwrap();
        if size > 0 {
            let half = size / 2;
            state.update(&data[..half]).unwrap();
            state.update(&data[half..]).unwrap();
        }
        let mut digest_inc = [0u8; 32];
        state.finalize(&mut digest_inc).unwrap();
        assert_eq!(
            &digest_inc[..],
            &expected[..],
            "SHA256 incremental mismatch at size {}",
            size
        );
    }

    // Test SHA-384
    for &size in &sizes {
        let data = generate_deterministic_data(size, 0x33);
        let digest =
            tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha384, &data, &mut out).unwrap();
        let expected = oracle_hash(Alg::SHA384, &data);
        assert_eq!(
            digest.digest(),
            &expected[..],
            "SHA384 mismatch at size {}",
            size
        );

        // Incremental test
        let mut state = provider.sha384().unwrap();
        if size > 0 {
            let half = size / 2;
            state.update(&data[..half]).unwrap();
            state.update(&data[half..]).unwrap();
        }
        let mut digest_inc = [0u8; 48];
        state.finalize(&mut digest_inc).unwrap();
        assert_eq!(
            &digest_inc[..],
            &expected[..],
            "SHA384 incremental mismatch at size {}",
            size
        );
    }

    // Test SHA-512
    for &size in &sizes {
        let data = generate_deterministic_data(size, 0x44);
        let digest =
            tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha512, &data, &mut out).unwrap();
        let expected = oracle_hash(Alg::SHA512, &data);
        assert_eq!(
            digest.digest(),
            &expected[..],
            "SHA512 mismatch at size {}",
            size
        );

        // Incremental test
        let mut state = provider.sha512().unwrap();
        if size > 0 {
            let half = size / 2;
            state.update(&data[..half]).unwrap();
            state.update(&data[half..]).unwrap();
        }
        let mut digest_inc = [0u8; 64];
        state.finalize(&mut digest_inc).unwrap();
        assert_eq!(
            &digest_inc[..],
            &expected[..],
            "SHA512 incremental mismatch at size {}",
            size
        );
    }
}

#[test]
fn test_rust_crypto_provider_hmac_differential() {
    let provider = TestProvider;
    let key_sizes = [0, 1, 10, 63, 64, 65, 127, 128, 129, 256];
    let data_sizes = [0, 1, 100, 1024, 10000];

    for &key_size in &key_sizes {
        for &data_size in &data_sizes {
            let key = generate_deterministic_data(key_size, 0x55);
            let data = generate_deterministic_data(data_size, 0x66);

            // Test SHA1
            {
                let mut out = [0u8; 64];
                let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha1, &key, &data, &mut out)
                    .unwrap();
                let expected = oracle_hmac(Alg::SHA1, &key, &data);
                assert_eq!(
                    mac.digest(),
                    &expected[..],
                    "HMAC-SHA1 mismatch: key_size={}, data_size={}",
                    key_size,
                    data_size
                );

                // Incremental
                let mut ctx =
                    tpm2::crypto::HmacCtx::new(&provider, TpmiAlgHash::Sha1, &key).unwrap();
                if data_size > 0 {
                    let half = data_size / 2;
                    ctx.update(&data[..half]).unwrap();
                    ctx.update(&data[half..]).unwrap();
                }
                let mut out_inc = [0u8; 64];
                let mac_inc = ctx.finalize(&mut out_inc).unwrap();
                assert_eq!(
                    mac_inc.digest(),
                    &expected[..],
                    "HMAC-SHA1 incremental mismatch: key_size={}, data_size={}",
                    key_size,
                    data_size
                );
            }

            // Test SHA256
            {
                let mut out = [0u8; 64];
                let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha256, &key, &data, &mut out)
                    .unwrap();
                let expected = oracle_hmac(Alg::SHA256, &key, &data);
                assert_eq!(
                    mac.digest(),
                    &expected[..],
                    "HMAC-SHA256 mismatch: key_size={}, data_size={}",
                    key_size,
                    data_size
                );

                // Incremental
                let mut ctx =
                    tpm2::crypto::HmacCtx::new(&provider, TpmiAlgHash::Sha256, &key).unwrap();
                if data_size > 0 {
                    let half = data_size / 2;
                    ctx.update(&data[..half]).unwrap();
                    ctx.update(&data[half..]).unwrap();
                }
                let mut out_inc = [0u8; 64];
                let mac_inc = ctx.finalize(&mut out_inc).unwrap();
                assert_eq!(
                    mac_inc.digest(),
                    &expected[..],
                    "HMAC-SHA256 incremental mismatch: key_size={}, data_size={}",
                    key_size,
                    data_size
                );
            }

            // Test SHA384
            {
                let mut out = [0u8; 64];
                let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha384, &key, &data, &mut out)
                    .unwrap();
                let expected = oracle_hmac(Alg::SHA384, &key, &data);
                assert_eq!(
                    mac.digest(),
                    &expected[..],
                    "HMAC-SHA384 mismatch: key_size={}, data_size={}",
                    key_size,
                    data_size
                );

                // Incremental
                let mut ctx =
                    tpm2::crypto::HmacCtx::new(&provider, TpmiAlgHash::Sha384, &key).unwrap();
                if data_size > 0 {
                    let half = data_size / 2;
                    ctx.update(&data[..half]).unwrap();
                    ctx.update(&data[half..]).unwrap();
                }
                let mut out_inc = [0u8; 64];
                let mac_inc = ctx.finalize(&mut out_inc).unwrap();
                assert_eq!(
                    mac_inc.digest(),
                    &expected[..],
                    "HMAC-SHA384 incremental mismatch: key_size={}, data_size={}",
                    key_size,
                    data_size
                );
            }

            // Test SHA512
            {
                let mut out = [0u8; 64];
                let mac = tpm2::crypto::hmac(&provider, TpmiAlgHash::Sha512, &key, &data, &mut out)
                    .unwrap();
                let expected = oracle_hmac(Alg::SHA512, &key, &data);
                assert_eq!(
                    mac.digest(),
                    &expected[..],
                    "HMAC-SHA512 mismatch: key_size={}, data_size={}",
                    key_size,
                    data_size
                );

                // Incremental
                let mut ctx =
                    tpm2::crypto::HmacCtx::new(&provider, TpmiAlgHash::Sha512, &key).unwrap();
                if data_size > 0 {
                    let half = data_size / 2;
                    ctx.update(&data[..half]).unwrap();
                    ctx.update(&data[half..]).unwrap();
                }
                let mut out_inc = [0u8; 64];
                let mac_inc = ctx.finalize(&mut out_inc).unwrap();
                assert_eq!(
                    mac_inc.digest(),
                    &expected[..],
                    "HMAC-SHA512 incremental mismatch: key_size={}, data_size={}",
                    key_size,
                    data_size
                );
            }
        }
    }
}

#[test]
fn test_rust_crypto_provider_rng_properties() {
    let provider = TestProvider;

    // 1. Edge Case: 0-length request
    let mut empty_buf = [];
    assert!(provider.get_random(&mut empty_buf).is_ok());

    // 2. Edge Case: varying lengths
    for size in [1, 2, 5, 10, 64, 100, 1024, 10000] {
        let mut buf = vec![0u8; size];
        provider.get_random(&mut buf).unwrap();
        if size >= 10 {
            assert!(
                !buf.iter().all(|&x| x == 0),
                "RNG returned all zeros for size {}",
                size
            );
        }
    }

    // 3. Statistical test: Uniformity
    let total_bytes = 100_000;
    let mut buf = vec![0u8; total_bytes];
    provider.get_random(&mut buf).unwrap();

    let mut counts = [0usize; 256];
    for &byte in &buf {
        counts[byte as usize] += 1;
    }

    for (val, &count) in counts.iter().enumerate() {
        assert!(
            (250..=530).contains(&count),
            "Byte value {} count {} is out of expected uniform range [250, 530]",
            val,
            count
        );
    }
}

// ==========================================
// FEATURE 10: KDFa and KDFe Stress & Boundary Tests
// ==========================================

#[test]
fn test_kdfa_boundary_conditions() {
    use tpm2::crypto::kdf::kdfa;
    let provider = TestProvider;

    let key = b"my_secret_kdf_key_that_is_long";
    let label = b"LABEL";
    let context_u = b"context_u";
    let context_v = b"context_v";

    // 1. Verify buffer too small triggers error
    let mut out_small = [0u8; 10];
    let err = kdfa(
        &provider,
        TpmiAlgHash::Sha256,
        key,
        label,
        context_u,
        context_v,
        128,
        &mut out_small,
    )
    .unwrap_err();
    assert_eq!(err, CryptoError::BufferTooSmall);

    // 2. Exact buffer size works
    let mut out_exact = [0u8; 16];
    let len = kdfa(
        &provider,
        TpmiAlgHash::Sha256,
        key,
        label,
        context_u,
        context_v,
        128,
        &mut out_exact,
    )
    .unwrap();
    assert_eq!(len, 16);

    // 3. Larger buffer size works, only populates required bytes
    let mut out_large = [0u8; 32];
    let len = kdfa(
        &provider,
        TpmiAlgHash::Sha256,
        key,
        label,
        context_u,
        context_v,
        128,
        &mut out_large,
    )
    .unwrap();
    assert_eq!(len, 16);
    assert_eq!(out_large[16..], [0u8; 16]);

    // 4. Test bits not divisible by 8 (e.g., 13 bits) -> div_ceil(13, 8) = 2 bytes
    let mut out_non_div = [0u8; 5];
    let len = kdfa(
        &provider,
        TpmiAlgHash::Sha256,
        key,
        label,
        context_u,
        context_v,
        13,
        &mut out_non_div,
    )
    .unwrap();
    assert_eq!(len, 2);
    assert_eq!(out_non_div[0] & 0xE0, 0);
    // Verify against raw HMAC digest with bits=13 that upper 3 bits are masked and lower bits preserved
    let mut raw_ctx = tpm2::crypto::HmacCtx::new(&provider, TpmiAlgHash::Sha256, key).unwrap();
    raw_ctx.update(&1u32.to_be_bytes()).unwrap();
    raw_ctx.update(label).unwrap();
    raw_ctx.update(&[0x00]).unwrap();
    raw_ctx.update(context_u).unwrap();
    raw_ctx.update(context_v).unwrap();
    raw_ctx.update(&13u32.to_be_bytes()).unwrap();
    let mut raw_mac_buf = [0u8; 64];
    let raw_mac = raw_ctx.finalize(&mut raw_mac_buf).unwrap();
    assert_eq!(out_non_div[0], raw_mac.digest()[0] & 0x1F);
    assert_eq!(out_non_div[1], raw_mac.digest()[1]);

    // 4b. Verify label with trailing NUL byte produces identical output
    let mut out_nul_label = [0u8; 16];
    let len_nul = kdfa(
        &provider,
        TpmiAlgHash::Sha256,
        key,
        b"LABEL\0",
        context_u,
        context_v,
        128,
        &mut out_nul_label,
    )
    .unwrap();
    assert_eq!(len_nul, 16);
    assert_eq!(out_exact, out_nul_label);

    // 5. Test different hash algorithms (Sha1, Sha256, Sha384, Sha512)
    let mut out_sha1 = [0u8; 20];
    let len1 = kdfa(
        &provider,
        TpmiAlgHash::Sha1,
        key,
        label,
        context_u,
        context_v,
        160,
        &mut out_sha1,
    )
    .unwrap();
    assert_eq!(len1, 20);

    let mut out_sha384 = [0u8; 48];
    let len3 = kdfa(
        &provider,
        TpmiAlgHash::Sha384,
        key,
        label,
        context_u,
        context_v,
        384,
        &mut out_sha384,
    )
    .unwrap();
    assert_eq!(len3, 48);

    let mut out_sha512 = [0u8; 64];
    let len5 = kdfa(
        &provider,
        TpmiAlgHash::Sha512,
        key,
        label,
        context_u,
        context_v,
        512,
        &mut out_sha512,
    )
    .unwrap();
    assert_eq!(len5, 64);

    // 6. Test very large bit generation (multiple iterations of KDF loop)
    let mut out_huge = [0u8; 512];
    let len_huge = kdfa(
        &provider,
        TpmiAlgHash::Sha256,
        key,
        label,
        context_u,
        context_v,
        4096,
        &mut out_huge,
    )
    .unwrap();
    assert_eq!(len_huge, 512);

    // 7. Empty inputs
    let mut out_empty = [0u8; 32];
    let len_empty = kdfa(
        &provider,
        TpmiAlgHash::Sha256,
        &[],
        &[],
        &[],
        &[],
        256,
        &mut out_empty,
    )
    .unwrap();
    assert_eq!(len_empty, 32);
}

#[test]
fn test_kdfe_boundary_conditions() {
    use tpm2::crypto::kdf::kdfe;
    let provider = TestProvider;

    let z = b"shared_secret_z_value_for_kdfe";
    let label = b"LABEL";
    let party_u = b"party_u";
    let party_v = b"party_v";

    // 1. Verify buffer too small triggers error
    let mut out_small = [0u8; 10];
    let err = kdfe(
        &provider,
        TpmiAlgHash::Sha256,
        z,
        label,
        party_u,
        party_v,
        128,
        &mut out_small,
    )
    .unwrap_err();
    assert_eq!(err, CryptoError::BufferTooSmall);

    // 2. Exact buffer size works
    let mut out_exact = [0u8; 16];
    let len = kdfe(
        &provider,
        TpmiAlgHash::Sha256,
        z,
        label,
        party_u,
        party_v,
        128,
        &mut out_exact,
    )
    .unwrap();
    assert_eq!(len, 16);

    // 3. Larger buffer size works, only populates required bytes
    let mut out_large = [0u8; 32];
    let len = kdfe(
        &provider,
        TpmiAlgHash::Sha256,
        z,
        label,
        party_u,
        party_v,
        128,
        &mut out_large,
    )
    .unwrap();
    assert_eq!(len, 16);
    assert_eq!(out_large[16..], [0u8; 16]);

    // 4. Test bits not divisible by 8 (e.g., 13 bits) -> div_ceil(13, 8) = 2 bytes
    let mut out_non_div = [0u8; 5];
    let len = kdfe(
        &provider,
        TpmiAlgHash::Sha256,
        z,
        label,
        party_u,
        party_v,
        13,
        &mut out_non_div,
    )
    .unwrap();
    assert_eq!(len, 2);
    assert_eq!(out_non_div[0] & 0xE0, 0);
    assert_eq!(out_non_div[0], out_exact[0] & 0x1F);
    assert_eq!(out_non_div[1], out_exact[1]);

    // 4b. Verify label with trailing NUL byte produces identical output
    let mut out_nul_label = [0u8; 16];
    let len_nul = kdfe(
        &provider,
        TpmiAlgHash::Sha256,
        z,
        b"LABEL\0",
        party_u,
        party_v,
        128,
        &mut out_nul_label,
    )
    .unwrap();
    assert_eq!(len_nul, 16);
    assert_eq!(out_exact, out_nul_label);

    // 5. Test different hash algorithms (Sha1, Sha256, Sha384, Sha512)
    let mut out_sha1 = [0u8; 20];
    let len1 = kdfe(
        &provider,
        TpmiAlgHash::Sha1,
        z,
        label,
        party_u,
        party_v,
        160,
        &mut out_sha1,
    )
    .unwrap();
    assert_eq!(len1, 20);

    let mut out_sha384 = [0u8; 48];
    let len3 = kdfe(
        &provider,
        TpmiAlgHash::Sha384,
        z,
        label,
        party_u,
        party_v,
        384,
        &mut out_sha384,
    )
    .unwrap();
    assert_eq!(len3, 48);

    let mut out_sha512 = [0u8; 64];
    let len5 = kdfe(
        &provider,
        TpmiAlgHash::Sha512,
        z,
        label,
        party_u,
        party_v,
        512,
        &mut out_sha512,
    )
    .unwrap();
    assert_eq!(len5, 64);

    // 6. Test very large bit generation (multiple iterations of KDFe loop)
    let mut out_huge = [0u8; 512];
    let len_huge = kdfe(
        &provider,
        TpmiAlgHash::Sha256,
        z,
        label,
        party_u,
        party_v,
        4096,
        &mut out_huge,
    )
    .unwrap();
    assert_eq!(len_huge, 512);

    // 7. Empty inputs
    let mut out_empty = [0u8; 32];
    let len_empty = kdfe(
        &provider,
        TpmiAlgHash::Sha256,
        &[],
        &[],
        &[],
        &[],
        256,
        &mut out_empty,
    )
    .unwrap();
    assert_eq!(len_empty, 32);
}
