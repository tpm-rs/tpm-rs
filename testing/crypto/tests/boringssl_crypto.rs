use tpm2::{
    AlgSym, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmEccCurve, TpmiAlgHash, TpmiRsaKeyBits,
    TpmtHa,
    crypto::{
        CipherInput, CmacContext, Crypto, CryptoError, Direction, EccPrivateKey, HashContext,
        HmacContext, Random, Rng, RsaEncryptScheme, RsaPrivateKey, RsaPublicKey, SymmetricKey,
        backend::{
            AsymmetricKey, Cmac, CmacState, Ecc, EccCurve, EccSigScheme, Hash, HashState, Hmac,
            HmacState, Rsa, RsaKey, RsaSigScheme, Symmetric, SymmetricState,
        },
        hash, hmac, kdfa, kdfa_xor, kdfe,
    },
};
use tpm2_boringssl::{BoringSsl, BoringSslRng};

fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(clean.len() % 2, 0);
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

#[test]
fn test_ct_eq() {
    assert!(BoringSsl::ct_eq(b"", b""));
    assert!(BoringSsl::ct_eq(b"tpm2-boringssl", b"tpm2-boringssl"));
    assert!(!BoringSsl::ct_eq(b"tpm2-boringssl", b"tpm2-boringssL"));
    assert!(!BoringSsl::ct_eq(b"short", b"longer"));
}

#[test]
fn test_hash_kats_and_streaming() {
    // NIST FIPS 180-4 / CAVP vectors for "abc"
    let sha1_abc = hex_array::<20>("a9993e364706816aba3e25717850c26c9cd0d89d");
    let sha256_abc =
        hex_array::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let sha384_abc = hex_array::<48>(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    );
    let sha512_abc = hex_array::<64>(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );

    let mut out1 = [0u8; 20];
    <BoringSsl as Hash>::Sha1::hash(&[b"abc"], &mut out1).unwrap();
    assert_eq!(out1, sha1_abc);

    let mut out256 = [0u8; 32];
    <BoringSsl as Hash>::Sha256::hash(&[b"abc"], &mut out256).unwrap();
    assert_eq!(out256, sha256_abc);

    let mut out384 = [0u8; 48];
    <BoringSsl as Hash>::Sha384::hash(&[b"abc"], &mut out384).unwrap();
    assert_eq!(out384, sha384_abc);

    let mut out512 = [0u8; 64];
    <BoringSsl as Hash>::Sha512::hash(&[b"abc"], &mut out512).unwrap();
    assert_eq!(out512, sha512_abc);

    // Streaming + Clone
    let mut h = <BoringSsl as Hash>::Sha256::init().unwrap();
    h.update(b"a").unwrap();
    let mut h_clone = h.clone();
    h.update(b"bc").unwrap();
    let mut d1 = [0u8; 32];
    h.finalize(&mut d1).unwrap();
    assert_eq!(d1, sha256_abc);

    h_clone.update(b"bc").unwrap();
    let mut d2 = [0u8; 32];
    h_clone.finalize(&mut d2).unwrap();
    assert_eq!(d2, sha256_abc);

    // Dispatch HashContext and KDFe
    let mut ctx = HashContext::<BoringSsl>::new(TpmiAlgHash::Sha256).unwrap();
    ctx.update(b"ab").unwrap();
    ctx.update(b"c").unwrap();
    let mut digest_buf = [0u8; 64];
    assert_eq!(
        ctx.finalize(&mut digest_buf).unwrap().digest(),
        sha256_abc.as_slice()
    );

    let mut kdf_out1 = [0u8; 40];
    let mut kdf_out2 = [0u8; 40];
    kdfe::<BoringSsl>(
        TpmiAlgHash::Sha256,
        b"shared-z",
        c"SM2",
        (b"partyU", b"partyV"),
        &mut kdf_out1,
    )
    .unwrap();
    <BoringSsl as Hash>::Sha256::kdfe(b"shared-z", c"SM2", (b"partyU", b"partyV"), &mut kdf_out2)
        .unwrap();
    assert_eq!(kdf_out1, kdf_out2);
    assert_ne!(kdf_out1, [0u8; 40]);

    // Unsupported hashes
    for alg in [
        TpmiAlgHash::Sm3_256,
        TpmiAlgHash::Sha3_256,
        TpmiAlgHash::Sha3_384,
        TpmiAlgHash::Sha3_512,
    ] {
        assert_eq!(
            hash::<BoringSsl>(alg, &[b"abc"], &mut digest_buf),
            Err(CryptoError::Unsupported)
        );
    }
}

#[test]
fn test_hmac_kats_and_kdfa() {
    // RFC 2202 Test Case 2 (HMAC-SHA-1: key = "Jefe", data = "what do ya want for nothing?")
    let hmac_sha1 = hex_array::<20>("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    let mut out1 = [0u8; 20];
    <BoringSsl as Hmac>::Sha1::hmac(b"Jefe", &[b"what do ya want for nothing?"], &mut out1)
        .unwrap();
    assert_eq!(out1, hmac_sha1);

    // RFC 4231 Test Case 2 (key = "Jefe", data = "what do ya want for nothing?")
    let hmac_sha256 =
        hex_array::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    let hmac_sha384 = hex_array::<48>(
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
         8e2240ca5e69e2c78b3239ecfab21649",
    );
    let hmac_sha512 = hex_array::<64>(
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
         9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    );

    let mut out256 = [0u8; 32];
    <BoringSsl as Hmac>::Sha256::hmac(b"Jefe", &[b"what do ya want for nothing?"], &mut out256)
        .unwrap();
    assert_eq!(out256, hmac_sha256);

    let mut out384 = [0u8; 48];
    <BoringSsl as Hmac>::Sha384::hmac(b"Jefe", &[b"what do ya want for nothing?"], &mut out384)
        .unwrap();
    assert_eq!(out384, hmac_sha384);

    let mut out512 = [0u8; 64];
    <BoringSsl as Hmac>::Sha512::hmac(b"Jefe", &[b"what do ya want for nothing?"], &mut out512)
        .unwrap();
    assert_eq!(out512, hmac_sha512);

    // RFC 4231 Test Case 6 (131-byte key = 0xaa * 131, data = "Test Using Larger Than Block-Size Key - Hash Key First")
    let long_key = [0xaau8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let tc6_sha256 =
        hex_array::<32>("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    <BoringSsl as Hmac>::Sha256::hmac(&long_key, &[data], &mut out256).unwrap();
    assert_eq!(out256, tc6_sha256);

    // Streaming + empty key
    let mut st = <BoringSsl as Hmac>::Sha256::init(b"").unwrap();
    st.update(b"part1").unwrap();
    st.update(b"part2").unwrap();
    let mut m1 = [0u8; 32];
    let mut m2 = [0u8; 32];
    st.finalize(&mut m1).unwrap();
    <BoringSsl as Hmac>::Sha256::hmac(b"", &[b"part1part2"], &mut m2).unwrap();
    assert_eq!(m1, m2);

    // Dispatch HmacContext, KDFa, and KDFa_xor
    let mut hctx = HmacContext::<BoringSsl>::new(TpmiAlgHash::Sha256, b"Jefe").unwrap();
    hctx.update(b"what do ya want ").unwrap();
    hctx.update(b"for nothing?").unwrap();
    let mut mac_buf = [0u8; 64];
    assert_eq!(
        hctx.finalize(&mut mac_buf).unwrap().digest(),
        hmac_sha256.as_slice()
    );

    let mut kdfa_buf = [0u8; 48];
    kdfa::<BoringSsl>(
        TpmiAlgHash::Sha256,
        b"key",
        c"STORAGE",
        (b"ctxU", b"ctxV"),
        &mut kdfa_buf,
    )
    .unwrap();
    let mut xor_buf = kdfa_buf;
    kdfa_xor::<BoringSsl>(
        TpmiAlgHash::Sha256,
        b"key",
        c"STORAGE",
        (b"ctxU", b"ctxV"),
        &mut xor_buf,
    )
    .unwrap();
    assert_eq!(xor_buf, [0u8; 48]);

    assert_eq!(
        hmac::<BoringSsl>(TpmiAlgHash::Sm3_256, b"k", &[b"d"], &mut mac_buf),
        Err(CryptoError::Unsupported)
    );
}

#[test]
fn test_cmac_kats() {
    // NIST SP 800-38B AES-128 CMAC test vectors
    let key128 = hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
    let m16 = hex("6bc1bee22e409f96e93d7e117393172a");
    let m40 =
        hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");

    let tag_empty = hex_array::<16>("bb1d6929e95937287fa37d129b756746");
    let tag_16 = hex_array::<16>("070a16b46b4d4144f79bdd9dd04a287c");
    let tag_40 = hex_array::<16>("dfa66747de9ae63030ca32611497c827");

    let mut out = [0u8; 16];
    <BoringSsl as Cmac>::Aes128::cmac(&key128, &[b""], &mut out).unwrap();
    assert_eq!(out, tag_empty);

    <BoringSsl as Cmac>::Aes128::cmac(&key128, &[&m16], &mut out).unwrap();
    assert_eq!(out, tag_16);

    <BoringSsl as Cmac>::Aes128::cmac(&key128, &[&m40[..10], &m40[10..]], &mut out).unwrap();
    assert_eq!(out, tag_40);

    // Streaming CmacState
    let mut c1 = <BoringSsl as Cmac>::Aes128::init(&key128).unwrap();
    c1.update(&m40[..20]).unwrap();
    c1.update(&m40[20..]).unwrap();
    let mut o1 = [0u8; 16];
    c1.finalize(&mut o1).unwrap();
    assert_eq!(o1, tag_40);

    // NIST SP 800-38B AES-192 & AES-256 CMAC empty message vectors
    let key192 = hex_array::<24>("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    let tag192_empty = hex_array::<16>("d17ddf46adaacde531cac483de7a9367");
    <BoringSsl as Cmac>::Aes192::cmac(&key192, &[b""], &mut out).unwrap();
    assert_eq!(out, tag192_empty);

    let key256 =
        hex_array::<32>("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let tag256_empty = hex_array::<16>("028962f61b7bf89efc6b551f4667d983");
    <BoringSsl as Cmac>::Aes256::cmac(&key256, &[b""], &mut out).unwrap();
    assert_eq!(out, tag256_empty);

    // Unsupported CMAC via dispatch CmacContext
    let sym_sm4 = SymmetricKey::new(AlgSym::Sm4_128, &[0u8; 16]).unwrap();
    assert!(matches!(
        CmacContext::<BoringSsl>::new(sym_sm4),
        Err(CryptoError::Unsupported)
    ));
}

#[test]
fn test_symmetric_modes_and_iv_semantics() {
    let key128 = hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
    let pt_block = hex_array::<16>("6bc1bee22e409f96e93d7e117393172a");
    let ct_ecb = hex_array::<16>("3ad77bb40d7a3660a89ecaf32466ef97");

    let st = <BoringSsl as Symmetric>::Aes128::init(&key128).unwrap();

    // 1. ECB known answer
    let mut blocks = [pt_block];
    st.ecb(Direction::Encrypt, &mut blocks).unwrap();
    assert_eq!(blocks[0], ct_ecb);
    st.ecb(Direction::Decrypt, &mut blocks).unwrap();
    assert_eq!(blocks[0], pt_block);

    // 2. CBC known answer + IV update
    let iv0 = hex_array::<16>("000102030405060608090a0b0c0d0e0f");
    let b1 = hex_array::<16>("6bc1bee22e409f96e93d7e117393172a");
    let b2 = hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51");
    let mut cbc_blocks = [b1, b2];
    let mut iv_enc = iv0;
    st.cbc(Direction::Encrypt, &mut iv_enc, &mut cbc_blocks)
        .unwrap();
    assert_eq!(iv_enc, cbc_blocks[1]);
    let mut iv_dec = iv0;
    st.cbc(Direction::Decrypt, &mut iv_dec, &mut cbc_blocks)
        .unwrap();
    assert_eq!(cbc_blocks, [b1, b2]);
    assert_eq!(iv_dec, iv_enc);

    // 3. CTR partial final block + 128-bit counter wraparound
    let mut ctr_iv = [0xffu8; 16];
    ctr_iv[15] = 0xfe; // 2 blocks: 0xff..fe (full 16B) and 0xff..ff (partial 5B), final iv -> 0x00..00
    let mut ctr_data = [0x42u8; 21];
    let orig_ctr = ctr_data;
    let mut ctr_iv_dec = ctr_iv;
    st.ctr(&mut ctr_iv, &mut ctr_data).unwrap();
    assert_eq!(ctr_iv, [0x00u8; 16]);
    st.ctr(&mut ctr_iv_dec, &mut ctr_data).unwrap();
    assert_eq!(ctr_data, orig_ctr);
    assert_eq!(ctr_iv_dec, [0x00u8; 16]);

    // 4. OFB partial final block: iv must hold full 16-byte final keystream block
    let mut ofb_iv_enc = iv0;
    let mut ofb_data = [0x55u8; 20]; // 1 full block + 4-byte partial block
    let mut expected_iv = iv0;
    st.ecb(Direction::Encrypt, core::slice::from_mut(&mut expected_iv))
        .unwrap();
    st.ecb(Direction::Encrypt, core::slice::from_mut(&mut expected_iv))
        .unwrap();

    st.ofb(&mut ofb_iv_enc, &mut ofb_data).unwrap();
    assert_eq!(ofb_iv_enc, expected_iv);
    let mut ofb_iv_dec = iv0;
    st.ofb(&mut ofb_iv_dec, &mut ofb_data).unwrap();
    assert_eq!(ofb_data, [0x55u8; 20]);
    assert_eq!(ofb_iv_dec, expected_iv);

    // 5. CFB partial final block via `crypt`: iv must hold zero-padded final ciphertext block on both enc & dec
    let mut cfb_iv_enc = iv0;
    let mut cfb_data = [0x77u8; 19]; // 16 + 3 bytes
    st.crypt(
        Direction::Encrypt,
        CipherInput::Cfb(&mut cfb_iv_enc, &mut cfb_data),
    )
    .unwrap();
    assert_eq!(&cfb_iv_enc[..3], &cfb_data[16..19]);
    assert_eq!(&cfb_iv_enc[3..], &[0u8; 13]);

    let mut cfb_iv_dec = iv0;
    st.crypt(
        Direction::Decrypt,
        CipherInput::Cfb(&mut cfb_iv_dec, &mut cfb_data),
    )
    .unwrap();
    assert_eq!(cfb_data, [0x77u8; 19]);
    assert_eq!(cfb_iv_dec, cfb_iv_enc);

    // Unsupported cipher
    let sym_sm4 = SymmetricKey::new(AlgSym::Sm4_128, &[0u8; 16]).unwrap();
    let mut dummy_iv = [0u8; 16];
    let mut dummy_data = [0u8; 16];
    assert_eq!(
        sym_sm4.crypt::<BoringSsl>(
            Direction::Encrypt,
            CipherInput::Ctr(&mut dummy_iv, &mut dummy_data)
        ),
        Err(CryptoError::Unsupported)
    );
}

#[test]
fn test_rng_determinism_and_entropy() {
    let mut rng_sys = BoringSsl::from_entropy().unwrap();
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];
    rng_sys.fill_bytes(&mut buf1).unwrap();
    rng_sys.fill_bytes(&mut buf2).unwrap();
    assert_ne!(buf1, buf2);

    // Deterministic seeding
    let seed = [0x9au8; 48];
    let mut d1 = BoringSsl::from_seed(&seed).unwrap();
    let mut d2 = BoringSsl::from_seed(&seed).unwrap();
    let mut out1 = [0u8; 128];
    let mut out2 = [0u8; 128];
    d1.fill_bytes(&mut out1).unwrap();
    d2.fill_bytes(&mut out2).unwrap();
    assert_eq!(out1, out2);

    d1.stir_bytes(&[0x11u8; 48]).unwrap();
    d2.stir_bytes(&[0x11u8; 48]).unwrap();
    d1.fill_bytes(&mut out1).unwrap();
    d2.fill_bytes(&mut out2).unwrap();
    assert_eq!(out1, out2);
}

#[test]
fn test_rsa_keygen_encrypt_sign() {
    let mut rng1 = BoringSsl::from_seed(b"rsa-deterministic-seed").unwrap();
    let mut rng2 = BoringSsl::from_seed(b"rsa-deterministic-seed").unwrap();

    // Deterministic RSA-1024 generation
    let priv1 = <BoringSsl as Rsa>::Rsa1024::generate(&mut rng1, 65537).unwrap();
    let priv2 = <BoringSsl as Rsa>::Rsa1024::generate(&mut rng2, 65537).unwrap();

    let (mut n1, mut n2) = ([0u8; 128], [0u8; 128]);
    let (mut p1, mut p2) = ([0u8; 64], [0u8; 64]);
    <BoringSsl as Rsa>::Rsa1024::store_public(
        <BoringSsl as Rsa>::Rsa1024::as_public(&priv1),
        &mut n1,
    )
    .unwrap();
    <BoringSsl as Rsa>::Rsa1024::store_public(
        <BoringSsl as Rsa>::Rsa1024::as_public(&priv2),
        &mut n2,
    )
    .unwrap();
    <BoringSsl as Rsa>::Rsa1024::store_private(&priv1, &mut p1).unwrap();
    <BoringSsl as Rsa>::Rsa1024::store_private(&priv2, &mut p2).unwrap();
    assert_eq!(n1, n2);
    assert_eq!(p1, p2);
    assert_eq!(
        <BoringSsl as Rsa>::Rsa1024::exponent(<BoringSsl as Rsa>::Rsa1024::as_public(&priv1)),
        65537
    );

    // Load public & private keys
    let pub_key = <BoringSsl as Rsa>::Rsa1024::load_public(65537, &n1)
        .unwrap()
        .unwrap();
    let priv_key = <BoringSsl as Rsa>::Rsa1024::load_private(pub_key.clone(), &p1)
        .unwrap()
        .unwrap();

    // Invalid modulus / prime rejection
    let mut bad_n = n1;
    bad_n[0] &= 0x7f; // MSB not set
    assert!(
        <BoringSsl as Rsa>::Rsa1024::load_public(65537, &bad_n)
            .unwrap()
            .is_none()
    );
    let mut bad_p = p1;
    bad_p[63] &= 0xfe; // even prime
    assert!(
        <BoringSsl as Rsa>::Rsa1024::load_private(pub_key.clone(), &bad_p)
            .unwrap()
            .is_none()
    );

    // Wrong (but valid) prime rejection
    let priv_other = <BoringSsl as Rsa>::Rsa1024::generate(&mut rng2, 65537).unwrap();
    let mut p_other = [0u8; 64];
    <BoringSsl as Rsa>::Rsa1024::store_private(&priv_other, &mut p_other).unwrap();
    assert!(
        <BoringSsl as Rsa>::Rsa1024::load_private(pub_key.clone(), &p_other)
            .unwrap()
            .is_none()
    );

    // Raw (`TPM_ALG_NULL`) encrypt / decrypt round-trip & range check
    let mut input_block = [0u8; 128];
    input_block[1] = 0x42;
    input_block[127] = 0x99;
    let mut ct_block = [0u8; 128];
    let mut dec_block = [0u8; 128];
    assert_eq!(
        <BoringSsl as Rsa>::Rsa1024::encrypt(
            &mut rng1,
            &pub_key,
            RsaEncryptScheme::Raw,
            &input_block,
            &mut ct_block
        ),
        Ok(Some(()))
    );
    assert_ne!(ct_block, input_block);
    assert_eq!(
        <BoringSsl as Rsa>::Rsa1024::decrypt(
            &mut rng1,
            &priv_key,
            RsaEncryptScheme::Raw,
            &ct_block,
            &mut dec_block
        ),
        Ok(Some(128))
    );
    assert_eq!(dec_block, input_block);

    // Short input and extra leading zeros are the same integer
    let mut long_input = [0u8; 130];
    long_input[2..].copy_from_slice(&input_block);
    for input in [&input_block[1..], &long_input[..]] {
        let mut ct = [0u8; 128];
        assert_eq!(
            <BoringSsl as Rsa>::Rsa1024::encrypt(
                &mut rng1,
                &pub_key,
                RsaEncryptScheme::Raw,
                input,
                &mut ct
            ),
            Ok(Some(()))
        );
        assert_eq!(ct, ct_block);
    }

    // Input `>= n` or longer than the modulus -> None
    let mut too_long = [0u8; 129];
    too_long[0] = 1;
    for input in [&n1[..], &[0xffu8; 128][..], &too_long[..]] {
        assert_eq!(
            <BoringSsl as Rsa>::Rsa1024::encrypt(
                &mut rng1,
                &pub_key,
                RsaEncryptScheme::Raw,
                input,
                &mut ct_block
            ),
            Ok(None)
        );
    }
    // Ciphertext `>= n` -> None
    assert_eq!(
        <BoringSsl as Rsa>::Rsa1024::decrypt(
            &mut rng1,
            &priv_key,
            RsaEncryptScheme::Raw,
            &n1,
            &mut dec_block
        ),
        Ok(None)
    );

    for scheme in [
        RsaEncryptScheme::Rsaes,
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha1,
            label: Some(c"DUPLICATE"),
        },
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha256,
            label: Some(c"DUPLICATE"),
        },
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha384,
            label: None,
        },
    ] {
        let mut ct = [0u8; 128];
        <BoringSsl as Rsa>::Rsa1024::encrypt(
            &mut rng1,
            &pub_key,
            scheme,
            b"secret message",
            &mut ct,
        )
        .unwrap()
        .unwrap();

        let mut pt = [0u8; 128];
        let len = <BoringSsl as Rsa>::Rsa1024::decrypt(&mut rng1, &priv_key, scheme, &ct, &mut pt)
            .unwrap()
            .unwrap();
        assert_eq!(&pt[..len], b"secret message");

        // Tamper ciphertext -> None
        ct[127] ^= 1;
        assert!(
            <BoringSsl as Rsa>::Rsa1024::decrypt(&mut rng1, &priv_key, scheme, &ct, &mut pt,)
                .unwrap()
                .is_none()
        );
    }

    // RSASSA & RSAPSS sign/verify (SHA-512 RSAPSS uses a 62-byte salt on RSA-1024)
    let digest_bytes = [0x5au8; 64];
    for (scheme, alg) in [
        (RsaSigScheme::Rsassa, TpmiAlgHash::Sha256),
        (RsaSigScheme::Rsapss, TpmiAlgHash::Sha256),
        (RsaSigScheme::Rsassa, TpmiAlgHash::Sha512),
        (RsaSigScheme::Rsapss, TpmiAlgHash::Sha512),
    ] {
        let digest = TpmtHa::new(alg, &digest_bytes[..alg.digest_size()]).unwrap();
        let mut sig = [0u8; 128];
        <BoringSsl as Rsa>::Rsa1024::sign(&mut rng1, &priv_key, scheme, digest, &mut sig).unwrap();

        assert!(<BoringSsl as Rsa>::Rsa1024::verify(&pub_key, scheme, digest, &sig).unwrap());
        let mut bad_sig = sig;
        bad_sig[127] ^= 1;
        assert!(!<BoringSsl as Rsa>::Rsa1024::verify(&pub_key, scheme, digest, &bad_sig).unwrap());
        // Signature `>= n` -> false
        assert!(!<BoringSsl as Rsa>::Rsa1024::verify(&pub_key, scheme, digest, &n1).unwrap());
    }

    // Hashes unsupported by BoringSSL's RSA implementation
    let sha3_digest = TpmtHa::new(TpmiAlgHash::Sha3_256, &digest_bytes[..32]).unwrap();
    for scheme in [RsaSigScheme::Rsassa, RsaSigScheme::Rsapss] {
        let mut sig = [0u8; 128];
        assert_eq!(
            <BoringSsl as Rsa>::Rsa1024::sign(&mut rng1, &priv_key, scheme, sha3_digest, &mut sig),
            Err(CryptoError::Unsupported)
        );
    }

    // Dispatch RsaPublicKey / RsaPrivateKey usage check
    let n_2b = Tpm2bPublicKeyRsa::new(&n1).unwrap();
    let p_2b = Tpm2bPrivateKeyRsa::new(&p1).unwrap();
    let fe_pub = RsaPublicKey::<BoringSsl>::load(TpmiRsaKeyBits::Rsa1024, 0, n_2b)
        .unwrap()
        .unwrap();
    let mut fe_ct = [0u8; 512];
    let ct_2b = fe_pub
        .encrypt(&mut rng1, RsaEncryptScheme::Rsaes, b"hello", &mut fe_ct)
        .unwrap()
        .unwrap();
    let ct_vec = ct_2b.as_slice().to_vec();

    let fe_priv = RsaPrivateKey::<BoringSsl>::load(fe_pub, p_2b)
        .unwrap()
        .unwrap();
    let mut fe_pt = [0u8; 512];
    let dec_2b = fe_priv
        .decrypt(&mut rng1, RsaEncryptScheme::Rsaes, &ct_vec, &mut fe_pt)
        .unwrap()
        .unwrap();
    assert_eq!(dec_2b.as_slice(), b"hello");
}

fn test_curve_ops<C: EccCurve<N, P>, const N: usize, const P: usize>(rng: &mut BoringSslRng) {
    // Off-curve point (1, 1) -> None
    let mut point_one = [0u8; P];
    point_one[N - 1] = 1;
    point_one[P - 1] = 1;
    assert!(C::load_public((), &point_one).unwrap().is_none());

    // Keygen, load_public/load_private round-trip & ECDH
    let priv_a = C::generate(rng, ()).unwrap();
    let priv_b = C::generate(rng, ()).unwrap();
    let (mut d_a, mut d_b, mut point_a) = ([0u8; N], [0u8; N], [0u8; P]);
    C::store_private(&priv_a, &mut d_a).unwrap();
    C::store_private(&priv_b, &mut d_b).unwrap();
    C::store_public(C::as_public(&priv_a), &mut point_a).unwrap();
    let pub_a = C::load_public((), &point_a).unwrap().unwrap();
    let mut point_reloaded = [0u8; P];
    C::store_public(&pub_a, &mut point_reloaded).unwrap();
    assert_eq!(point_reloaded, point_a);

    // Scalar 0, scalar >= n, and a scalar for a different public key -> None
    let pub_a2 = C::load_public((), &point_a).unwrap().unwrap();
    assert!(C::load_private(pub_a2, &[0u8; N]).unwrap().is_none());
    let pub_a2 = C::load_public((), &point_a).unwrap().unwrap();
    assert!(C::load_private(pub_a2, &[0xffu8; N]).unwrap().is_none());
    let pub_a2 = C::load_public((), &point_a).unwrap().unwrap();
    assert!(C::load_private(pub_a2, &d_b).unwrap().is_none());

    let reloaded_a = C::load_private(pub_a, &d_a).unwrap().unwrap();
    let mut d_reloaded = [0u8; N];
    C::store_private(&reloaded_a, &mut d_reloaded).unwrap();
    assert_eq!(d_reloaded, d_a);

    let (mut z_ab_x, mut z_ab_y) = ([0u8; N], [0u8; N]);
    let (mut z_ba_x, mut z_ba_y) = ([0u8; N], [0u8; N]);
    assert_eq!(
        C::ecdh(&priv_a, C::as_public(&priv_b), &mut z_ab_x, &mut z_ab_y),
        Ok(Some(()))
    );
    assert_eq!(
        C::ecdh(&priv_b, C::as_public(&priv_a), &mut z_ba_x, &mut z_ba_y),
        Ok(Some(()))
    );
    assert_eq!(z_ab_x, z_ba_x);
    assert_eq!(z_ab_y, z_ba_y);

    // ECDSA & ECSchnorr sign + verify
    let digest_bytes = [0x33u8; 32];
    let digest = TpmtHa::new(TpmiAlgHash::Sha256, &digest_bytes).unwrap();

    for is_schnorr in [false, true] {
        let sign_scheme = if is_schnorr {
            EccSigScheme::Ecschnorr
        } else {
            EccSigScheme::Ecdsa
        };
        let verify_scheme = if is_schnorr {
            EccSigScheme::Ecschnorr
        } else {
            EccSigScheme::Ecdsa
        };

        let (mut r, mut s) = ([0u8; N], [0u8; N]);
        C::sign::<BoringSsl>(rng, &priv_a, sign_scheme, digest, &mut r, &mut s).unwrap();
        assert!(
            C::verify::<BoringSsl>(C::as_public(&priv_a), verify_scheme, digest, &r, &s).unwrap()
        );

        let mut bad_s = s;
        bad_s[N - 1] ^= 1;
        assert!(
            !C::verify::<BoringSsl>(C::as_public(&priv_a), verify_scheme, digest, &r, &bad_s)
                .unwrap()
        );

        let bad_digest_bytes = [0x34u8; 32];
        let bad_digest = TpmtHa::new(TpmiAlgHash::Sha256, &bad_digest_bytes).unwrap();
        assert!(
            !C::verify::<BoringSsl>(C::as_public(&priv_a), verify_scheme, bad_digest, &r, &s)
                .unwrap()
        );
    }
}

#[test]
fn test_ecc_all_nist_curves() {
    let mut rng = BoringSsl::from_seed(b"ecc-test-seed").unwrap();
    test_curve_ops::<<BoringSsl as Ecc>::NistP224, 28, 56>(&mut rng);
    test_curve_ops::<<BoringSsl as Ecc>::NistP256, 32, 64>(&mut rng);
    test_curve_ops::<<BoringSsl as Ecc>::NistP384, 48, 96>(&mut rng);
    test_curve_ops::<<BoringSsl as Ecc>::NistP521, 66, 132>(&mut rng);

    // Deterministic P-256 key generation check
    let mut r1 = BoringSsl::from_seed(b"p256-det").unwrap();
    let mut r2 = BoringSsl::from_seed(b"p256-det").unwrap();
    let k1 = <BoringSsl as Ecc>::NistP256::generate(&mut r1, ()).unwrap();
    let k2 = <BoringSsl as Ecc>::NistP256::generate(&mut r2, ()).unwrap();
    let (mut d1, mut d2) = ([0u8; 32], [0u8; 32]);
    <BoringSsl as Ecc>::NistP256::store_private(&k1, &mut d1).unwrap();
    <BoringSsl as Ecc>::NistP256::store_private(&k2, &mut d2).unwrap();
    assert_eq!(d1, d2);

    // Unsupported curve via dispatch
    assert!(matches!(
        EccPrivateKey::<BoringSsl>::generate(&mut rng, TpmEccCurve::SM2P256, None),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        EccPrivateKey::<BoringSsl>::generate(&mut rng, TpmEccCurve::Curve448, None),
        Err(CryptoError::Unsupported)
    ));
}

#[cfg(not(feature = "boringssl-non-fips"))]
#[test]
fn test_curve25519_disabled_without_non_fips() {
    let mut rng = BoringSsl::from_seed(b"c25519-disabled").unwrap();
    assert!(matches!(
        EccPrivateKey::<BoringSsl>::generate(&mut rng, TpmEccCurve::Curve25519, None),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        EccPrivateKey::<BoringSsl>::generate(
            &mut rng,
            TpmEccCurve::Curve25519,
            Some(tpm2::TpmtEccScheme::Eddsa),
        ),
        Err(CryptoError::Unsupported)
    ));
}

#[cfg(feature = "boringssl-non-fips")]
#[test]
fn test_curve25519_ed25519_and_x25519() {
    use tpm2::{
        TpmtEccScheme, TpmtSigScheme,
        crypto::{
            EccPublicKey, SigningKey, VerifyingKey,
            backend::{AsymmetricKey, EdwardsCurve, MontgomeryCurve},
            sign, sign_message, verify, verify_message,
        },
    };

    let mut rng = BoringSsl::from_seed(b"c25519-enabled").unwrap();

    // 1. RFC 8032 §7.1 TEST 1 (empty message) & TEST 2 (1-byte message 0x72)
    let rfc_seed1 =
        hex_array::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let rfc_pub1 =
        hex_array::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let rfc_sig1 = hex_array::<64>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let pk1 = <BoringSsl as Ecc>::Ed25519::load_public((), &rfc_pub1)
        .unwrap()
        .unwrap();
    let sk1 = <BoringSsl as Ecc>::Ed25519::load_private(pk1.clone(), &rfc_seed1)
        .unwrap()
        .unwrap();
    let mut pk1_bytes = [0u8; 32];
    <BoringSsl as Ecc>::Ed25519::store_public(
        <BoringSsl as Ecc>::Ed25519::as_public(&sk1),
        &mut pk1_bytes,
    )
    .unwrap();
    assert_eq!(pk1_bytes, rfc_pub1);
    let mut seed1_bytes = [0u8; 32];
    <BoringSsl as Ecc>::Ed25519::store_private(&sk1, &mut seed1_bytes).unwrap();
    assert_eq!(seed1_bytes, rfc_seed1);

    // Secret seed which doesn't derive the public key -> None
    let mut bad_seed1 = rfc_seed1;
    bad_seed1[0] ^= 1;
    assert!(
        <BoringSsl as Ecc>::Ed25519::load_private(pk1.clone(), &bad_seed1)
            .unwrap()
            .is_none()
    );

    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    <BoringSsl as Ecc>::Ed25519::sign_message(&sk1, &[], &mut r, &mut s).unwrap();
    assert_eq!(&r[..], &rfc_sig1[..32]);
    assert_eq!(&s[..], &rfc_sig1[32..]);
    assert!(<BoringSsl as Ecc>::Ed25519::verify_message(&pk1, &[], &r, &s).unwrap());

    // Multi-slice message and >4096-byte streaming path
    let chunk_a = [0x41u8; 2500];
    let chunk_b = [0x42u8; 2500];
    let mut full = Vec::with_capacity(5000);
    full.extend_from_slice(&chunk_a);
    full.extend_from_slice(&chunk_b);

    let (mut r_multi, mut s_multi) = ([0u8; 32], [0u8; 32]);
    let (mut r_single, mut s_single) = ([0u8; 32], [0u8; 32]);
    <BoringSsl as Ecc>::Ed25519::sign_message(
        &sk1,
        &[&chunk_a, &chunk_b],
        &mut r_multi,
        &mut s_multi,
    )
    .unwrap();
    <BoringSsl as Ecc>::Ed25519::sign_message(&sk1, &[&full], &mut r_single, &mut s_single)
        .unwrap();
    assert_eq!(r_multi, r_single);
    assert_eq!(s_multi, s_single);
    assert!(
        <BoringSsl as Ecc>::Ed25519::verify_message(
            &pk1,
            &[&chunk_a, &chunk_b],
            &r_multi,
            &s_multi
        )
        .unwrap()
    );
    let mut bad_s = s_multi;
    bad_s[0] ^= 1;
    assert!(
        !<BoringSsl as Ecc>::Ed25519::verify_message(&pk1, &[&chunk_a, &chunk_b], &r_multi, &bad_s)
            .unwrap()
    );

    // Non-canonical point y = 2^255 - 19 (all 0xff except byte 0 = 0xed, byte 31 = 0x7f) -> rejected
    let non_canon_y =
        hex_array::<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    assert!(
        <BoringSsl as Ecc>::Ed25519::load_public((), &non_canon_y)
            .unwrap()
            .is_none()
    );

    // RFC 8032 §7.3 Ed25519ph (HashEdDSA) test vector for message "abc"
    let ph_seed =
        hex_array::<32>("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    let ph_pub =
        hex_array::<32>("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let ph_sig = hex_array::<64>(
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41\
         31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
    );
    let sha512_abc = hex_array::<64>(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
    let ph_pk = <BoringSsl as Ecc>::Ed25519::load_public((), &ph_pub)
        .unwrap()
        .unwrap();
    let ph_sk = <BoringSsl as Ecc>::Ed25519::load_private(ph_pk.clone(), &ph_seed)
        .unwrap()
        .unwrap();
    <BoringSsl as Ecc>::Ed25519::sign_prehash(&ph_sk, &sha512_abc, &mut r, &mut s).unwrap();
    assert_eq!(&r[..], &ph_sig[..32]);
    assert_eq!(&s[..], &ph_sig[32..]);
    assert!(<BoringSsl as Ecc>::Ed25519::verify_prehash(&ph_pk, &sha512_abc, &r, &s).unwrap());

    // Dispatch Ed25519 pure & HashEdDSA signing
    let fe_ed_sk = EccPrivateKey::<BoringSsl>::generate(
        &mut rng,
        TpmEccCurve::Curve25519,
        Some(TpmtEccScheme::Eddsa),
    )
    .unwrap();
    let (mut ox, mut oy) = ([0u8; 66], [0u8; 66]);
    let pt = fe_ed_sk.point(&mut ox, &mut oy).unwrap();
    let fe_ed_pk =
        EccPublicKey::<BoringSsl>::load(TpmEccCurve::Curve25519, Some(TpmtEccScheme::Eddsa), pt)
            .unwrap()
            .unwrap();
    let mut sig_buf = [0u8; tpm2::crypto::MAX_SIGNATURE_BYTES];
    let ed_sig = sign_message::<BoringSsl>(
        &mut rng,
        SigningKey::Ecc(&fe_ed_sk),
        TpmtSigScheme::Eddsa,
        &[b"hello ", b"ed25519"],
        &mut sig_buf,
    )
    .unwrap();
    assert!(
        verify_message::<BoringSsl>(VerifyingKey::Ecc(&fe_ed_pk), &[b"hello ed25519"], ed_sig)
            .unwrap()
    );
    let hed_sig = sign::<BoringSsl>(
        &mut rng,
        SigningKey::Ecc(&fe_ed_sk),
        TpmtSigScheme::HashEddsa,
        &sha512_abc,
        &mut sig_buf,
    )
    .unwrap();
    assert!(verify::<BoringSsl>(VerifyingKey::Ecc(&fe_ed_pk), &sha512_abc, hed_sig).unwrap());

    // 2. RFC 7748 §6.1 X25519 test vector
    let alice_priv =
        hex_array::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub_expected =
        hex_array::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_priv =
        hex_array::<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pub_expected =
        hex_array::<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared_expected =
        hex_array::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let a_pk = <BoringSsl as Ecc>::X25519::load_public((), &alice_pub_expected)
        .unwrap()
        .unwrap();
    let b_pk = <BoringSsl as Ecc>::X25519::load_public((), &bob_pub_expected)
        .unwrap()
        .unwrap();
    // Scalar which doesn't derive the public key -> None
    assert!(
        <BoringSsl as Ecc>::X25519::load_private(a_pk.clone(), &bob_priv)
            .unwrap()
            .is_none()
    );
    let a_sk = <BoringSsl as Ecc>::X25519::load_private(a_pk, &alice_priv)
        .unwrap()
        .unwrap();
    let b_sk = <BoringSsl as Ecc>::X25519::load_private(b_pk, &bob_priv)
        .unwrap()
        .unwrap();
    let (mut a_u, mut b_u) = ([0u8; 32], [0u8; 32]);
    <BoringSsl as Ecc>::X25519::store_public(
        <BoringSsl as Ecc>::X25519::as_public(&a_sk),
        &mut a_u,
    )
    .unwrap();
    <BoringSsl as Ecc>::X25519::store_public(
        <BoringSsl as Ecc>::X25519::as_public(&b_sk),
        &mut b_u,
    )
    .unwrap();
    assert_eq!(a_u, alice_pub_expected);
    assert_eq!(b_u, bob_pub_expected);
    let mut a_scalar = [0u8; 32];
    <BoringSsl as Ecc>::X25519::store_private(&a_sk, &mut a_scalar).unwrap();
    assert_eq!(a_scalar, alice_priv);

    let mut ss_ab = [0u8; 32];
    let mut ss_ba = [0u8; 32];
    assert_eq!(
        <BoringSsl as Ecc>::X25519::ecdh(
            &a_sk,
            <BoringSsl as Ecc>::X25519::as_public(&b_sk),
            &mut ss_ab
        ),
        Ok(Some(()))
    );
    assert_eq!(
        <BoringSsl as Ecc>::X25519::ecdh(
            &b_sk,
            <BoringSsl as Ecc>::X25519::as_public(&a_sk),
            &mut ss_ba
        ),
        Ok(Some(()))
    );
    assert_eq!(ss_ab, shared_expected);
    assert_eq!(ss_ba, shared_expected);

    // Low-order point u = 0 -> ecdh returns Ok(None)
    let zero_pub = <BoringSsl as Ecc>::X25519::load_public((), &[0u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        <BoringSsl as Ecc>::X25519::ecdh(&a_sk, &zero_pub, &mut ss_ab),
        Ok(None)
    );
}

#[test]
fn test_mlkem_768_and_1024() {
    use tpm2::{
        Tpm2bKemCiphertext, Tpm2bPublicKeyMlkem, TpmiMlkemParms,
        crypto::{MlkemPrivateKey, MlkemPublicKey},
    };

    let mut rng = BoringSsl::from_seed(b"mlkem-seed").unwrap();

    // ML-KEM-512 is unsupported by BoringSSL
    assert!(matches!(
        MlkemPrivateKey::<BoringSsl>::generate(&mut rng, TpmiMlkemParms::Mlkem512),
        Err(CryptoError::Unsupported)
    ));

    for parms in [TpmiMlkemParms::Mlkem768, TpmiMlkemParms::Mlkem1024] {
        let sk = MlkemPrivateKey::<BoringSsl>::generate(&mut rng, parms).unwrap();
        let mut seed_buf = [0u8; 64];
        sk.seed(&mut seed_buf).unwrap();

        let mut pk_buf1 = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let mut pk_buf2 = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let pk_2b = sk.public(&mut pk_buf1).unwrap();

        let pk = MlkemPublicKey::<BoringSsl>::load(parms, pk_2b)
            .unwrap()
            .unwrap();
        let sk_loaded = MlkemPrivateKey::<BoringSsl>::load(pk, tpm2::Tpm2b(&seed_buf))
            .unwrap()
            .unwrap();
        let pk2_2b = sk_loaded.public(&mut pk_buf2).unwrap();
        assert_eq!(pk_2b.as_slice(), pk2_2b.as_slice());

        // Wrong seed rejected by load
        let pk_again = MlkemPublicKey::<BoringSsl>::load(parms, pk_2b)
            .unwrap()
            .unwrap();
        let mut bad_seed = seed_buf;
        bad_seed[0] ^= 1;
        assert!(
            MlkemPrivateKey::<BoringSsl>::load(pk_again, tpm2::Tpm2b(&bad_seed))
                .unwrap()
                .is_none()
        );

        // Non-reduced coefficient (0xfff >= 3329) rejected by FIPS 203 modulus check
        let mut bad_pk_bytes = pk_2b.as_slice().to_vec();
        bad_pk_bytes[0] = 0xff;
        bad_pk_bytes[1] = 0xff;
        let bad_pk_2b = Tpm2bPublicKeyMlkem::new(&bad_pk_bytes).unwrap();
        assert!(
            MlkemPublicKey::<BoringSsl>::load(parms, bad_pk_2b)
                .unwrap()
                .is_none()
        );

        // Encapsulate / decapsulate round-trip
        let pk_enc = MlkemPublicKey::<BoringSsl>::load(parms, pk_2b)
            .unwrap()
            .unwrap();
        let mut ct_buf = [0u8; TpmiMlkemParms::MAX_CT_BYTES];
        let mut ss_enc_buf = [0u8; 32];
        let (ct_2b, ss_enc) = pk_enc
            .encapsulate(&mut rng, &mut ct_buf, &mut ss_enc_buf)
            .unwrap();
        let ct_vec = ct_2b.as_slice().to_vec();

        let mut ss_dec_buf = [0u8; 32];
        let ss_dec = sk_loaded
            .decapsulate(Tpm2bKemCiphertext::new(&ct_vec).unwrap(), &mut ss_dec_buf)
            .unwrap()
            .unwrap();
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());

        // Implicit rejection on modified ciphertext
        let mut bad_ct = ct_vec;
        bad_ct[0] ^= 1;
        let mut ss_bad_buf = [0u8; 32];
        let ss_bad = sk_loaded
            .decapsulate(Tpm2bKemCiphertext::new(&bad_ct).unwrap(), &mut ss_bad_buf)
            .unwrap()
            .unwrap();
        assert_ne!(ss_enc.as_slice(), ss_bad.as_slice());
    }
}

#[test]
fn test_mldsa_44_65_87() {
    use tpm2::{
        TpmiMldsaParms, TpmtSigScheme,
        crypto::{
            MldsaPrivateKey, MldsaPublicKey, SigningKey, VerifyingKey, sign, sign_message, verify,
            verify_message,
        },
    };

    let mut rng = BoringSsl::from_seed(b"mldsa-seed").unwrap();

    for parms in [
        TpmiMldsaParms::Mldsa44,
        TpmiMldsaParms::Mldsa65,
        TpmiMldsaParms::Mldsa87,
    ] {
        let sk = MldsaPrivateKey::<BoringSsl>::generate(&mut rng, parms).unwrap();
        let mut seed_buf = [0u8; 32];
        sk.seed(&mut seed_buf).unwrap();

        let mut pk_buf1 = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let mut pk_buf2 = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let pk_2b = sk.public(&mut pk_buf1).unwrap();

        let pk = MldsaPublicKey::<BoringSsl>::load(parms, pk_2b)
            .unwrap()
            .unwrap();
        let sk_loaded = MldsaPrivateKey::<BoringSsl>::load(pk, tpm2::Tpm2b(&seed_buf))
            .unwrap()
            .unwrap();
        let pk2_2b = sk_loaded.public(&mut pk_buf2).unwrap();
        assert_eq!(pk_2b.as_slice(), pk2_2b.as_slice());

        // Wrong seed rejected by load
        let pk_again = MldsaPublicKey::<BoringSsl>::load(parms, pk_2b)
            .unwrap()
            .unwrap();
        let mut bad_seed = seed_buf;
        bad_seed[0] ^= 1;
        assert!(
            MldsaPrivateKey::<BoringSsl>::load(pk_again, tpm2::Tpm2b(&bad_seed))
                .unwrap()
                .is_none()
        );

        let pk_ver = MldsaPublicKey::<BoringSsl>::load(parms, pk_2b)
            .unwrap()
            .unwrap();

        // 1. Pure ML-DSA message signing & verification (multi-slice, empty & non-empty context)
        let mut sig_buf = [0u8; tpm2::crypto::MAX_SIGNATURE_BYTES];
        for ctx in [&b""[..], &b"tpm2-boringssl-ctx"[..]] {
            let sig = sign_message::<BoringSsl>(
                &mut rng,
                SigningKey::Mldsa {
                    key: &sk,
                    context: ctx,
                },
                TpmtSigScheme::Mldsa,
                &[b"multi-", b"slice ", b"message"],
                &mut sig_buf,
            )
            .unwrap();
            assert!(
                verify_message::<BoringSsl>(
                    VerifyingKey::Mldsa {
                        key: &pk_ver,
                        context: ctx,
                    },
                    &[b"multi-slice message"],
                    sig,
                )
                .unwrap()
            );
            assert!(
                !verify_message::<BoringSsl>(
                    VerifyingKey::Mldsa {
                        key: &pk_ver,
                        context: ctx,
                    },
                    &[b"wrong message"],
                    sig,
                )
                .unwrap()
            );
            assert!(
                !verify_message::<BoringSsl>(
                    VerifyingKey::Mldsa {
                        key: &pk_ver,
                        context: b"other-ctx",
                    },
                    &[b"multi-slice message"],
                    sig,
                )
                .unwrap()
            );
        }

        // 2. External-mu ML-DSA signing & verification (requires empty context)
        let mu = [0x5au8; 64];
        let mu_sig = sign::<BoringSsl>(
            &mut rng,
            SigningKey::Mldsa {
                key: &sk,
                context: b"",
            },
            TpmtSigScheme::Mldsa,
            &mu,
            &mut sig_buf,
        )
        .unwrap();
        assert!(
            verify::<BoringSsl>(
                VerifyingKey::Mldsa {
                    key: &pk_ver,
                    context: b"",
                },
                &mu,
                mu_sig,
            )
            .unwrap()
        );
        let mut bad_mu = mu;
        bad_mu[0] ^= 1;
        assert!(
            !verify::<BoringSsl>(
                VerifyingKey::Mldsa {
                    key: &pk_ver,
                    context: b"",
                },
                &bad_mu,
                mu_sig,
            )
            .unwrap()
        );

        // 3. HashML-DSA signing & verification (empty & non-empty context)
        for hash_alg in [
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
            TpmiAlgHash::Sha3_256,
            TpmiAlgHash::Sha3_384,
            TpmiAlgHash::Sha3_512,
        ] {
            let ph_bytes = [0x42u8; 64];
            let ph = &ph_bytes[..hash_alg.digest_size()];
            for ctx in [&b""[..], &b"hash-mldsa-ctx"[..]] {
                let ph_sig = sign::<BoringSsl>(
                    &mut rng,
                    SigningKey::HashMldsa {
                        key: &sk,
                        hash: hash_alg,
                        context: ctx,
                    },
                    TpmtSigScheme::HashMldsa,
                    ph,
                    &mut sig_buf,
                )
                .unwrap();
                assert!(
                    verify::<BoringSsl>(
                        VerifyingKey::Mldsa {
                            key: &pk_ver,
                            context: ctx,
                        },
                        ph,
                        ph_sig,
                    )
                    .unwrap()
                );

                let bad_ph_bytes = [0x43u8; 64];
                let bad_ph = &bad_ph_bytes[..hash_alg.digest_size()];
                assert!(
                    !verify::<BoringSsl>(
                        VerifyingKey::Mldsa {
                            key: &pk_ver,
                            context: ctx,
                        },
                        bad_ph,
                        ph_sig,
                    )
                    .unwrap()
                );
                assert!(
                    !verify::<BoringSsl>(
                        VerifyingKey::Mldsa {
                            key: &pk_ver,
                            context: b"wrong-ctx",
                        },
                        ph,
                        ph_sig,
                    )
                    .unwrap()
                );
            }
        }

        // Non-FIPS-204 prehash (SHA-1) returns Unsupported
        assert_eq!(
            sign::<BoringSsl>(
                &mut rng,
                SigningKey::HashMldsa {
                    key: &sk,
                    hash: TpmiAlgHash::Sha1,
                    context: b"",
                },
                TpmtSigScheme::HashMldsa,
                &[0u8; 20],
                &mut sig_buf,
            ),
            Err(CryptoError::Unsupported)
        );
    }
}
