//! Shared `testing-crypto` suite and cross-backend interoperability matrix
//! for `tpm2-boringssl` against `tpm2-rustcrypto` and `tpm2-openssl`.

use testing_crypto::*;
use tpm2::{
    TpmEccCurve, TpmiAlgHash, TpmtHa, TpmtSigScheme,
    crypto::{
        EccPrivateKey, EccPublicKey, Random, Rng, RsaEncryptScheme, SigningKey, VerifyingKey,
        backend::{
            AsymmetricKey, Ecc, EccCurve, EccSigScheme, Mldsa, MldsaKey, Mlkem, MlkemKey, Rsa,
            RsaKey, RsaSigScheme,
        },
        sign, verify,
    },
};
use tpm2_boringssl::{BoringSsl, BoringSslRng};
use tpm2_openssl::OpensslBackend;
use tpm2_rustcrypto::RustCrypto;

#[test]
fn test_hash_one_shot() {
    hash_one_shot::<BoringSsl>();
}
#[test]
fn test_hash_one_shot_parts() {
    hash_one_shot_parts::<BoringSsl>();
}
#[test]
fn test_hash_streaming() {
    hash_streaming::<BoringSsl>();
}
#[test]
fn test_hash_wrong_output_size() {
    hash_wrong_output_size::<BoringSsl>();
}
#[test]
fn test_hash_longer_output_buffer() {
    hash_longer_output_buffer::<BoringSsl>();
}

#[test]
fn test_hmac_one_shot() {
    hmac_one_shot::<BoringSsl>();
}
#[test]
fn test_hmac_streaming() {
    hmac_streaming::<BoringSsl>();
}
#[test]
fn test_kdfa_single_block_matches_hmac() {
    kdfa_single_block_matches_hmac::<BoringSsl>();
}
#[test]
fn test_kdfa_xor_matches_kdfa() {
    kdfa_xor_matches_kdfa::<BoringSsl>();
}
#[test]
fn test_kdfe_single_block_matches_hash() {
    kdfe_single_block_matches_hash::<BoringSsl>();
}
#[test]
fn test_specialized_one_shot_override() {
    specialized_one_shot_override::<BoringSsl>();
}
#[test]
fn test_implements_crypto() {
    implements_crypto::<BoringSsl>();
}

#[test]
fn test_random() {
    random_tests::<BoringSsl>();
}
#[test]
fn test_fips197_ecb() {
    fips197_ecb::<BoringSsl>();
}
#[test]
fn test_sp800_38a_modes() {
    sp800_38a_modes::<BoringSsl>();
}
#[test]
fn test_chaining_matches_single_call() {
    chaining_matches_single_call::<BoringSsl>();
}
#[test]
fn test_matches_reference_implementation() {
    matches_reference_implementation::<BoringSsl>();
}
#[test]
fn test_cipher_input_validation() {
    cipher_input_validation::<BoringSsl>();
}
#[test]
fn test_symmetric_key() {
    symmetric_key::<BoringSsl>();
}
#[test]
fn test_unsupported() {
    unsupported::<BoringSsl>();
}

#[test]
fn test_cmac_vectors() {
    cmac_vectors::<BoringSsl>();
}

#[test]
fn test_hash_vectors() {
    hash_vectors::<BoringSsl>();
}

#[test]
fn test_hmac_vectors() {
    hmac_vectors::<BoringSsl>();
}

#[test]
fn test_kdf_vectors() {
    kdf_vectors::<BoringSsl>();
}

#[test]
fn test_cipher_vectors() {
    cipher_vectors::<BoringSsl>();
}

#[test]
fn test_rsa_vectors() {
    let mut rng = BoringSsl::from_seed(b"boringssl-rsa-vectors").unwrap();
    rsa_vectors::<BoringSsl>(&mut rng);
}

#[test]
fn test_ecc_vectors() {
    let mut rng = BoringSsl::from_seed(b"boringssl-ecc-vectors").unwrap();
    ecc_vectors::<BoringSsl>(&mut rng);
}

#[test]
fn test_asym_vectors() {
    let mut rng = BoringSsl::from_seed(b"boringssl-asym-vectors").unwrap();
    asym_vectors::<BoringSsl>(&mut rng);
}

#[test]
fn test_interop_rsa_vs_openssl() {
    let mut rng = BoringSsl::from_seed(b"boringssl-interop-rsa-ossl").unwrap();
    interop_rsa_sign_verify::<BoringSsl, OpensslBackend>(&mut rng);
    interop_rsa_sign_verify::<OpensslBackend, BoringSsl>(&mut rng);
    interop_rsa_encrypt_decrypt::<BoringSsl, OpensslBackend>(&mut rng);
    interop_rsa_encrypt_decrypt::<OpensslBackend, BoringSsl>(&mut rng);
}

#[test]
fn test_interop_rsa_sign_vs_rustcrypto() {
    let mut rng = BoringSsl::from_seed(b"boringssl-interop-rsa-rc-sign").unwrap();
    interop_rsa_sign_verify::<BoringSsl, RustCrypto>(&mut rng);
    interop_rsa_sign_verify::<RustCrypto, BoringSsl>(&mut rng);
}

#[test]
fn test_interop_rsa_enc_vs_rustcrypto() {
    let mut rng = BoringSsl::from_seed(b"boringssl-interop-rsa-rc-enc").unwrap();
    interop_rsa_encrypt_decrypt::<BoringSsl, RustCrypto>(&mut rng);
    interop_rsa_encrypt_decrypt::<RustCrypto, BoringSsl>(&mut rng);
}

#[test]
fn test_interop_ecc_and_pqc_shared_helpers() {
    let mut rng = BoringSsl::from_seed(b"boringssl-interop").unwrap();

    // ECDSA sign/verify & ECDH vs RustCrypto and OpensslBackend (both directions)
    interop_ecdsa_sign_verify::<BoringSsl, RustCrypto>(&mut rng);
    interop_ecdsa_sign_verify::<RustCrypto, BoringSsl>(&mut rng);
    interop_ecdsa_sign_verify::<BoringSsl, OpensslBackend>(&mut rng);
    interop_ecdsa_sign_verify::<OpensslBackend, BoringSsl>(&mut rng);

    interop_ecdh::<BoringSsl, RustCrypto>(&mut rng);
    interop_ecdh::<RustCrypto, BoringSsl>(&mut rng);
    interop_ecdh::<BoringSsl, OpensslBackend>(&mut rng);
    interop_ecdh::<OpensslBackend, BoringSsl>(&mut rng);

    // Ed25519, Ed448, X25519, ML-KEM-768, ML-DSA-44/65/87 vs RustCrypto and OpensslBackend (both directions)
    interop_ed25519::<BoringSsl, RustCrypto>(&mut rng);
    interop_ed25519::<RustCrypto, BoringSsl>(&mut rng);
    interop_ed25519::<BoringSsl, OpensslBackend>(&mut rng);
    interop_ed25519::<OpensslBackend, BoringSsl>(&mut rng);

    interop_ed448::<BoringSsl, RustCrypto>(&mut rng);
    interop_ed448::<RustCrypto, BoringSsl>(&mut rng);
    interop_ed448::<BoringSsl, OpensslBackend>(&mut rng);
    interop_ed448::<OpensslBackend, BoringSsl>(&mut rng);

    interop_x25519::<BoringSsl, RustCrypto>(&mut rng);
    interop_x25519::<RustCrypto, BoringSsl>(&mut rng);
    interop_x25519::<BoringSsl, OpensslBackend>(&mut rng);
    interop_x25519::<OpensslBackend, BoringSsl>(&mut rng);

    interop_mlkem::<BoringSsl, RustCrypto>(&mut rng);
    interop_mlkem::<RustCrypto, BoringSsl>(&mut rng);
    interop_mlkem::<BoringSsl, OpensslBackend>(&mut rng);
    interop_mlkem::<OpensslBackend, BoringSsl>(&mut rng);

    interop_mldsa::<BoringSsl, RustCrypto>(&mut rng);
    interop_mldsa::<RustCrypto, BoringSsl>(&mut rng);
    interop_mldsa::<BoringSsl, OpensslBackend>(&mut rng);
    interop_mldsa::<OpensslBackend, BoringSsl>(&mut rng);
}

fn check_ecschnorr_interop<Signer: tpm2::crypto::Crypto, Verifier: tpm2::crypto::Crypto>(
    rng: &mut impl Rng,
) {
    let digest_bytes = [0x33u8; 32];
    let digest = TpmtHa::Sha256(&digest_bytes);
    macro_rules! check_curve {
        ($Curve:ident, $COORD:expr) => {
            if let Ok(priv_key) = <Signer as Ecc>::$Curve::generate(rng, ()) {
                let pub_key = <Signer as Ecc>::$Curve::as_public(&priv_key);
                let mut q = [0u8; 2 * $COORD];
                <Signer as Ecc>::$Curve::store_public(pub_key, &mut q).unwrap();
                let mut r = [0u8; $COORD];
                let mut s = [0u8; $COORD];
                if let Ok(()) = <Signer as Ecc>::$Curve::sign::<Signer>(
                    rng,
                    &priv_key,
                    EccSigScheme::Ecschnorr,
                    digest,
                    &mut r,
                    &mut s,
                ) {
                    if let Ok(Some(ver_pub)) = <Verifier as Ecc>::$Curve::load_public((), &q) {
                        match <Verifier as Ecc>::$Curve::verify::<Verifier>(
                            &ver_pub,
                            EccSigScheme::Ecschnorr,
                            digest,
                            &r,
                            &s,
                        ) {
                            Ok(valid) => {
                                assert!(valid, "ECSchnorr verify failed on {}", stringify!($Curve))
                            }
                            Err(tpm2::crypto::CryptoError::Unsupported) => {}
                            Err(e) => {
                                panic!("ECSchnorr verify error on {}: {e:?}", stringify!($Curve))
                            }
                        }
                    }
                }
            }
        };
    }
    check_curve!(NistP224, 28);
    check_curve!(NistP256, 32);
    check_curve!(NistP384, 48);
}

#[test]
fn test_interop_ecschnorr_and_all_nist_curves() {
    let mut rng = BoringSsl::from_seed(b"boringssl-ecschnorr-interop").unwrap();

    // ECSchnorr across P-224, P-256, P-384, P-521
    check_ecschnorr_interop::<BoringSsl, OpensslBackend>(&mut rng);
    check_ecschnorr_interop::<OpensslBackend, BoringSsl>(&mut rng);
    check_ecschnorr_interop::<BoringSsl, RustCrypto>(&mut rng);
    check_ecschnorr_interop::<RustCrypto, BoringSsl>(&mut rng);

    // Also verify P-521 ECSchnorr between BoringSsl and OpensslBackend
    {
        let digest_bytes = [0x33u8; 32];
        let digest = TpmtHa::Sha256(&digest_bytes);
        let sk_b = <BoringSsl as Ecc>::NistP521::generate(&mut rng, ()).unwrap();
        let pk_b = <BoringSsl as Ecc>::NistP521::as_public(&sk_b);
        let mut q = [0u8; 132];
        <BoringSsl as Ecc>::NistP521::store_public(pk_b, &mut q).unwrap();
        let (mut r, mut s) = ([0u8; 66], [0u8; 66]);
        <BoringSsl as Ecc>::NistP521::sign::<BoringSsl>(
            &mut rng,
            &sk_b,
            EccSigScheme::Ecschnorr,
            digest,
            &mut r,
            &mut s,
        )
        .unwrap();
        let pk_o = <OpensslBackend as Ecc>::NistP521::load_public((), &q)
            .unwrap()
            .unwrap();
        assert!(
            <OpensslBackend as Ecc>::NistP521::verify::<OpensslBackend>(
                &pk_o,
                EccSigScheme::Ecschnorr,
                digest,
                &r,
                &s,
            )
            .unwrap()
        );

        let sk_o = <OpensslBackend as Ecc>::NistP521::generate(&mut rng, ()).unwrap();
        let pk_o2 = <OpensslBackend as Ecc>::NistP521::as_public(&sk_o);
        <OpensslBackend as Ecc>::NistP521::store_public(pk_o2, &mut q).unwrap();
        <OpensslBackend as Ecc>::NistP521::sign::<OpensslBackend>(
            &mut rng,
            &sk_o,
            EccSigScheme::Ecschnorr,
            digest,
            &mut r,
            &mut s,
        )
        .unwrap();
        let pk_b2 = <BoringSsl as Ecc>::NistP521::load_public((), &q)
            .unwrap()
            .unwrap();
        assert!(
            <BoringSsl as Ecc>::NistP521::verify::<BoringSsl>(
                &pk_b2,
                EccSigScheme::Ecschnorr,
                digest,
                &r,
                &s,
            )
            .unwrap()
        );
    }

    // P-224 and P-521 ECDSA and ECDH interop (in addition to P-256/P-384 in interop_ecdsa/ecdh)
    let digest_bytes = [0x44u8; 32];
    let digest = TpmtHa::Sha256(&digest_bytes);
    for curve in [
        TpmEccCurve::NistP224,
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
    ] {
        // BoringSsl <-> OpensslBackend ECDSA & ECDH
        let sk_b = EccPrivateKey::<BoringSsl>::generate(&mut rng, curve, None).unwrap();
        let (mut bx, mut by) = ([0u8; 66], [0u8; 66]);
        let b_pt = sk_b.point(&mut bx, &mut by).unwrap();
        let pk_o = EccPublicKey::<OpensslBackend>::load(curve, None, b_pt)
            .unwrap()
            .unwrap();
        let mut sig_buf = [0u8; tpm2::crypto::MAX_SIGNATURE_BYTES];
        let sig = sign::<BoringSsl>(
            &mut rng,
            SigningKey::Ecc(&sk_b),
            TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
            &digest_bytes,
            &mut sig_buf,
        )
        .unwrap();
        assert!(verify::<OpensslBackend>(VerifyingKey::Ecc(&pk_o), &digest_bytes, sig).unwrap());

        let sk_o = EccPrivateKey::<OpensslBackend>::generate(&mut rng, curve, None).unwrap();
        let (mut ox, mut oy) = ([0u8; 66], [0u8; 66]);
        let o_pt = sk_o.point(&mut ox, &mut oy).unwrap();
        let pk_b = EccPublicKey::<BoringSsl>::load(curve, None, o_pt)
            .unwrap()
            .unwrap();
        let mut sig_buf2 = [0u8; tpm2::crypto::MAX_SIGNATURE_BYTES];
        let sig2 = sign::<OpensslBackend>(
            &mut rng,
            SigningKey::Ecc(&sk_o),
            TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
            &digest_bytes,
            &mut sig_buf2,
        )
        .unwrap();
        assert!(verify::<BoringSsl>(VerifyingKey::Ecc(&pk_b), &digest_bytes, sig2).unwrap());

        let (mut zbx, mut zby) = ([0u8; 66], [0u8; 66]);
        let (mut zox, mut zoy) = ([0u8; 66], [0u8; 66]);
        let zb = sk_b.ecdh(&pk_b, &mut zbx, &mut zby).unwrap().unwrap();
        let zo = sk_o.ecdh(&pk_o, &mut zox, &mut zoy).unwrap().unwrap();
        assert_eq!(zb.x.as_slice(), zo.x.as_slice());
        assert_eq!(zb.y.as_slice(), zo.y.as_slice());
        let _ = digest;
    }
}

#[test]
fn test_interop_rsa_pss_and_oaep() {
    let mut rng = BoringSsl::from_seed(b"boringssl-rsa-pss-oaep-interop").unwrap();
    let digest = [0x55u8; 32];

    // Generate a 2048-bit key once via BoringSSL and load (n, p) into each backend.
    let gen_sk = <BoringSsl as Rsa>::Rsa2048::generate(&mut rng, 65537).unwrap();
    let gen_pk = <BoringSsl as Rsa>::Rsa2048::as_public(&gen_sk);
    let mut n = [0u8; 256];
    let mut p = [0u8; 128];
    <BoringSsl as Rsa>::Rsa2048::store_public(gen_pk, &mut n).unwrap();
    <BoringSsl as Rsa>::Rsa2048::store_private(&gen_sk, &mut p).unwrap();

    macro_rules! check_rsa_pair {
        ($A:ty, $B:ty) => {{
            let pk_a = <$A as Rsa>::Rsa2048::load_public(65537, &n)
                .unwrap()
                .unwrap();
            let sk_a = <$A as Rsa>::Rsa2048::load_private(pk_a, &p)
                .unwrap()
                .unwrap();
            let pk_b = <$B as Rsa>::Rsa2048::load_public(65537, &n)
                .unwrap()
                .unwrap();

            // RSAPSS sign in A, verify in B
            let mut sig = [0u8; 256];
            <$A as Rsa>::Rsa2048::sign(
                &mut rng,
                &sk_a,
                RsaSigScheme::Rsapss,
                TpmtHa::Sha256(&digest),
                &mut sig,
            )
            .unwrap();
            assert!(
                <$B as Rsa>::Rsa2048::verify(
                    &pk_b,
                    RsaSigScheme::Rsapss,
                    TpmtHa::Sha256(&digest),
                    &sig,
                )
                .unwrap()
            );

            // OAEP encrypt in B, decrypt in A
            let mut ct = [0u8; 256];
            <$B as Rsa>::Rsa2048::encrypt(
                &mut rng,
                &pk_b,
                RsaEncryptScheme::Oaep {
                    hash: TpmiAlgHash::Sha256,
                    label: Some(c"INTEROP"),
                },
                b"secret payload",
                &mut ct,
            )
            .unwrap();
            let mut pt = [0u8; 256];
            let len = <$A as Rsa>::Rsa2048::decrypt(
                &mut rng,
                &sk_a,
                RsaEncryptScheme::Oaep {
                    hash: TpmiAlgHash::Sha256,
                    label: Some(c"INTEROP"),
                },
                &ct,
                &mut pt,
            )
            .unwrap()
            .unwrap();
            assert_eq!(&pt[..len], b"secret payload");
        }};
    }

    check_rsa_pair!(BoringSsl, OpensslBackend);
    check_rsa_pair!(OpensslBackend, BoringSsl);
    check_rsa_pair!(BoringSsl, RustCrypto);
    check_rsa_pair!(RustCrypto, BoringSsl);
}

#[test]
fn test_interop_mlkem1024_and_mldsa_all_modes() {
    let mut rng = BoringSsl::from_seed(b"boringssl-pqc-full-interop").unwrap();

    macro_rules! check_mlkem1024 {
        ($A:ty, $B:ty) => {{
            let a_priv =
                <<$A as Mlkem>::Mlkem1024 as AsymmetricKey<1568, 64>>::generate(&mut rng, ())
                    .unwrap();
            let a_pub = <<$A as Mlkem>::Mlkem1024 as AsymmetricKey<1568, 64>>::as_public(&a_priv);
            let mut pk_bytes = [0u8; 1568];
            <<$A as Mlkem>::Mlkem1024 as AsymmetricKey<1568, 64>>::store_public(
                a_pub,
                &mut pk_bytes,
            )
            .unwrap();
            let b_pub =
                <<$B as Mlkem>::Mlkem1024 as AsymmetricKey<1568, 64>>::load_public((), &pk_bytes)
                    .unwrap()
                    .unwrap();
            let mut ct = [0u8; 1568];
            let mut ss_b = [0u8; 32];
            <<$B as Mlkem>::Mlkem1024 as MlkemKey<1568, 1568>>::encapsulate(
                &mut rng, &b_pub, &mut ct, &mut ss_b,
            )
            .unwrap();
            let mut ss_a = [0u8; 32];
            <<$A as Mlkem>::Mlkem1024 as MlkemKey<1568, 1568>>::decapsulate(
                &a_priv, &ct, &mut ss_a,
            )
            .unwrap();
            assert_eq!(ss_a, ss_b);
        }};
    }

    check_mlkem1024!(BoringSsl, OpensslBackend);
    check_mlkem1024!(OpensslBackend, BoringSsl);
    check_mlkem1024!(BoringSsl, RustCrypto);
    check_mlkem1024!(RustCrypto, BoringSsl);

    // ML-DSA-44, ML-DSA-65, ML-DSA-87: pure, external-mu, and HashML-DSA
    let mu = [0x77u8; 64];
    let ph_sha256 = [0x88u8; 32];
    let digest = TpmtHa::Sha256(&ph_sha256);

    macro_rules! check_mldsa_all {
        ($A:ty, $B:ty, $Alg:ident, $PUB:literal, $SIG:literal) => {{
            #[inline(never)]
            fn run(rng: &mut BoringSslRng, mu: &[u8; 64], digest: TpmtHa<'_>) {
                let a_priv =
                    <<$A as Mldsa>::$Alg as AsymmetricKey<$PUB, 32>>::generate(rng, ()).unwrap();
                let a_pub = <<$A as Mldsa>::$Alg as AsymmetricKey<$PUB, 32>>::as_public(&a_priv);
                let mut pk_bytes = [0u8; $PUB];
                <<$A as Mldsa>::$Alg as AsymmetricKey<$PUB, 32>>::store_public(
                    a_pub,
                    &mut pk_bytes,
                )
                .unwrap();
                let b_pub =
                    <<$B as Mldsa>::$Alg as AsymmetricKey<$PUB, 32>>::load_public((), &pk_bytes)
                        .unwrap()
                        .unwrap();

                // Pure ML-DSA (multi-slice, empty & non-empty context)
                let mut sig = [0u8; $SIG];
                for ctx in [&b""[..], &b"interop-ctx"[..]] {
                    <<$A as Mldsa>::$Alg as MldsaKey<$PUB, $SIG>>::sign_message(
                        rng,
                        &a_priv,
                        ctx,
                        &[b"hello ", b"mldsa"],
                        &mut sig,
                    )
                    .unwrap();
                    assert!(
                        <<$B as Mldsa>::$Alg as MldsaKey<$PUB, $SIG>>::verify_message(
                            &b_pub,
                            ctx,
                            &[b"hello mldsa"],
                            &sig,
                        )
                        .unwrap()
                    );
                }

                // External-mu
                if <<$A as Mldsa>::$Alg as MldsaKey<$PUB, $SIG>>::sign_mu(
                    rng, &a_priv, mu, &mut sig,
                )
                .is_ok()
                {
                    match <<$B as Mldsa>::$Alg as MldsaKey<$PUB, $SIG>>::verify_mu(&b_pub, mu, &sig)
                    {
                        Ok(valid) => assert!(valid),
                        Err(tpm2::crypto::CryptoError::Unsupported) => {}
                        Err(e) => panic!("verify_mu error: {e:?}"),
                    }
                }

                // HashML-DSA (empty & non-empty context)
                for ctx in [&b""[..], &b"interop-ph-ctx"[..]] {
                    if <<$A as Mldsa>::$Alg as MldsaKey<$PUB, $SIG>>::sign_prehash(
                        rng, &a_priv, ctx, digest, &mut sig,
                    )
                    .is_ok()
                    {
                        match <<$B as Mldsa>::$Alg as MldsaKey<$PUB, $SIG>>::verify_prehash(
                            &b_pub, ctx, digest, &sig,
                        ) {
                            Ok(valid) => assert!(valid),
                            Err(tpm2::crypto::CryptoError::Unsupported) => {}
                            Err(e) => panic!("verify_prehash error: {e:?}"),
                        }
                    }
                }
            }
            run(&mut rng, &mu, digest);
        }};
    }

    check_mldsa_all!(BoringSsl, OpensslBackend, Mldsa44, 1312, 2420);
    check_mldsa_all!(OpensslBackend, BoringSsl, Mldsa44, 1312, 2420);
    check_mldsa_all!(BoringSsl, RustCrypto, Mldsa44, 1312, 2420);
    check_mldsa_all!(RustCrypto, BoringSsl, Mldsa44, 1312, 2420);

    check_mldsa_all!(BoringSsl, OpensslBackend, Mldsa65, 1952, 3309);
    check_mldsa_all!(OpensslBackend, BoringSsl, Mldsa65, 1952, 3309);
    check_mldsa_all!(BoringSsl, RustCrypto, Mldsa65, 1952, 3309);
    check_mldsa_all!(RustCrypto, BoringSsl, Mldsa65, 1952, 3309);

    check_mldsa_all!(BoringSsl, OpensslBackend, Mldsa87, 2592, 4627);
    check_mldsa_all!(OpensslBackend, BoringSsl, Mldsa87, 2592, 4627);
    check_mldsa_all!(BoringSsl, RustCrypto, Mldsa87, 2592, 4627);
    check_mldsa_all!(RustCrypto, BoringSsl, Mldsa87, 2592, 4627);
}

#[cfg(feature = "boringssl-non-fips")]
#[test]
fn test_interop_ed25519ph() {
    use tpm2::crypto::backend::EdwardsCurve;

    let mut rng = BoringSsl::from_seed(b"boringssl-ed25519ph-interop").unwrap();
    let prehash = [0x99u8; 64];

    macro_rules! check_ed25519ph {
        ($A:ty, $B:ty) => {{
            if let Ok(a_priv) =
                <<$A as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::generate(&mut rng, ())
            {
                let a_pub = <<$A as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::as_public(&a_priv);
                let mut pk_bytes = [0u8; 32];
                <<$A as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::store_public(a_pub, &mut pk_bytes)
                    .unwrap();
                if let Ok(Some(b_pub)) =
                    <<$B as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::load_public((), &pk_bytes)
                {
                    let mut r = [0u8; 32];
                    let mut s = [0u8; 32];
                    if <<$A as Ecc>::Ed25519 as EdwardsCurve<32>>::sign_prehash(
                        &a_priv, &prehash, &mut r, &mut s,
                    )
                    .is_ok()
                    {
                        match <<$B as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_prehash(
                            &b_pub, &prehash, &r, &s,
                        ) {
                            Ok(valid) => assert!(valid),
                            Err(tpm2::crypto::CryptoError::Unsupported) => {}
                            Err(e) => panic!("Ed25519ph verify error: {e:?}"),
                        }
                    }
                }
            }
        }};
    }

    check_ed25519ph!(BoringSsl, OpensslBackend);
    check_ed25519ph!(OpensslBackend, BoringSsl);
    check_ed25519ph!(BoringSsl, RustCrypto);
    check_ed25519ph!(RustCrypto, BoringSsl);
}
