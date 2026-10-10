//! Cross-backend agreement and interoperability tests.
//!
//! Each function takes two backends `(a, a_caps)` and `(b, b_caps)` and tests
//! every algorithm or parameter set supported by both, in both directions.

use tpm2::{
    Tpm2b, TpmiAlgHash, TpmiRsaKeyBits,
    crypto::{
        Ecc, EccPrivateKey, EccSigScheme, Mldsa, MldsaMessage, MldsaPrivateKey, Mlkem,
        MlkemPrivateKey, Rsa, RsaEncryptScheme, RsaPrivateKey, RsaSigScheme, Signing,
    },
};

use crate::{
    Caps, Check,
    ecc::{CURVES, ecdh, generate, load_point, load_private as ecc_load_private, point, scalar},
    mldsa::{
        derive as mldsa_derive, encoded as mldsa_encoded, load_public as mldsa_load_public,
        reference_mu, seed as mldsa_seed, sig_ctx, sign as mldsa_sign, verify as mldsa_verify,
    },
    mlkem::{
        decapsulate, derive as mlkem_derive, encapsulate, encoded as mlkem_encoded,
        load_public as mlkem_load_public, seed as mlkem_seed,
    },
    rsa::{
        bytes, decrypt, encrypt, load_fixed, load_private as rsa_load_private,
        load_public as rsa_load_public, modulus, prime, scheme_supported,
    },
    signing::{ecc_sign, ecc_verify, rsa_scheme_supported, rsa_sign, rsa_verify},
    util::{HASHES, MLDSA, MLKEM, RSA_KEY_BITS, assert_bytes, flip, pattern, seeded_rng, tpmt_ha},
};

/// Deriving an ML-KEM key from the same 64-byte `(d || z)` seed produces the
/// exact same encapsulation key on both backends, and exported keys load on
/// the other backend.
pub fn mlkem_keys_agree<A: Mlkem, B: Mlkem>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    let mut seed_bytes = [0u8; 64];
    seed_bytes.copy_from_slice(&pattern(64, 70));
    for &parms in MLKEM {
        if !a_caps.mlkem.contains(&parms) || !b_caps.mlkem.contains(&parms) {
            continue;
        }
        let ka = mlkem_derive(a, a_caps, parms, &seed_bytes).expect("supported on A");
        let kb = mlkem_derive(b, b_caps, parms, &seed_bytes).expect("supported on B");
        let ek_a = mlkem_encoded(ka.public_key());
        let ek_b = mlkem_encoded(kb.public_key());
        assert_bytes(
            &ek_a,
            &ek_b,
            format!("{parms:?} cross-backend encapsulation key"),
        );
        assert_bytes(
            &mlkem_seed(&ka),
            &mlkem_seed(&kb),
            format!("{parms:?} seed"),
        );

        let pub_on_b = mlkem_load_public(b, parms, &ek_a).expect("A public key rejected by B");
        let priv_on_b = Mlkem::load_private(b, pub_on_b, Tpm2b(&seed_bytes))
            .check("B load_private")
            .expect("A seed rejected by B");
        assert_bytes(
            &mlkem_encoded(priv_on_b.public_key()),
            &ek_a,
            format!("{parms:?} A -> B"),
        );

        let pub_on_a = mlkem_load_public(a, parms, &ek_b).expect("B public key rejected by A");
        let priv_on_a = Mlkem::load_private(a, pub_on_a, Tpm2b(&seed_bytes))
            .check("A load_private")
            .expect("B seed rejected by A");
        assert_bytes(
            &mlkem_encoded(priv_on_a.public_key()),
            &ek_b,
            format!("{parms:?} B -> A"),
        );
    }
}

fn mlkem_interop_one_way<A: Mlkem, B: Mlkem>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    let mut rng_a = seeded_rng(a, "mlkem_interop_a");
    let mut rng_b = seeded_rng(b, "mlkem_interop_b");
    for &parms in MLKEM {
        if !a_caps.mlkem.contains(&parms) || !b_caps.mlkem.contains(&parms) {
            continue;
        }
        let key_b = Mlkem::generate_key(b, &mut rng_b, parms).check("B generate_key");
        let ek_b = mlkem_encoded(key_b.public_key());
        let pub_on_a = mlkem_load_public(a, parms, &ek_b).expect("B public key rejected by A");
        let (ct, ss_a) = encapsulate(a, &mut rng_a, &pub_on_a);
        let ss_b = decapsulate(b, &key_b, &ct).expect("A ciphertext rejected by B");
        assert_bytes(
            &ss_b,
            &ss_a,
            format!("{parms:?} encaps -> decaps shared secret"),
        );
    }
}

/// ML-KEM ciphertexts encapsulated by one backend decapsulate to the same
/// shared secret on the other, in both directions.
pub fn mlkem_ciphertext_interop<A: Mlkem, B: Mlkem>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    mlkem_interop_one_way(a, a_caps, b, b_caps);
    mlkem_interop_one_way(b, b_caps, a, a_caps);
}

/// Deriving an ML-DSA key from the same 32-byte `ξ` seed produces the exact
/// same public key on both backends, and exported keys load on the other
/// backend.
pub fn mldsa_keys_agree<A: Mldsa, B: Mldsa>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&pattern(32, 71));
    for &parms in MLDSA {
        if !a_caps.mldsa.contains(&parms) || !b_caps.mldsa.contains(&parms) {
            continue;
        }
        let ka = mldsa_derive(a, a_caps, parms, &seed_bytes).expect("supported on A");
        let kb = mldsa_derive(b, b_caps, parms, &seed_bytes).expect("supported on B");
        let pk_a = mldsa_encoded(ka.public_key());
        let pk_b = mldsa_encoded(kb.public_key());
        assert_bytes(&pk_a, &pk_b, format!("{parms:?} cross-backend public key"));
        assert_bytes(
            &mldsa_seed(&ka),
            &mldsa_seed(&kb),
            format!("{parms:?} seed"),
        );

        let pub_on_b = mldsa_load_public(b, parms, &pk_a).expect("A public key rejected by B");
        let priv_on_b = Mldsa::load_private(b, pub_on_b, Tpm2b(&seed_bytes))
            .check("B load_private")
            .expect("A seed rejected by B");
        assert_bytes(
            &mldsa_encoded(priv_on_b.public_key()),
            &pk_a,
            format!("{parms:?} A -> B"),
        );

        let pub_on_a = mldsa_load_public(a, parms, &pk_b).expect("B public key rejected by A");
        let priv_on_a = Mldsa::load_private(a, pub_on_a, Tpm2b(&seed_bytes))
            .check("A load_private")
            .expect("B seed rejected by A");
        assert_bytes(
            &mldsa_encoded(priv_on_a.public_key()),
            &pk_b,
            format!("{parms:?} B -> A"),
        );
    }
}

fn mldsa_interop_one_way<A: Mldsa, B: Mldsa>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    let mut rng_a = seeded_rng(a, "mldsa_interop_a");
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&pattern(32, 72));
    for &parms in MLDSA {
        if !a_caps.mldsa.contains(&parms) || !b_caps.mldsa.contains(&parms) {
            continue;
        }
        let key_a = mldsa_derive(a, a_caps, parms, &seed_bytes).expect("supported on A");
        let pk_bytes = mldsa_encoded(key_a.public_key());
        let pub_b = mldsa_load_public(b, parms, &pk_bytes).expect("A public key rejected by B");

        // Pure ML-DSA with empty and non-empty context.
        for ctx in [&b""[..], b"cross-backend context"] {
            let msg = b"cross-backend ML-DSA message";
            let pure = MldsaMessage::Pure {
                context: sig_ctx(ctx),
                message: msg,
            };
            let sig = mldsa_sign(a, &mut rng_a, &key_a, pure).check("A sign Pure");
            assert!(
                mldsa_verify(b, &pub_b, pure, &sig).check("B verify Pure"),
                "{parms:?}: Pure signature from A rejected by B"
            );
            assert!(
                !mldsa_verify(b, &pub_b, pure, &flip(&sig, 0)).check("B verify tampered"),
                "{parms:?}: tampered Pure signature accepted by B"
            );

            // ExternalMu <-> Pure cross-verification when supported.
            let mu = reference_mu(&pk_bytes, 0, ctx, &[msg]);
            if a_caps.mldsa_external_mu {
                let mu_sig = mldsa_sign(a, &mut rng_a, &key_a, MldsaMessage::ExternalMu(&mu))
                    .check("A sign ExternalMu");
                assert!(
                    mldsa_verify(b, &pub_b, pure, &mu_sig).check("B verify Pure"),
                    "{parms:?}: ExternalMu signature from A rejected by B Pure verify"
                );
            }
            if b_caps.mldsa_external_mu {
                assert!(
                    mldsa_verify(b, &pub_b, MldsaMessage::ExternalMu(&mu), &sig)
                        .check("B verify ExternalMu"),
                    "{parms:?}: Pure signature from A rejected by B ExternalMu verify"
                );
            }
        }

        // HashML-DSA across all jointly supported pre-hash algorithms.
        for &hash in HASHES {
            if !a_caps.mldsa_pre_hash.contains(&hash) || !b_caps.mldsa_pre_hash.contains(&hash) {
                continue;
            }
            let digest = pattern(hash.digest_size(), 73);
            let pre_hash = MldsaMessage::PreHash {
                context: sig_ctx(b"cross pre-hash"),
                digest: tpmt_ha(hash, &digest),
            };
            let sig = mldsa_sign(a, &mut rng_a, &key_a, pre_hash).check("A sign PreHash");
            assert!(
                mldsa_verify(b, &pub_b, pre_hash, &sig).check("B verify PreHash"),
                "{parms:?} {hash:?}: PreHash signature from A rejected by B"
            );
        }
    }
}

/// ML-DSA signatures (Pure, PreHash, and ExternalMu) produced by one backend
/// verify on the other, in both directions.
pub fn mldsa_signature_interop<A: Mldsa, B: Mldsa>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    mldsa_interop_one_way(a, a_caps, b, b_caps);
    mldsa_interop_one_way(b, b_caps, a, a_caps);
}

/// ECDH key exchange and key import/export agree across both backends on every
/// jointly supported curve.
pub fn ecdh_interop<A: Ecc, B: Ecc>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    let mut rng_a = seeded_rng(a, "ecdh_interop_a");
    let mut rng_b = seeded_rng(b, "ecdh_interop_b");
    for &curve in CURVES {
        if !a_caps.curves.contains(&curve) || !b_caps.curves.contains(&curve) {
            continue;
        }
        let ka = generate(a, a_caps, &mut rng_a, curve).expect("supported on A");
        let kb = generate(b, b_caps, &mut rng_b, curve).expect("supported on B");
        let (xa, ya) = point(ka.public_key());
        let (xb, yb) = point(kb.public_key());

        let pub_b_on_a = load_point(a, curve, &xb, &yb).expect("B point rejected by A");
        let pub_a_on_b = load_point(b, curve, &xa, &ya).expect("A point rejected by B");

        let z_a = ecdh(a, &ka, &pub_b_on_a);
        let z_b = ecdh(b, &kb, &pub_a_on_b);
        assert_eq!(z_a, z_b, "{curve:?}: cross-backend ECDH mismatch");

        // Importing A's private scalar into B (and B's into A) reproduces the
        // public key and shared point.
        let ka_on_b =
            ecc_load_private(b, pub_a_on_b, &scalar(&ka)).expect("A scalar rejected by B");
        assert_eq!(
            ecdh(b, &ka_on_b, kb.public_key()),
            z_a,
            "{curve:?}: imported A key ECDH"
        );
        let kb_on_a =
            ecc_load_private(a, pub_b_on_a, &scalar(&kb)).expect("B scalar rejected by A");
        assert_eq!(
            ecdh(a, &kb_on_a, ka.public_key()),
            z_b,
            "{curve:?}: imported B key ECDH"
        );
    }
}

fn ecc_sig_interop_one_way<A: Signing, B: Signing>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    let mut rng_a = seeded_rng(a, "ecc_sig_interop_a");
    for &curve in CURVES {
        if !a_caps.curves.contains(&curve) || !b_caps.curves.contains(&curve) {
            continue;
        }
        let key_a = generate(a, a_caps, &mut rng_a, curve).expect("supported on A");
        let (x, y) = point(key_a.public_key());
        let pub_b = load_point(b, curve, &x, &y).expect("A point rejected by B");

        for &hash in HASHES {
            if !a_caps.ecdsa.contains(&hash) || !b_caps.ecdsa.contains(&hash) {
                continue;
            }
            let digest = pattern(hash.digest_size(), 74);
            let (r, s) =
                ecc_sign(a, &mut rng_a, &key_a, EccSigScheme::Ecdsa, hash, &digest).check("A sign");
            assert!(
                ecc_verify(b, &pub_b, EccSigScheme::Ecdsa, hash, &digest, &r, &s).check("B verify"),
                "{curve:?} ECDSA {hash:?}: A signature rejected by B"
            );
            assert!(
                !ecc_verify(
                    b,
                    &pub_b,
                    EccSigScheme::Ecdsa,
                    hash,
                    &digest,
                    &flip(&r, r.len() - 1),
                    &s,
                )
                .check("B verify tampered"),
                "{curve:?} ECDSA {hash:?}: tampered signature accepted by B"
            );
        }

        if a_caps.sm2 && b_caps.sm2 {
            let digest = pattern(32, 75);
            let (r, s) = ecc_sign(
                a,
                &mut rng_a,
                &key_a,
                EccSigScheme::Sm2,
                TpmiAlgHash::Sha256,
                &digest,
            )
            .check("A sign SM2");
            assert!(
                ecc_verify(
                    b,
                    &pub_b,
                    EccSigScheme::Sm2,
                    TpmiAlgHash::Sha256,
                    &digest,
                    &r,
                    &s,
                )
                .check("B verify SM2"),
                "{curve:?} SM2: A signature rejected by B"
            );
        }

        if a_caps.ecschnorr
            && b_caps.ecschnorr
            && a_caps.hash.contains(&TpmiAlgHash::Sha256)
            && b_caps.hash.contains(&TpmiAlgHash::Sha256)
        {
            let digest = pattern(32, 76);
            let (r, s) = ecc_sign(
                a,
                &mut rng_a,
                &key_a,
                EccSigScheme::Ecschnorr,
                TpmiAlgHash::Sha256,
                &digest,
            )
            .check("A sign ECSchnorr");
            assert!(
                ecc_verify(
                    b,
                    &pub_b,
                    EccSigScheme::Ecschnorr,
                    TpmiAlgHash::Sha256,
                    &digest,
                    &r,
                    &s,
                )
                .check("B verify ECSchnorr"),
                "{curve:?} ECSchnorr: A signature rejected by B"
            );
        }
    }
}

/// ECC signatures (ECDSA, SM2, and EC-Schnorr) produced by one backend verify
/// on the other, in both directions.
pub fn ecdsa_interop<A: Signing, B: Signing>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    ecc_sig_interop_one_way(a, a_caps, b, b_caps);
    ecc_sig_interop_one_way(b, b_caps, a, a_caps);
}

fn rsa_sig_interop_one_way<A: Signing, B: Signing>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    let mut rng_a = seeded_rng(a, "rsa_sig_interop_a");
    let mut rng_b = seeded_rng(b, "rsa_sig_interop_b");
    for &bits in RSA_KEY_BITS {
        if !a_caps.rsa.contains(&bits) || !b_caps.rsa.contains(&bits) {
            continue;
        }
        let key_a = load_fixed(a, a_caps, bits).expect("supported on A");
        let key_b = load_fixed(b, b_caps, bits).expect("supported on B");

        for scheme in [RsaSigScheme::Rsassa, RsaSigScheme::Rsapss] {
            for &hash in HASHES {
                if bits != TpmiRsaKeyBits::Rsa2048
                    && hash != TpmiAlgHash::Sha256
                    && !(bits == TpmiRsaKeyBits::Rsa1024 && hash == TpmiAlgHash::Sha512)
                {
                    continue;
                }
                if !rsa_scheme_supported(a_caps, scheme, hash)
                    || !rsa_scheme_supported(b_caps, scheme, hash)
                {
                    continue;
                }
                let what = format!("RSA-{} {scheme:?} {hash:?}", bits.as_u16());
                let digest = pattern(hash.digest_size(), 77);
                let sig_a = rsa_sign(a, &mut rng_a, &key_a, scheme, hash, &digest).check(&what);
                if scheme == RsaSigScheme::Rsassa {
                    let sig_b = rsa_sign(b, &mut rng_b, &key_b, scheme, hash, &digest).check(&what);
                    assert_bytes(&sig_a, &sig_b, &what);
                }
                assert!(
                    rsa_verify(b, key_b.public_key(), scheme, hash, &digest, &sig_a).check(&what),
                    "{what}: A signature rejected by B"
                );
                assert!(
                    !rsa_verify(
                        b,
                        key_b.public_key(),
                        scheme,
                        hash,
                        &digest,
                        &flip(&sig_a, sig_a.len() - 1),
                    )
                    .check(&what),
                    "{what}: tampered signature accepted by B"
                );
            }
        }
    }

    // Also check that a key generated on A exports its modulus and prime `p`
    // in a form that B can load and use.
    if a_caps.rsa.contains(&TpmiRsaKeyBits::Rsa1024)
        && b_caps.rsa.contains(&TpmiRsaKeyBits::Rsa1024)
    {
        let gen_a = Rsa::generate_key(a, &mut rng_a, TpmiRsaKeyBits::Rsa1024, 0)
            .check("A generate RSA-1024");
        let n = modulus(gen_a.public_key());
        let p = prime(&gen_a);
        let pub_b =
            rsa_load_public(b, TpmiRsaKeyBits::Rsa1024, 0, &n).expect("A modulus rejected by B");
        let priv_b = rsa_load_private(b, pub_b, &p).expect("A prime rejected by B");
        if rsa_scheme_supported(a_caps, RsaSigScheme::Rsapss, TpmiAlgHash::Sha256)
            && rsa_scheme_supported(b_caps, RsaSigScheme::Rsapss, TpmiAlgHash::Sha256)
        {
            let digest = [0x42u8; 32];
            let sig = rsa_sign(
                a,
                &mut rng_a,
                &gen_a,
                RsaSigScheme::Rsapss,
                TpmiAlgHash::Sha256,
                &digest,
            )
            .check("A sign");
            assert!(
                rsa_verify(
                    b,
                    priv_b.public_key(),
                    RsaSigScheme::Rsapss,
                    TpmiAlgHash::Sha256,
                    &digest,
                    &sig,
                )
                .check("B verify"),
                "generated RSA-1024 signature rejected by B"
            );
        }
    }
}

/// RSA signatures (RSASSA-PKCS1-v1_5 and RSASSA-PSS) produced by one backend
/// verify on the other, in both directions.
pub fn rsa_signature_interop<A: Signing, B: Signing>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    rsa_sig_interop_one_way(a, a_caps, b, b_caps);
    rsa_sig_interop_one_way(b, b_caps, a, a_caps);
}

fn rsa_enc_interop_one_way<A: Rsa, B: Rsa>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    let mut rng_a = seeded_rng(a, "rsa_enc_interop_a");
    for &bits in RSA_KEY_BITS {
        if !a_caps.rsa.contains(&bits) || !b_caps.rsa.contains(&bits) {
            continue;
        }
        let key_a = load_fixed(a, a_caps, bits).expect("supported on A");
        let key_b = load_fixed(b, b_caps, bits).expect("supported on B");
        let k = bytes(bits);

        let mut schemes = vec![RsaEncryptScheme::Raw, RsaEncryptScheme::Rsaes];
        for &hash in HASHES {
            if bits == TpmiRsaKeyBits::Rsa2048 || hash == TpmiAlgHash::Sha256 {
                schemes.push(RsaEncryptScheme::Oaep { hash, label: b"" });
            }
        }
        schemes.push(RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha256,
            label: b"DUPLICATE\0",
        });

        for scheme in schemes {
            if !scheme_supported(a_caps, scheme) || !scheme_supported(b_caps, scheme) {
                continue;
            }
            if let RsaEncryptScheme::Oaep { hash, .. } = scheme
                && k < 2 * hash.digest_size() + 2
            {
                continue;
            }
            let what = format!("RSA-{} {scheme:?}", bits.as_u16());
            let msg = match scheme {
                RsaEncryptScheme::Raw => [&[0u8][..], &pattern(k - 1, 78)].concat(),
                _ => b"cross-backend RSA plaintext".to_vec(),
            };
            let ct = encrypt(a, &mut rng_a, key_a.public_key(), scheme, &msg)
                .check(&what)
                .expect("valid plaintext rejected by A");
            let pt = decrypt(b, &key_b, scheme, &ct)
                .check(&what)
                .expect("A ciphertext rejected by B");
            assert_bytes(&pt, &msg, &what);
        }
    }
}

/// RSA ciphertexts (raw, RSAES-PKCS1-v1_5, and OAEP) encrypted by one backend
/// decrypt to the original plaintext on the other, in both directions.
pub fn rsa_encryption_interop<A: Rsa, B: Rsa>(a: &A, a_caps: &Caps, b: &B, b_caps: &Caps) {
    rsa_enc_interop_one_way(a, a_caps, b, b_caps);
    rsa_enc_interop_one_way(b, b_caps, a, a_caps);
}
