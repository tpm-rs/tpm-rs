//! Tests for [`Signing`] and the [`sign`] and [`verify`] wrappers.

use tpm2::{
    Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmEccCurve, TpmiAlgHash, TpmiRsaKeyBits,
    TpmsSchemeEcdaa, TpmsSignatureEcc, TpmsSignatureRsa, TpmtSigScheme, TpmtSignature,
    crypto::{
        CryptoError, Ecc, EccPrivateKey, EccSigScheme, Rsa, RsaPrivateKey, RsaSigScheme,
        SignatureBuffer, Signing, SigningKey, VerifyingKey, hmac, sign, verify,
    },
};

use crate::{
    Caps, Check,
    ecc::{CURVES, generate, load_point},
    expect_support,
    rsa::{bytes, fixed_key, load_fixed},
    util::{
        HASHES, RSA_KEY_BITS, assert_bytes, flip, pattern, same_size_hash, seeded_rng, tpmt_ha,
    },
    vectors::{ecc as ecc_kat, hash as hash_kat, rsa as rsa_kat},
};

/// Signs `digest` with an RSA private key.
pub(crate) fn rsa_sign<C: Signing>(
    c: &C,
    rng: &mut C::Rng,
    key: &<C as Rsa>::PrivateKey,
    scheme: RsaSigScheme,
    hash: TpmiAlgHash,
    digest: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig = c.rsa_sign(rng, key, scheme, tpmt_ha(hash, digest), &mut out)?;
    Ok(sig.as_slice().to_vec())
}

/// Verifies an RSA signature over `digest`.
pub(crate) fn rsa_verify<C: Signing>(
    c: &C,
    key: &<C as Rsa>::PublicKey,
    scheme: RsaSigScheme,
    hash: TpmiAlgHash,
    digest: &[u8],
    sig: &[u8],
) -> Result<bool, CryptoError> {
    c.rsa_verify(key, scheme, tpmt_ha(hash, digest), sig)
}

/// Signs `digest` with an ECC private key.
pub(crate) fn ecc_sign<C: Signing>(
    c: &C,
    rng: &mut C::Rng,
    key: &<C as Ecc>::PrivateKey,
    scheme: EccSigScheme,
    hash: TpmiAlgHash,
    digest: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut out_r = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut out_s = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let (r, s) = c.ecc_sign(
        rng,
        key,
        scheme,
        tpmt_ha(hash, digest),
        &mut out_r,
        &mut out_s,
    )?;
    Ok((r.as_slice().to_vec(), s.as_slice().to_vec()))
}

/// Verifies an ECC `(r, s)` signature over `digest`.
pub(crate) fn ecc_verify<C: Signing>(
    c: &C,
    key: &<C as Ecc>::PublicKey,
    scheme: EccSigScheme,
    hash: TpmiAlgHash,
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<bool, CryptoError> {
    c.ecc_verify(key, scheme, tpmt_ha(hash, digest), r, s)
}

/// Builds a [`TpmsSignatureEcc`] from `r` and `s` slices.
fn tpms_sig_ecc<'a>(hash: TpmiAlgHash, r: &'a [u8], s: &'a [u8]) -> TpmsSignatureEcc<'a> {
    TpmsSignatureEcc {
        hash,
        signature_r: Tpm2bEccParameter::new(r).expect("r too long"),
        signature_s: Tpm2bEccParameter::new(s).expect("s too long"),
    }
}

/// Builds a [`TpmsSignatureRsa`] from a signature slice.
fn tpms_sig_rsa(hash: TpmiAlgHash, sig: &[u8]) -> TpmsSignatureRsa<'_> {
    TpmsSignatureRsa {
        hash,
        sig: Tpm2bPublicKeyRsa::new(sig).expect("RSA signature too long"),
    }
}

/// Returns whether `scheme` with `hash` is expected to be supported.
pub(crate) fn rsa_scheme_supported(caps: &Caps, scheme: RsaSigScheme, hash: TpmiAlgHash) -> bool {
    match scheme {
        RsaSigScheme::Rsassa => caps.rsassa.contains(&hash),
        RsaSigScheme::Rsapss => caps.rsapss.contains(&hash),
    }
}

/// Deterministic RSASSA-PKCS1-v1_5 SHA-256 known answers for every RSA key
/// size.
pub fn rsassa_kat<C: Signing>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "rsassa_kat");
    let digest = hash_kat::SHA256[1].1;
    let cases: [(TpmiRsaKeyBits, &[u8]); 4] = [
        (TpmiRsaKeyBits::Rsa1024, &rsa_kat::RSASSA_SHA256_1024),
        (TpmiRsaKeyBits::Rsa2048, &rsa_kat::RSASSA_SHA256_2048),
        (TpmiRsaKeyBits::Rsa3072, &rsa_kat::RSASSA_SHA256_3072),
        (TpmiRsaKeyBits::Rsa4096, &rsa_kat::RSASSA_SHA256_4096),
    ];
    let supported = caps.rsassa.contains(&TpmiAlgHash::Sha256);
    for (bits, expected) in cases {
        let Some(key) = load_fixed(c, caps, bits) else {
            continue;
        };
        let what = format!("RSA-{} RSASSA SHA-256", bits.as_u16());
        let result = rsa_sign(
            c,
            &mut rng,
            &key,
            RsaSigScheme::Rsassa,
            TpmiAlgHash::Sha256,
            digest,
        );
        let Some(sig) = expect_support(supported, &what, result) else {
            let verify_res = rsa_verify(
                c,
                key.public_key(),
                RsaSigScheme::Rsassa,
                TpmiAlgHash::Sha256,
                digest,
                expected,
            );
            expect_support(false, &what, verify_res);
            continue;
        };
        assert_bytes(&sig, expected, &what);
        let valid = rsa_verify(
            c,
            key.public_key(),
            RsaSigScheme::Rsassa,
            TpmiAlgHash::Sha256,
            digest,
            expected,
        )
        .check(&what);
        assert!(valid, "{what}: valid signature rejected");
    }
}

/// RSASSA-PSS SHA-256 verification known answer on the 2048-bit fixed key.
pub fn rsapss_verify_kat<C: Signing>(c: &C, caps: &Caps) {
    let Some(key) = load_fixed(c, caps, TpmiRsaKeyBits::Rsa2048) else {
        return;
    };
    let digest = hash_kat::SHA256[1].1;
    let supported = caps.rsapss.contains(&TpmiAlgHash::Sha256);
    let result = rsa_verify(
        c,
        key.public_key(),
        RsaSigScheme::Rsapss,
        TpmiAlgHash::Sha256,
        digest,
        &rsa_kat::RSAPSS_SHA256_2048,
    );
    let Some(valid) = expect_support(supported, "RSAPSS SHA-256", result) else {
        return;
    };
    assert!(valid, "RSAPSS SHA-256: valid KAT signature rejected");

    let wrapped = TpmtSignature::Rsapss(tpms_sig_rsa(
        TpmiAlgHash::Sha256,
        &rsa_kat::RSAPSS_SHA256_2048,
    ));
    assert!(
        verify(c, VerifyingKey::Rsa(key.public_key()), digest, wrapped).check("verify RSAPSS"),
        "verify RSAPSS KAT failed"
    );

    let corrupted = flip(&rsa_kat::RSAPSS_SHA256_2048, 128);
    assert!(
        !rsa_verify(
            c,
            key.public_key(),
            RsaSigScheme::Rsapss,
            TpmiAlgHash::Sha256,
            digest,
            &corrupted,
        )
        .check("RSAPSS corrupted"),
        "RSAPSS corrupted signature accepted"
    );
}

/// RSASSA and RSAPSS signing and verification across every hash algorithm on
/// the 2048-bit key, including negative checks (tampered signature/digest,
/// wrong scheme, wrong hash OID, and out-of-range signatures).
pub fn rsa_sign_verify<C: Signing>(c: &C, caps: &Caps) {
    let Some(key) = load_fixed(c, caps, TpmiRsaKeyBits::Rsa2048) else {
        return;
    };
    let mut rng = seeded_rng(c, "rsa_sign_verify");
    let (n, _) = fixed_key(TpmiRsaKeyBits::Rsa2048);
    let k = n.len();

    for scheme in [RsaSigScheme::Rsassa, RsaSigScheme::Rsapss] {
        for &hash in HASHES {
            let what = format!("{scheme:?} {hash:?}");
            let supported = rsa_scheme_supported(caps, scheme, hash);
            let digest = pattern(hash.digest_size(), 20);
            let tpmt_scheme = match scheme {
                RsaSigScheme::Rsassa => TpmtSigScheme::Rsassa(hash),
                RsaSigScheme::Rsapss => TpmtSigScheme::Rsapss(hash),
            };
            let mut buf: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
            let result = sign(
                c,
                &mut rng,
                SigningKey::Rsa(&key),
                tpmt_scheme,
                &digest,
                &mut buf,
            );
            let Some(tpmt_sig) = expect_support(supported, &what, result) else {
                let verify_res =
                    rsa_verify(c, key.public_key(), scheme, hash, &digest, &vec![0u8; k]);
                expect_support(false, &what, verify_res);
                continue;
            };
            let sig_bytes = match (scheme, tpmt_sig) {
                (RsaSigScheme::Rsassa, TpmtSignature::Rsassa(s)) => {
                    assert_eq!(s.hash, hash);
                    s.sig.as_slice().to_vec()
                }
                (RsaSigScheme::Rsapss, TpmtSignature::Rsapss(s)) => {
                    assert_eq!(s.hash, hash);
                    s.sig.as_slice().to_vec()
                }
                _ => panic!("{what}: unexpected TpmtSignature variant"),
            };
            assert_eq!(sig_bytes.len(), k, "{what}: signature length");
            assert!(
                verify(c, VerifyingKey::Rsa(key.public_key()), &digest, tpmt_sig).check(&what),
                "{what}: valid signature rejected"
            );

            // Determinism / randomization.
            let sig2 = rsa_sign(c, &mut rng, &key, scheme, hash, &digest).check(&what);
            match scheme {
                RsaSigScheme::Rsassa => {
                    assert_bytes(&sig2, &sig_bytes, format!("{what} determinism"))
                }
                RsaSigScheme::Rsapss => {
                    assert_ne!(sig2, sig_bytes, "{what}: PSS signing isn't randomized");
                    assert!(
                        rsa_verify(c, key.public_key(), scheme, hash, &digest, &sig2).check(&what),
                        "{what}: second PSS signature rejected"
                    );
                }
            }

            // Tampered signature and tampered digest.
            let bad_sig = flip(&sig_bytes, k / 2);
            assert!(
                !rsa_verify(c, key.public_key(), scheme, hash, &digest, &bad_sig).check(&what),
                "{what}: corrupted signature accepted"
            );
            let bad_digest = flip(&digest, 0);
            assert!(
                !rsa_verify(c, key.public_key(), scheme, hash, &bad_digest, &sig_bytes)
                    .check(&what),
                "{what}: signature accepted for modified digest"
            );

            // Wrong scheme.
            let other_scheme = match scheme {
                RsaSigScheme::Rsassa => RsaSigScheme::Rsapss,
                RsaSigScheme::Rsapss => RsaSigScheme::Rsassa,
            };
            if rsa_scheme_supported(caps, other_scheme, hash) {
                assert!(
                    !rsa_verify(c, key.public_key(), other_scheme, hash, &digest, &sig_bytes)
                        .check(&what),
                    "{what}: signature accepted under {other_scheme:?}"
                );
            }

            // Same-size hash algorithm (different DigestInfo OID for RSASSA).
            if scheme == RsaSigScheme::Rsassa
                && let Some(other_hash) = same_size_hash(hash)
                && caps.rsassa.contains(&other_hash)
            {
                assert!(
                    !rsa_verify(c, key.public_key(), scheme, other_hash, &digest, &sig_bytes)
                        .check(&what),
                    "{what}: RSASSA signature accepted under {other_hash:?}"
                );
            }

            // Malformed / out-of-range signature representations.
            for bad in [&[][..], &sig_bytes[1..], n, &vec![0xFF; k]] {
                assert!(
                    !rsa_verify(c, key.public_key(), scheme, hash, &digest, bad).check(&what),
                    "{what}: invalid signature representation accepted"
                );
            }

            // Wrong-length digest in the `sign` and `verify` wrappers.
            let mut scratch: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
            assert_eq!(
                sign(
                    c,
                    &mut rng,
                    SigningKey::Rsa(&key),
                    tpmt_scheme,
                    &digest[1..],
                    &mut scratch,
                ),
                Err(CryptoError::Unsupported),
            );
            assert!(
                !verify(
                    c,
                    VerifyingKey::Rsa(key.public_key()),
                    &digest[1..],
                    tpmt_sig
                )
                .check(&what),
                "{what}: wrong-length digest accepted by verify"
            );
        }
    }
}

/// RSASSA and RSAPSS round-trip across all RSA key sizes (including 1024-bit
/// RSA-PSS with SHA-512, where the salt is clamped to fit).
pub fn rsa_sign_verify_all_sizes<C: Signing>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "rsa_sign_verify_all_sizes");
    for &bits in RSA_KEY_BITS {
        let Some(key) = load_fixed(c, caps, bits) else {
            continue;
        };
        let k = bytes(bits);
        for scheme in [RsaSigScheme::Rsassa, RsaSigScheme::Rsapss] {
            for hash in [TpmiAlgHash::Sha256, TpmiAlgHash::Sha512] {
                if bits != TpmiRsaKeyBits::Rsa1024 && hash == TpmiAlgHash::Sha512 {
                    continue;
                }
                let what = format!("RSA-{} {scheme:?} {hash:?}", bits.as_u16());
                let supported = rsa_scheme_supported(caps, scheme, hash);
                let digest = pattern(hash.digest_size(), 21);
                let result = rsa_sign(c, &mut rng, &key, scheme, hash, &digest);
                let Some(sig) = expect_support(supported, &what, result) else {
                    continue;
                };
                assert_eq!(sig.len(), k);
                assert!(
                    rsa_verify(c, key.public_key(), scheme, hash, &digest, &sig).check(&what),
                    "{what}: valid signature rejected"
                );
                assert!(
                    !rsa_verify(
                        c,
                        key.public_key(),
                        scheme,
                        hash,
                        &digest,
                        &flip(&sig, k - 1)
                    )
                    .check(&what),
                    "{what}: corrupted signature accepted"
                );
            }
        }
    }
}

/// ECDSA verification known answers (RFC 6979 for P-256, pyca/cryptography for
/// P-384 and P-521).
pub fn ecdsa_verify_kat<C: Signing>(c: &C, caps: &Caps) {
    for v in ecc_kat::ECDSA {
        if !caps.curves.contains(&v.curve) {
            continue;
        }
        let public = load_point(c, v.curve, v.q.0, v.q.1).expect("valid KAT point rejected");
        let what = format!("{:?} ECDSA {:?}", v.curve, v.hash);
        let supported = caps.ecdsa.contains(&v.hash);
        let result = ecc_verify(
            c,
            &public,
            EccSigScheme::Ecdsa,
            v.hash,
            v.digest,
            v.sig.0,
            v.sig.1,
        );
        let Some(valid) = expect_support(supported, &what, result) else {
            continue;
        };
        assert!(valid, "{what}: valid KAT signature rejected");

        let tpmt_sig = TpmtSignature::Ecdsa(tpms_sig_ecc(v.hash, v.sig.0, v.sig.1));
        assert!(
            verify(c, VerifyingKey::Ecc(&public), v.digest, tpmt_sig).check(&what),
            "{what}: verify wrapper rejected valid KAT signature"
        );

        // Unpadded or zero-padded r and s (within MAX_ECC_KEY_BYTES) are accepted,
        // and any bit flip is rejected.
        let r_flipped = flip(v.sig.0, v.sig.0.len() - 1);
        assert!(
            !ecc_verify(
                c,
                &public,
                EccSigScheme::Ecdsa,
                v.hash,
                v.digest,
                &r_flipped,
                v.sig.1,
            )
            .check(&what),
            "{what}: corrupted r accepted"
        );
        let s_flipped = flip(v.sig.1, v.sig.1.len() - 1);
        assert!(
            !ecc_verify(
                c,
                &public,
                EccSigScheme::Ecdsa,
                v.hash,
                v.digest,
                v.sig.0,
                &s_flipped,
            )
            .check(&what),
            "{what}: corrupted s accepted"
        );
        let digest_flipped = flip(v.digest, 0);
        assert!(
            !ecc_verify(
                c,
                &public,
                EccSigScheme::Ecdsa,
                v.hash,
                &digest_flipped,
                v.sig.0,
                v.sig.1,
            )
            .check(&what),
            "{what}: corrupted digest accepted"
        );
    }
}

/// Checks an ECC signature scheme across all curves and hashes.
fn check_ecc_scheme<C: Signing>(
    c: &C,
    caps: &Caps,
    scheme: EccSigScheme,
    scheme_supported: fn(&Caps, TpmiAlgHash) -> bool,
) {
    let mut rng = seeded_rng(c, "check_ecc_scheme");
    for &curve in CURVES {
        let Some(key) = generate(c, caps, &mut rng, curve) else {
            continue;
        };
        let other = generate(c, caps, &mut rng, curve).expect("second key");
        let size = curve.key_bytes();

        for &hash in HASHES {
            let what = format!("{curve:?} {scheme:?} {hash:?}");
            let supported = scheme_supported(caps, hash);
            let digest = pattern(hash.digest_size(), 30);
            let tpmt_scheme = match scheme {
                EccSigScheme::Ecdsa => TpmtSigScheme::Ecdsa(hash),
                EccSigScheme::Sm2 => TpmtSigScheme::Sm2(hash),
                EccSigScheme::Ecschnorr => TpmtSigScheme::Ecschnorr(hash),
                EccSigScheme::Ecdaa(count) => TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: hash,
                    count,
                }),
            };
            let mut buf: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
            let result = sign(
                c,
                &mut rng,
                SigningKey::Ecc(&key),
                tpmt_scheme,
                &digest,
                &mut buf,
            );
            let Some(tpmt_sig) = expect_support(supported, &what, result) else {
                let verify_res = ecc_verify(
                    c,
                    key.public_key(),
                    scheme,
                    hash,
                    &digest,
                    &vec![1u8; size],
                    &vec![1u8; size],
                );
                expect_support(false, &what, verify_res);
                continue;
            };
            let (r, s) = match (scheme, tpmt_sig) {
                (EccSigScheme::Ecdsa, TpmtSignature::Ecdsa(sig))
                | (EccSigScheme::Sm2, TpmtSignature::Sm2(sig))
                | (EccSigScheme::Ecschnorr, TpmtSignature::Ecschnorr(sig)) => {
                    assert_eq!(sig.hash, hash);
                    (
                        sig.signature_r.as_slice().to_vec(),
                        sig.signature_s.as_slice().to_vec(),
                    )
                }
                _ => panic!("{what}: unexpected TpmtSignature variant"),
            };
            assert!(
                !r.is_empty() && r.len() <= size,
                "{what}: r size {}",
                r.len()
            );
            assert!(
                !s.is_empty() && s.len() <= size,
                "{what}: s size {}",
                s.len()
            );
            assert!(
                verify(c, VerifyingKey::Ecc(key.public_key()), &digest, tpmt_sig).check(&what),
                "{what}: valid signature rejected"
            );

            // Signing is randomized.
            let (r2, s2) = ecc_sign(c, &mut rng, &key, scheme, hash, &digest).check(&what);
            assert_ne!((&r2, &s2), (&r, &s), "{what}: signing isn't randomized");
            assert!(
                ecc_verify(c, key.public_key(), scheme, hash, &digest, &r2, &s2).check(&what),
                "{what}: second signature rejected"
            );

            // Negative checks on SHA-256 (or the first supported hash) to keep runtime fast.
            if hash == TpmiAlgHash::Sha256 {
                let bad_r = flip(&r, r.len() - 1);
                assert!(
                    !ecc_verify(c, key.public_key(), scheme, hash, &digest, &bad_r, &s)
                        .check(&what),
                    "{what}: corrupted r accepted"
                );
                let bad_s = flip(&s, s.len() - 1);
                assert!(
                    !ecc_verify(c, key.public_key(), scheme, hash, &digest, &r, &bad_s)
                        .check(&what),
                    "{what}: corrupted s accepted"
                );
                let bad_digest = flip(&digest, 0);
                assert!(
                    !ecc_verify(c, key.public_key(), scheme, hash, &bad_digest, &r, &s)
                        .check(&what),
                    "{what}: corrupted digest accepted"
                );
                assert!(
                    !ecc_verify(c, other.public_key(), scheme, hash, &digest, &r, &s).check(&what),
                    "{what}: wrong public key accepted"
                );

                // Out-of-range (0 or >= n) and empty signature components.
                let zeros = vec![0u8; size];
                let ones = vec![0xFFu8; size];
                for (br, bs) in [
                    (&[][..], &s[..]),
                    (&r[..], &[][..]),
                    (&zeros[..], &s[..]),
                    (&r[..], &zeros[..]),
                    (&ones[..], &s[..]),
                    (&r[..], &ones[..]),
                ] {
                    assert!(
                        !ecc_verify(c, key.public_key(), scheme, hash, &digest, br, bs)
                            .check(&what),
                        "{what}: out-of-range signature component accepted"
                    );
                }
            }
        }
    }
}

/// ECDSA signing and verification across all curves and hash algorithms
/// (including digests shorter and longer than the curve order), plus ECDAA
/// rejection.
pub fn ecdsa_sign_verify<C: Signing>(c: &C, caps: &Caps) {
    check_ecc_scheme(c, caps, EccSigScheme::Ecdsa, |caps, hash| {
        caps.ecdsa.contains(&hash)
    });
    // ECDAA requires the stateful TPM2_Commit protocol and is not supported
    // through the stateless Signing trait.
    check_ecc_scheme(c, caps, EccSigScheme::Ecdaa(1), |_, _| false);
}

/// SM2 signing and verification across all curves and hash algorithms.
pub fn sm2_sign_verify<C: Signing>(c: &C, caps: &Caps) {
    check_ecc_scheme(c, caps, EccSigScheme::Sm2, |caps, _| caps.sm2);
}

/// EC-Schnorr signing and verification across all curves and hash algorithms.
pub fn ecschnorr_sign_verify<C: Signing>(c: &C, caps: &Caps) {
    check_ecc_scheme(c, caps, EccSigScheme::Ecschnorr, |caps, hash| {
        caps.ecschnorr && caps.hash.contains(&hash)
    });
}

/// HMAC signing and verification via [`sign`] and [`verify`], plus rejection
/// of mismatched key/scheme combinations.
pub fn hmac_sign_verify<C: Signing>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "hmac_sign_verify");
    let key = b"hmac signing key";
    for &hash in HASHES {
        let what = format!("HMAC {hash:?}");
        let supported = caps.hmac.contains(&hash);
        let digest = pattern(hash.digest_size(), 40);
        let mut buf: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let result = sign(
            c,
            &mut rng,
            SigningKey::Hmac(key),
            TpmtSigScheme::Hmac(hash),
            &digest,
            &mut buf,
        );
        let Some(sig) = expect_support(supported, &what, result) else {
            let fake = TpmtSignature::Hmac(tpmt_ha(hash, &digest));
            let verify_res = verify(c, VerifyingKey::Hmac(key), &digest, fake);
            expect_support(false, &what, verify_res);
            continue;
        };
        let TpmtSignature::Hmac(tag) = sig else {
            panic!("{what}: expected TpmtSignature::Hmac");
        };
        let mut expected_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let expected = hmac(c, hash, key, &digest, &mut expected_buf).check(&what);
        assert_eq!(tag, expected);

        assert!(
            verify(c, VerifyingKey::Hmac(key), &digest, sig).check(&what),
            "{what}: valid HMAC signature rejected"
        );
        assert!(
            !verify(c, VerifyingKey::Hmac(b"wrong key"), &digest, sig).check(&what),
            "{what}: wrong HMAC key accepted"
        );
        assert!(
            !verify(c, VerifyingKey::Hmac(key), &flip(&digest, 0), sig).check(&what),
            "{what}: modified digest accepted"
        );
        let bad_tag = flip(tag.digest(), 0);
        let bad_sig = TpmtSignature::Hmac(tpmt_ha(hash, &bad_tag));
        assert!(
            !verify(c, VerifyingKey::Hmac(key), &digest, bad_sig).check(&what),
            "{what}: modified HMAC tag accepted"
        );
        assert!(
            !verify(c, VerifyingKey::Hmac(key), &digest[1..], sig).check(&what),
            "{what}: wrong-length digest accepted"
        );

        // Mismatched key and scheme (e.g. HMAC key with RSASSA scheme) and
        // non-digest schemes (ML-DSA, EdDSA) return Unsupported.
        let mut scratch: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        for bad_scheme in [
            TpmtSigScheme::Rsassa(hash),
            TpmtSigScheme::Ecdsa(hash),
            TpmtSigScheme::Mldsa,
            TpmtSigScheme::HashMldsa,
            TpmtSigScheme::Eddsa,
            TpmtSigScheme::HashEddsa,
        ] {
            assert_eq!(
                sign(
                    c,
                    &mut rng,
                    SigningKey::Hmac(key),
                    bad_scheme,
                    &digest,
                    &mut scratch,
                ),
                Err(CryptoError::Unsupported),
            );
        }
        let rsa_sig = TpmtSignature::Rsassa(tpms_sig_rsa(hash, &[0u8; 256]));
        assert_eq!(
            verify(c, VerifyingKey::Hmac(key), &digest, rsa_sig),
            Err(CryptoError::Unsupported),
        );
    }
}
