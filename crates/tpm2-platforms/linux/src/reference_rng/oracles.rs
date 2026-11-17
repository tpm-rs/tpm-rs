//! Oracle tests of the Rust implementations of the C reference TPMs' random algorithms: the RSA
//! encodings of `tpm2::crypto` (`rsa_oaep_encode`, `rsa_pkcs1v15_encode`, `rsa_pss_encode`) and
//! the key generations and ECC signatures of `tpm2_engine::asymmetric` must draw and produce
//! exactly what the linked C functions (`OaepEncode()`, `RSAES_PKCS1v1_5Encode()`,
//! `PssEncode()`, `CryptRsaGenerateKey()`, `CryptEccGenerateKey()`, `CryptEccNewKeyPair()`,
//! `CryptEccSign()`) produce from the same DRBG state: the same outputs, the same errors, and the
//! DRBG left in the same state. Every curve and hash of the build is covered (the C code is built
//! with SHA-512 exactly when this crate's `sha512` feature is enabled, so both builds are).
//!
//! Each test runs the Rust function on one [`ReferenceRng`] and the C function on an identical
//! copy (both seeded DRBGs, or both the TPM's DRBG of the same reference process), then compares
//! the outputs and the two DRBG states.

use tpm2::crypto::{Random, Rng, rsa_oaep_encode, rsa_pkcs1v15_encode, rsa_pss_encode};
use tpm2::errors::TpmRc;
use tpm2::{Alg, TpmEccCurve, TpmiAlgHash, TpmiRsaKeyBits};
use tpm2_engine::asymmetric;

use super::tests::started_tpm_rng;
use super::{ReferenceRng, ecc, rsa};
use crate::ReferenceCryptoProvider as Provider;

/// The largest coordinate or order size of the curves.
const MAX_COORD: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;

/// Every curve of the build (the C code implements every curve of the reference profile).
fn curves() -> Vec<TpmEccCurve> {
    (0u16..0x40)
        .filter_map(|id| TpmEccCurve::try_from(id).ok())
        .filter(|&curve| tpm2::crypto::ecc_curve_params(curve).is_some())
        .collect()
}

/// Every hash of the build.
fn hashes() -> Vec<TpmiAlgHash> {
    [Alg::SHA1, Alg::SHA256, Alg::SHA384, Alg::SHA512]
        .into_iter()
        .filter_map(|alg| TpmiAlgHash::try_from(alg).ok())
        .collect()
}

/// Two identical seeded DRBGs (`DRBG_InstantiateSeeded(seed, "", "", "")`): one for the Rust
/// implementation, one for the C reference.
fn seeded_pair(seed: &[u8]) -> (ReferenceRng, ReferenceRng) {
    (
        ReferenceRng::from_seed(seed).unwrap(),
        ReferenceRng::from_seed(seed).unwrap(),
    )
}

/// Two identical TPM DRBGs of the same reference process.
fn tpm_pair() -> (ReferenceRng, ReferenceRng) {
    (started_tpm_rng(), started_tpm_rng())
}

/// The DRBG pairs the tests draw from: seeded (a Primary Object's DRBG) and the TPM's DRBG
/// (which the C code reaches as `drbgDefault`).
fn pairs(seed: &[u8]) -> [(ReferenceRng, ReferenceRng); 2] {
    [seeded_pair(seed), tpm_pair()]
}

/// The private scalar and the public point `x || y` of `key` (each the coordinate size).
fn key_bytes(
    key: &tpm2::crypto::EccPrivateKey<Provider>,
    curve: TpmEccCurve,
) -> (Vec<u8>, Vec<u8>) {
    let (mut d, mut x, mut y) = ([0u8; MAX_COORD], [0u8; MAX_COORD], [0u8; MAX_COORD]);
    let len = curve.key_bytes();
    let d = key.scalar(&mut d).unwrap().as_slice().to_vec();
    let point = key.point(&mut x, &mut y).unwrap();
    assert_eq!(d.len(), len);
    let mut q = point.x.as_slice().to_vec();
    q.extend_from_slice(point.y.as_slice());
    (d, q)
}

/// `TpmEcc_GenPrivateScalar()`/`TpmEcc_GenerateKeyPair()`: the keys of
/// `asymmetric::ecc_generate_key` (and the scalars of `asymmetric::ecc_private_scalar`) are those
/// of `CryptEccGenerateKey()` (an object without the *sign* attribute) on every curve, from a
/// seeded DRBG and from the TPM's DRBG.
#[test]
fn ecc_keys_match_crypt_ecc_generate_key() {
    for curve in curves() {
        for (mut rust, mut c) in pairs(&u16::from(curve).to_be_bytes()) {
            let mut twin = clone_rng(&rust);
            let key = asymmetric::ecc_generate_key::<Provider>(&mut rust, curve).unwrap();
            let (d, q) = key_bytes(&key, curve);
            let (mut c_d, mut c_q) = ([0u8; MAX_COORD], [0u8; 2 * MAX_COORD]);
            let len = c
                .with_drbg(|r, rand| ecc::generate_key(r, rand, curve, false, &mut c_d, &mut c_q))
                .unwrap();
            assert_eq!(d, c_d[..len], "{curve:?}: d");
            assert_eq!(q, c_q[..2 * len], "{curve:?}: Q");
            assert_eq!(rust.drbg, c.drbg, "{curve:?}");
            let mut scalar = [0u8; MAX_COORD];
            let n = asymmetric::ecc_private_scalar(&mut twin, curve, &mut scalar).unwrap();
            assert_eq!(scalar[..n], c_d[..len], "{curve:?}: scalar");
            assert_eq!(twin.drbg, c.drbg, "{curve:?}");
        }
    }
}

/// A copy of `rng` (its DRBG state and kind; a TPM DRBG's entropy source is the same process's).
fn clone_rng(rng: &ReferenceRng) -> ReferenceRng {
    let mut copy = if rng.is_seeded() {
        ReferenceRng::from_seed(b"").unwrap()
    } else {
        started_tpm_rng()
    };
    copy.drbg = rng.drbg;
    copy
}

/// `CryptEccNewKeyPair()`: the ephemeral keys of the engine (`asymmetric::ecc_generate_key` on
/// the TPM's DRBG) are the reference's on every curve.
#[test]
fn ephemeral_keys_match_crypt_ecc_new_key_pair() {
    for curve in curves() {
        let (mut rust, mut c) = tpm_pair();
        let key = asymmetric::ecc_generate_key::<Provider>(&mut rust, curve).unwrap();
        let (d, q) = key_bytes(&key, curve);
        let (mut c_d, mut c_q) = ([0u8; MAX_COORD], [0u8; 2 * MAX_COORD]);
        let len = c
            .with_drbg(|r, _| ecc::new_key_pair(r, curve, &mut c_d, &mut c_q))
            .unwrap();
        assert_eq!((d, q), (c_d[..len].to_vec(), c_q[..2 * len].to_vec()));
        assert_eq!(rust.drbg, c.drbg, "{curve:?}");
    }
}

/// The FIPS pairwise consistency test of an ECC signing key: the engine's (a key from a seeded
/// DRBG, then a digest of `min(key size, MAX_DIGEST_SIZE)` octets and an ECDSA nonce from the
/// TPM's DRBG with `asymmetric::ecdsa_sign`) draws exactly what `CryptEccGenerateKey()` with the
/// *sign* attribute draws (and the C test alone, `ecc::pairwise_test`), on every curve.
#[test]
fn ecc_pairwise_test_draws_like_crypt_ecc_generate_key() {
    for curve in curves() {
        let (mut seeded, mut c_seeded) = seeded_pair(b"pairwise");
        let (mut tpm, mut c_tpm) = tpm_pair();
        let key = asymmetric::ecc_generate_key::<Provider>(&mut seeded, curve).unwrap();
        let (d, q) = key_bytes(&key, curve);
        let mut digest = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = &mut digest[..d.len().min(TpmiAlgHash::MAX_DIGEST_BYTES)];
        tpm.fill_bytes(digest).unwrap();
        let mut signature = [0u8; 2 * MAX_COORD];
        let len = asymmetric::ecdsa_sign::<Provider>(&mut tpm, curve, &d, digest, &mut signature)
            .unwrap()
            .unwrap();
        assert_eq!(len, 2 * d.len());

        let (mut c_d, mut c_q) = ([0u8; MAX_COORD], [0u8; 2 * MAX_COORD]);
        let c_seeded_drbg = &mut c_seeded.drbg;
        let n = c_tpm
            .with_drbg(|r, _| {
                ecc::generate_key(r, Some(c_seeded_drbg), curve, true, &mut c_d, &mut c_q)
            })
            .unwrap();
        assert_eq!((&d[..], &q[..]), (&c_d[..n], &c_q[..2 * n]), "{curve:?}");
        assert_eq!(seeded.drbg, c_seeded.drbg, "{curve:?}: seeded DRBG");
        assert_eq!(tpm.drbg, c_tpm.drbg, "{curve:?}: TPM DRBG");

        // The C pairwise test alone draws the same.
        let mut c_tpm = started_tpm_rng();
        c_tpm
            .with_drbg(|r, _| ecc::pairwise_test(r, curve, &d))
            .unwrap();
        assert_eq!(tpm.drbg, c_tpm.drbg, "{curve:?}: pairwise test");
    }
}

/// `CryptEccSign()`: ECDSA, SM2 and EC-Schnorr signatures of `asymmetric::ecdsa_sign`,
/// `sm2_sign` and `ecschnorr_sign` are the reference's on every curve with every hash (digests of
/// the hash's size, and a 64-octet digest such as the self test's), from a seeded DRBG and from
/// the TPM's DRBG.
#[test]
fn ecc_signatures_match_crypt_ecc_sign() {
    for curve in curves() {
        let (mut keys, _) = seeded_pair(&[0x5a, u16::from(curve) as u8]);
        let key = asymmetric::ecc_generate_key::<Provider>(&mut keys, curve).unwrap();
        let (d, _) = key_bytes(&key, curve);
        for hash in hashes() {
            let digest_sizes = [hash.digest_size(), 64];
            for (scheme, digest_len) in [Alg::ECDSA, Alg::SM2, Alg::ECSCHNORR]
                .into_iter()
                .flat_map(|scheme| digest_sizes.map(|len| (scheme, len)))
            {
                let digest: Vec<u8> = (0..digest_len as u8).map(|i| i.wrapping_mul(37)).collect();
                for (mut rust, mut c) in pairs(&[scheme.id() as u8, digest_len as u8]) {
                    let mut out = [0u8; 2 * MAX_COORD];
                    let signed = match scheme {
                        Alg::ECDSA => asymmetric::ecdsa_sign::<Provider>(
                            &mut rust, curve, &d, &digest, &mut out,
                        ),
                        Alg::SM2 => asymmetric::sm2_sign::<Provider>(
                            &mut rust, curve, &d, &digest, &mut out,
                        ),
                        _ => asymmetric::ecschnorr_sign::<Provider>(
                            &mut rust, curve, hash, &d, &digest, &mut out,
                        ),
                    };
                    let len = signed.unwrap().unwrap();
                    let (mut r, mut s) = ([0u8; MAX_COORD], [0u8; MAX_COORD]);
                    let c_len = c
                        .with_drbg(|g, rand| {
                            ecc::sign(g, rand, scheme, hash, curve, &d, &digest, &mut r, &mut s)
                        })
                        .unwrap();
                    let what = format!("{curve:?} {scheme:?} {hash:?} {digest_len}");
                    assert_eq!(len, 2 * c_len, "{what}");
                    assert_eq!(out[..c_len], r[..c_len], "{what}: r");
                    assert_eq!(out[c_len..len], s[..c_len], "{what}: s");
                    assert_eq!(rust.drbg, c.drbg, "{what}");
                }
            }
        }
    }
}

/// The result of a C encoding as the Rust encodings report it: `TPM_RC_VALUE` and `TPM_RC_HASH`
/// (a message that does not fit, a modulus that cannot hold two digests) are `None`.
fn c_encoding(result: Result<(), TpmRc>) -> Option<()> {
    match result {
        Ok(()) => Some(()),
        Err(rc) if rc == TpmRc::VALUE.to_rc() || rc == TpmRc::HASH.to_rc() => None,
        Err(rc) => panic!("unexpected C error {rc:?}"),
    }
}

/// `OaepEncode()`: `rsa_oaep_encode` encodes and draws the reference's seed for every hash,
/// modulus size and label (including one with an embedded zero octet), and rejects the messages
/// and moduli the reference rejects (drawing nothing).
#[test]
fn oaep_encodings_match_oaep_encode() {
    for hash in hashes() {
        let h = hash.digest_size();
        for k in [128usize, 256, 384, 512] {
            for label in [&b""[..], b"DUPLICATE\0", b"A\0B\0"] {
                let max = k.saturating_sub(2 * h + 2);
                for len in [0, 1, max.saturating_sub(1), max, max + 1] {
                    let message: Vec<u8> = (0..len).map(|i| i as u8 ^ 0xa5).collect();
                    for (mut rust, mut c) in pairs(&[k as u8, len as u8]) {
                        let (mut out, mut c_out) = (vec![0u8; k], vec![0u8; k]);
                        let encoded =
                            rsa_oaep_encode::<Provider>(&mut rust, hash, label, &message, &mut out)
                                .unwrap();
                        let c_encoded = c_encoding(c.with_drbg(|g, rand| {
                            rsa::oaep_encode(g, rand, hash, label, &message, &mut c_out)
                        }));
                        let what = format!("{hash:?} k={k} label={label:?} len={len}");
                        assert_eq!(encoded, c_encoded, "{what}");
                        if encoded.is_some() {
                            assert_eq!(out, c_out, "{what}");
                        }
                        assert_eq!(rust.drbg, c.drbg, "{what}");
                    }
                }
            }
        }
        // A modulus that cannot hold two digests.
        let (mut rust, mut c) = seeded_pair(b"small");
        let mut out = vec![0u8; 2 * h + 1];
        assert_eq!(
            rsa_oaep_encode::<Provider>(&mut rust, hash, b"", b"", &mut out),
            Ok(None)
        );
        let c_result = c.with_drbg(|g, rand| rsa::oaep_encode(g, rand, hash, b"", b"", &mut out));
        assert_eq!(c_encoding(c_result), None);
        assert_eq!(rust.drbg, c.drbg);
    }
}

/// `RSAES_PKCS1v1_5Encode()`: `rsa_pkcs1v15_encode` encodes and draws the reference's padding
/// (with its zero octets replaced) for every modulus size, and rejects the messages the
/// reference rejects (drawing nothing).
#[test]
fn pkcs1v15_encodings_match_rsaes_pkcs1v1_5_encode() {
    for k in [128usize, 256, 384, 512] {
        for len in [0, 1, 32, k - 12, k - 11, k - 10] {
            let message: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x3c).collect();
            // Enough draws that some padding octets are zero.
            for seed in 0u8..4 {
                for (mut rust, mut c) in pairs(&[seed, k as u8, len as u8]) {
                    let (mut out, mut c_out) = (vec![0u8; k], vec![0u8; k]);
                    let encoded = rsa_pkcs1v15_encode(&mut rust, &message, &mut out).unwrap();
                    let c_encoded = c_encoding(c.with_drbg(|g, rand| {
                        rsa::rsaes_pkcs1v15_encode(g, rand, &message, &mut c_out)
                    }));
                    let what = format!("k={k} len={len} seed={seed}");
                    assert_eq!(encoded, c_encoded, "{what}");
                    if encoded.is_some() {
                        assert_eq!(out, c_out, "{what}");
                    }
                    assert_eq!(rust.drbg, c.drbg, "{what}");
                }
            }
        }
    }
}

/// `PssEncode()`: `rsa_pss_encode` encodes and draws the reference's salt
/// (`CryptRsaPssSaltSize()`) for every hash and modulus size, including outputs too small for a
/// full salt; an output that cannot hold the digest is an error in both (drawing nothing).
#[test]
fn pss_encodings_match_pss_encode() {
    for hash in hashes() {
        let h = hash.digest_size();
        let digest: Vec<u8> = (0..h as u8).map(|i| i.wrapping_mul(11)).collect();
        for k in [128usize, 256, 384, 512, 2 * h + 2, 2 * h + 1, h + 3, h + 2] {
            for (mut rust, mut c) in pairs(&[k as u8, h as u8]) {
                let (mut out, mut c_out) = (vec![0u8; k], vec![0u8; k]);
                rsa_pss_encode::<Provider>(&mut rust, hash, &digest, &mut out).unwrap();
                c.with_drbg(|g, rand| rsa::pss_encode(g, rand, hash, &digest, &mut c_out))
                    .unwrap();
                let what = format!("{hash:?} k={k}");
                assert_eq!(out, c_out, "{what}");
                assert_eq!(rust.drbg, c.drbg, "{what}");
            }
        }
        let (mut rust, mut c) = seeded_pair(b"tiny");
        let mut out = vec![0u8; h + 1];
        assert!(rsa_pss_encode::<Provider>(&mut rust, hash, &digest, &mut out).is_err());
        assert!(
            c.with_drbg(|g, rand| rsa::pss_encode(g, rand, hash, &digest, &mut out))
                .is_err()
        );
        assert_eq!(rust.drbg, c.drbg);
    }
}

/// `CryptRsaGenerateKey()`: the keys of `asymmetric::rsa_generate_key` are the reference's for
/// every key size of the build, with and without the pairwise test of a signing key, from seeded
/// DRBGs (several, so that the reference's first stored prime is the larger one for some and the
/// smaller one for others) and from the TPM's DRBG: the modulus, the prime stored first, and the
/// DRBG left in the same state.
#[test]
fn rsa_keys_match_crypt_rsa_generate_key() {
    let (mut larger_first, mut smaller_first) = (0, 0);
    for bits in [1024, 2048, 3072, 4096]
        .into_iter()
        .filter_map(TpmiRsaKeyBits::new)
    {
        let len = usize::from(bits.as_u16()) / 8;
        let seeds: u8 = if bits.as_u16() <= 2048 { 4 } else { 1 };
        for (i, sign) in (0..seeds).flat_map(|seed| [(seed, false), (seed, true)]) {
            let seed = [bits.as_u16().to_be_bytes()[0], i, u8::from(sign)];
            let mut drbgs = vec![seeded_pair(&seed)];
            if bits == TpmiRsaKeyBits::Rsa1024 && i == 0 {
                drbgs.push(tpm_pair());
            }
            for (mut rust, mut c) in drbgs {
                let key =
                    asymmetric::rsa_generate_key::<Provider>(&mut rust, bits, 0, sign).unwrap();
                let (mut c_n, mut c_p) = (vec![0u8; len], vec![0u8; len / 2]);
                c.with_drbg(|g, rand| {
                    rsa::generate_key(g, rand, bits.as_u16(), 0, sign, &mut c_n, &mut c_p)
                })
                .unwrap();
                let mut n = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                let what = format!(
                    "{bits:?} sign={sign} seed={seed:?} seeded={}",
                    rust.is_seeded()
                );
                assert_eq!(key.modulus(&mut n).unwrap().as_slice(), &c_n[..], "{what}");
                assert_eq!(key.exponent(), 65537);
                // The key holds the prime the reference's sensitive area holds first (the larger
                // or the smaller one), so the TPM stores the reference's private areas.
                let mut p = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
                assert_eq!(key.prime_p(&mut p).unwrap().as_slice(), &c_p[..], "{what}");
                assert_eq!(rust.drbg, c.drbg, "{what}");
                let p = num_bigint::BigUint::from_bytes_be(&c_p);
                let q = num_bigint::BigUint::from_bytes_be(&c_n) / &p;
                if p > q {
                    larger_first += 1;
                } else {
                    smaller_first += 1;
                }
            }
        }
    }
    assert!(
        larger_first > 0 && smaller_first > 0,
        "{larger_first}/{smaller_first}"
    );
}

/// `CryptRsaGenerateKey()` with a public exponent other than 65537 (a prime of at least 65537):
/// the prime search excludes the primes `p` with `p mod e` of 0 or 1 for that exponent.
#[test]
fn rsa_keys_with_another_exponent_match_crypt_rsa_generate_key() {
    let bits = TpmiRsaKeyBits::Rsa1024;
    let e = 65539;
    let (mut rust, mut c) = seeded_pair(b"exponent");
    let (mut c_n, mut c_p) = ([0u8; 128], [0u8; 64]);
    c.with_drbg(|g, rand| rsa::generate_key(g, rand, 1024, e, true, &mut c_n, &mut c_p))
        .unwrap();
    match asymmetric::rsa_generate_key::<Provider>(&mut rust, bits, e, true) {
        Ok(key) => {
            let mut n = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
            assert_eq!(key.modulus(&mut n).unwrap().as_slice(), &c_n[..]);
            let mut p = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
            assert_eq!(key.prime_p(&mut p).unwrap().as_slice(), &c_p[..]);
            assert_eq!(key.exponent(), e);
            assert_eq!(rust.drbg, c.drbg);
        }
        // A backend that only supports 65537 cannot build the key (the TPM reports
        // `TPM_RC_RANGE`).
        Err(tpm2::crypto::CryptoError::Unsupported) => {}
        Err(other) => panic!("{other:?}"),
    }
    // Exponents that are not primes of at least 65537 are rejected before anything is drawn.
    let (mut rust, before) = seeded_pair(b"exponent");
    for e in [3, 65535, 65541] {
        assert_eq!(
            asymmetric::rsa_generate_key::<Provider>(&mut rust, bits, e, false).err(),
            Some(tpm2::crypto::CryptoError::Unsupported)
        );
    }
    assert_eq!(rust.drbg, before.drbg);
}
