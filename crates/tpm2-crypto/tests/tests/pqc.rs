//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204) through the crypto provider
//! ([`tpm2::crypto::Mlkem`], [`tpm2::crypto::Mldsa`]): known-answer tests for
//! every parameter set (NIST ACVP, Wycheproof and the TCG v185 reference's
//! self-test data, in `pqc_vectors/`), the encapsulation key check, size
//! checks, round trips and tampered signatures.

use sha2::{Digest, Sha256};
use tpm2::crypto::{
    CryptoError, MLDSA_MU_SIZE, MLDSA_RND_SIZE, MLDSA_SEED_SIZE, MLKEM_ENTROPY_SIZE,
    MLKEM_SEED_SIZE, MLKEM_SHARED_SECRET_SIZE, Mldsa, Mlkem,
};
use tpm2::{TpmiMldsaParms, TpmiMlkemParms};
use tpm2_crypto_tests::TestProvider;

const MLKEM_PARAMS: [TpmiMlkemParms; 3] = [
    TpmiMlkemParms::Mlkem512,
    TpmiMlkemParms::Mlkem768,
    TpmiMlkemParms::Mlkem1024,
];
const MLDSA_PARAMS: [TpmiMldsaParms; 3] = [
    TpmiMldsaParms::Mldsa44,
    TpmiMldsaParms::Mldsa65,
    TpmiMldsaParms::Mldsa87,
];

const TCG_VECTORS: &str = include_str!("pqc_vectors/tcg_self_test.txt");
const ACVP_VECTORS: &str = include_str!("pqc_vectors/acvp.txt");
const WYCHEPROOF_VECTORS: &str = include_str!("pqc_vectors/wycheproof.txt");

/// A test vector: the `key = hex` lines of one blank-line-separated record.
struct Record<'a>(Vec<(&'a str, &'a str)>);

impl Record<'_> {
    fn str(&self, key: &str) -> &str {
        self.0
            .iter()
            .find(|(k, _)| *k == key)
            .unwrap_or_else(|| panic!("no `{key}` in record"))
            .1
    }

    fn bytes(&self, key: &str) -> Vec<u8> {
        let hex = self.str(key);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn array<const N: usize>(&self, key: &str) -> [u8; N] {
        self.bytes(key).try_into().unwrap()
    }

    fn mlkem(&self) -> TpmiMlkemParms {
        match self.str("params") {
            "512" => TpmiMlkemParms::Mlkem512,
            "768" => TpmiMlkemParms::Mlkem768,
            "1024" => TpmiMlkemParms::Mlkem1024,
            p => panic!("unknown ML-KEM parameter set {p}"),
        }
    }

    fn mldsa(&self) -> TpmiMldsaParms {
        match self.str("params") {
            "44" => TpmiMldsaParms::Mldsa44,
            "65" => TpmiMldsaParms::Mldsa65,
            "87" => TpmiMldsaParms::Mldsa87,
            p => panic!("unknown ML-DSA parameter set {p}"),
        }
    }
}

/// Returns the records of `test` kind in `vectors` (asserting there is one per parameter set).
fn records<'a>(vectors: &'a str, test: &str) -> Vec<Record<'a>> {
    let records: Vec<Record<'a>> = vectors
        .split("\n\n")
        .map(|block| {
            Record(
                block
                    .lines()
                    .filter(|line| !line.starts_with('#') && !line.is_empty())
                    .map(|line| line.split_once(" = ").unwrap())
                    .collect(),
            )
        })
        .filter(|record| !record.0.is_empty() && record.str("test") == test)
        .collect();
    assert_eq!(records.len(), 3, "{test}: one record per parameter set");
    records
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn mlkem_public_key(param_set: TpmiMlkemParms, seed: &[u8; MLKEM_SEED_SIZE]) -> Vec<u8> {
    let mut ek = vec![0u8; 2048];
    let len = TestProvider
        .mlkem_generate_key(param_set, seed, &mut ek)
        .unwrap();
    assert_eq!(len, param_set.public_key_bytes());
    ek.truncate(len);
    ek
}

fn mlkem_encapsulate(
    param_set: TpmiMlkemParms,
    ek: &[u8],
    entropy: &[u8; MLKEM_ENTROPY_SIZE],
) -> Option<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_SIZE])> {
    let mut ct = vec![0u8; 2048];
    let mut k = [0u8; MLKEM_SHARED_SECRET_SIZE];
    let len = TestProvider
        .mlkem_encapsulate(param_set, ek, entropy, &mut ct, &mut k)
        .unwrap()?;
    assert_eq!(len, param_set.ciphertext_bytes());
    ct.truncate(len);
    Some((ct, k))
}

fn mlkem_decapsulate(
    param_set: TpmiMlkemParms,
    seed: &[u8; MLKEM_SEED_SIZE],
    ct: &[u8],
) -> Option<[u8; MLKEM_SHARED_SECRET_SIZE]> {
    let mut k = [0u8; MLKEM_SHARED_SECRET_SIZE];
    TestProvider
        .mlkem_decapsulate(param_set, seed, ct, &mut k)
        .unwrap()
        .then_some(k)
}

fn mldsa_public_key(param_set: TpmiMldsaParms, seed: &[u8; MLDSA_SEED_SIZE]) -> Vec<u8> {
    let mut pk = vec![0u8; 4096];
    let len = TestProvider
        .mldsa_generate_key(param_set, seed, &mut pk)
        .unwrap();
    assert_eq!(len, param_set.public_key_bytes());
    pk.truncate(len);
    pk
}

fn mldsa_sign(
    param_set: TpmiMldsaParms,
    seed: &[u8; MLDSA_SEED_SIZE],
    mu: &[u8; MLDSA_MU_SIZE],
    rnd: &[u8; MLDSA_RND_SIZE],
) -> Vec<u8> {
    let mut sig = vec![0u8; 5000];
    let len = TestProvider
        .mldsa_sign_mu(param_set, seed, mu, rnd, &mut sig)
        .unwrap()
        .unwrap();
    assert_eq!(len, param_set.signature_bytes());
    sig.truncate(len);
    sig
}

fn mldsa_verify(
    param_set: TpmiMldsaParms,
    pk: &[u8],
    mu: &[u8; MLDSA_MU_SIZE],
    sig: &[u8],
) -> bool {
    TestProvider
        .mldsa_verify_mu(param_set, pk, mu, sig)
        .unwrap()
}

/// ML-KEM key generation from a seed `d || z` matches the NIST ACVP keyGen vectors.
#[test]
fn mlkem_key_generation_matches_acvp() {
    for r in records(ACVP_VECTORS, "mlkem_keygen") {
        let ek = mlkem_public_key(r.mlkem(), &r.array("seed"));
        assert_eq!(sha256(&ek), r.bytes("ek_sha256"), "{:?}", r.mlkem());
    }
}

/// ML-KEM encapsulation with the randomness `m` matches the NIST ACVP encapsulation vectors.
#[test]
fn mlkem_encapsulation_matches_acvp() {
    for r in records(ACVP_VECTORS, "mlkem_encap") {
        let (ct, k) = mlkem_encapsulate(r.mlkem(), &r.bytes("ek"), &r.array("m")).unwrap();
        assert_eq!(sha256(&ct), r.bytes("c_sha256"), "{:?}", r.mlkem());
        assert_eq!(k.to_vec(), r.bytes("k"), "{:?}", r.mlkem());
    }
}

/// ML-KEM decapsulation of a corrupted ciphertext gives the implicit-rejection secret of the
/// Wycheproof vectors.
#[test]
fn mlkem_decapsulation_implicitly_rejects_as_wycheproof() {
    for r in records(WYCHEPROOF_VECTORS, "mlkem_decap") {
        let k = mlkem_decapsulate(r.mlkem(), &r.array("seed"), &r.bytes("c")).unwrap();
        assert_eq!(k.to_vec(), r.bytes("k"), "{:?}", r.mlkem());
    }
}

/// The TCG reference's ML-KEM self-test data: the key pair matches, the decapsulation
/// known-answer test passes, and the key pair round-trips an encapsulation.
#[test]
fn mlkem_matches_tcg_self_test_data() {
    for r in records(TCG_VECTORS, "mlkem") {
        let p = r.mlkem();
        let seed = r.array("test_seed");
        assert_eq!(mlkem_public_key(p, &seed), r.bytes("test_pub"), "{p:?}");
        let k = mlkem_decapsulate(p, &r.array("kat_seed"), &r.bytes("kat_ct")).unwrap();
        assert_eq!(k.to_vec(), r.bytes("kat_secret"), "{p:?}");
        let (ct, k) = mlkem_encapsulate(p, &r.bytes("test_pub"), &[0x5a; 32]).unwrap();
        assert_eq!(mlkem_decapsulate(p, &seed, &ct), Some(k), "{p:?}");
    }
}

/// An ML-KEM key pair round-trips encapsulation and decapsulation, encapsulation is
/// deterministic in `m`, and a modified ciphertext decapsulates to another secret.
#[test]
fn mlkem_encapsulation_round_trips() {
    for p in MLKEM_PARAMS {
        let seed = [0x11; MLKEM_SEED_SIZE];
        let ek = mlkem_public_key(p, &seed);
        let (ct, k) = mlkem_encapsulate(p, &ek, &[0x22; 32]).unwrap();
        assert_eq!(
            mlkem_encapsulate(p, &ek, &[0x22; 32]),
            Some((ct.clone(), k))
        );
        assert_ne!(mlkem_encapsulate(p, &ek, &[0x23; 32]).unwrap().1, k);
        assert_eq!(mlkem_decapsulate(p, &seed, &ct), Some(k), "{p:?}");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_ne!(mlkem_decapsulate(p, &seed, &bad).unwrap(), k, "{p:?}");
        // Another seed (the same d, another z) rejects with another secret.
        let mut other = seed;
        other[63] ^= 1;
        assert_eq!(mlkem_public_key(p, &other), ek);
        assert_ne!(
            mlkem_decapsulate(p, &other, &bad),
            mlkem_decapsulate(p, &seed, &bad)
        );
    }
}

/// Encapsulation rejects an encapsulation key with a coefficient that is not reduced modulo
/// q = 3329 (the modulus check of FIPS 203, Section 7.2), or of the wrong size.
#[test]
fn mlkem_encapsulation_rejects_invalid_keys() {
    for p in MLKEM_PARAMS {
        let ek = mlkem_public_key(p, &[0x33; MLKEM_SEED_SIZE]);
        // The first 12-bit coefficient is ek[0] | (ek[1] & 0xf) << 8.
        for coefficient in [3329u16, 4095] {
            let mut bad = ek.clone();
            bad[0] = coefficient as u8;
            bad[1] = (bad[1] & 0xf0) | (coefficient >> 8) as u8;
            assert_eq!(mlkem_encapsulate(p, &bad, &[0; 32]), None, "{p:?}");
        }
        // The largest reduced coefficient is valid.
        let mut edge = ek.clone();
        edge[0] = (3328 & 0xff) as u8;
        edge[1] = (edge[1] & 0xf0) | (3328 >> 8) as u8;
        assert!(mlkem_encapsulate(p, &edge, &[0; 32]).is_some(), "{p:?}");
        // A coefficient of the last polynomial (before the 32-byte rho).
        let mut bad = ek.clone();
        let last = ek.len() - 32 - 2;
        bad[last] |= 0xf0;
        bad[last + 1] = 0xff;
        assert_eq!(mlkem_encapsulate(p, &bad, &[0; 32]), None, "{p:?}");
        for len in [0, ek.len() - 1, ek.len() + 1] {
            let mut wrong = ek.clone();
            wrong.resize(len, 0);
            assert_eq!(mlkem_encapsulate(p, &wrong, &[0; 32]), None, "{p:?} {len}");
        }
        // The key of another parameter set.
        for q in MLKEM_PARAMS.into_iter().filter(|q| *q != p) {
            assert_eq!(mlkem_encapsulate(q, &ek, &[0; 32]), None, "{p:?} as {q:?}");
        }
    }
}

/// Decapsulation reports a ciphertext of the wrong size as `Ok(false)`.
#[test]
fn mlkem_decapsulation_rejects_wrong_sizes() {
    for p in MLKEM_PARAMS {
        let seed = [0x44; MLKEM_SEED_SIZE];
        let len = p.ciphertext_bytes();
        for wrong in [0, 1, len - 1, len + 1] {
            assert_eq!(
                mlkem_decapsulate(p, &seed, &vec![0; wrong]),
                None,
                "{p:?} {wrong}"
            );
        }
    }
}

/// Output buffers that are too small are internal errors.
#[test]
fn mlkem_rejects_small_output_buffers() {
    for p in MLKEM_PARAMS {
        let seed = [0x55; MLKEM_SEED_SIZE];
        let mut small = vec![0u8; p.public_key_bytes() - 1];
        assert_eq!(
            TestProvider.mlkem_generate_key(p, &seed, &mut small),
            Err(CryptoError::Internal)
        );
        let ek = mlkem_public_key(p, &seed);
        let mut small = vec![0u8; p.ciphertext_bytes() - 1];
        assert_eq!(
            TestProvider.mlkem_encapsulate(p, &ek, &[0; 32], &mut small, &mut [0; 32]),
            Err(CryptoError::Internal)
        );
    }
}

/// ML-DSA key generation from a seed `xi` matches the NIST ACVP keyGen vectors.
#[test]
fn mldsa_key_generation_matches_acvp() {
    for r in records(ACVP_VECTORS, "mldsa_keygen") {
        let pk = mldsa_public_key(r.mldsa(), &r.array("seed"));
        assert_eq!(sha256(&pk), r.bytes("pk_sha256"), "{:?}", r.mldsa());
    }
}

/// Hedged ML-DSA signing on an external mu with the randomness `rnd` matches the known
/// answers (an ACVP keyGen seed and an ACVP sigGen mu and rnd), and the signatures verify.
#[test]
fn mldsa_hedged_signing_matches_known_answers() {
    for r in records(ACVP_VECTORS, "mldsa_sign") {
        let (p, seed, mu) = (r.mldsa(), r.array("seed"), r.array("mu"));
        let sig = mldsa_sign(p, &seed, &mu, &r.array("rnd"));
        assert_eq!(sha256(&sig), r.bytes("sig_sha256"), "{p:?}");
        assert!(
            mldsa_verify(p, &mldsa_public_key(p, &seed), &mu, &sig),
            "{p:?}"
        );
    }
}

/// Deterministic ML-DSA signing (an all-zero `rnd`) matches the Wycheproof vectors.
#[test]
fn mldsa_deterministic_signing_matches_wycheproof() {
    for r in records(WYCHEPROOF_VECTORS, "mldsa_sign") {
        let (p, seed, mu) = (r.mldsa(), r.array("seed"), r.array("mu"));
        let sig = mldsa_sign(p, &seed, &mu, &r.array("rnd"));
        assert_eq!(sha256(&sig), r.bytes("sig_sha256"), "{p:?}");
        assert!(
            mldsa_verify(p, &mldsa_public_key(p, &seed), &mu, &sig),
            "{p:?}"
        );
    }
}

/// Verification rejects the invalid external-mu signatures of the NIST ACVP sigVer vectors.
#[test]
fn mldsa_verification_rejects_acvp_invalid_signatures() {
    for r in records(ACVP_VECTORS, "mldsa_verify") {
        assert_eq!(r.str("valid"), "false");
        let p = r.mldsa();
        assert!(
            !mldsa_verify(p, &r.bytes("pk"), &r.array("mu"), &r.bytes("sig")),
            "{p:?}"
        );
    }
}

/// The TCG reference's ML-DSA self-test data: the key pair matches, the verification
/// known-answer test passes, and the key pair round-trips a signature.
#[test]
fn mldsa_matches_tcg_self_test_data() {
    for r in records(TCG_VECTORS, "mldsa") {
        let p = r.mldsa();
        let seed = r.array("test_seed");
        let pk = r.bytes("test_pub");
        assert_eq!(mldsa_public_key(p, &seed), pk, "{p:?}");
        let mu = r.array("kat_mu");
        assert!(
            mldsa_verify(p, &r.bytes("kat_pub"), &mu, &r.bytes("kat_sig")),
            "{p:?}"
        );
        let sig = mldsa_sign(p, &seed, &mu, &[0x77; 32]);
        assert!(mldsa_verify(p, &pk, &mu, &sig), "{p:?}");
    }
}

/// ML-DSA signatures verify, depend on `rnd` only through hedging, and fail verification
/// after tampering with the signature, the mu or the public key.
#[test]
fn mldsa_tampered_signatures_fail_verification() {
    for p in MLDSA_PARAMS {
        let seed = [0x66; MLDSA_SEED_SIZE];
        let pk = mldsa_public_key(p, &seed);
        let mu = [0x88; MLDSA_MU_SIZE];
        let sig = mldsa_sign(p, &seed, &mu, &[0; 32]);
        assert_eq!(mldsa_sign(p, &seed, &mu, &[0; 32]), sig, "{p:?}");
        let hedged = mldsa_sign(p, &seed, &mu, &[1; 32]);
        assert_ne!(hedged, sig, "{p:?}");
        assert!(mldsa_verify(p, &pk, &mu, &sig), "{p:?}");
        assert!(mldsa_verify(p, &pk, &mu, &hedged), "{p:?}");
        // The challenge, the start of z, and the last byte of the hint.
        for i in [0, 64, sig.len() - 1] {
            let mut bad = sig.clone();
            bad[i] ^= 0x01;
            assert!(!mldsa_verify(p, &pk, &mu, &bad), "{p:?} byte {i}");
        }
        let mut bad_mu = mu;
        bad_mu[63] ^= 0x80;
        assert!(!mldsa_verify(p, &pk, &bad_mu, &sig), "{p:?}");
        let mut bad_pk = pk.clone();
        bad_pk[40] ^= 0x01;
        assert!(!mldsa_verify(p, &bad_pk, &mu, &sig), "{p:?}");
        let other_pk = mldsa_public_key(p, &[0x67; MLDSA_SEED_SIZE]);
        assert!(!mldsa_verify(p, &other_pk, &mu, &sig), "{p:?}");
    }
}

/// Verification reports a public key or signature of the wrong size as `Ok(false)`.
#[test]
fn mldsa_verification_rejects_wrong_sizes() {
    for p in MLDSA_PARAMS {
        let seed = [0x99; MLDSA_SEED_SIZE];
        let pk = mldsa_public_key(p, &seed);
        let mu = [0xaa; MLDSA_MU_SIZE];
        let sig = mldsa_sign(p, &seed, &mu, &[0; 32]);
        for len in [0, sig.len() - 1, sig.len() + 1] {
            let mut wrong = sig.clone();
            wrong.resize(len, 0);
            assert!(!mldsa_verify(p, &pk, &mu, &wrong), "{p:?} signature {len}");
        }
        for len in [0, pk.len() - 1, pk.len() + 1] {
            let mut wrong = pk.clone();
            wrong.resize(len, 0);
            assert!(!mldsa_verify(p, &wrong, &mu, &sig), "{p:?} key {len}");
        }
        for q in MLDSA_PARAMS.into_iter().filter(|q| *q != p) {
            assert!(!mldsa_verify(q, &pk, &mu, &sig), "{p:?} as {q:?}");
        }
    }
}

/// Output buffers that are too small are internal errors.
#[test]
fn mldsa_rejects_small_output_buffers() {
    for p in MLDSA_PARAMS {
        let seed = [0xbb; MLDSA_SEED_SIZE];
        let mut small = vec![0u8; p.public_key_bytes() - 1];
        assert_eq!(
            TestProvider.mldsa_generate_key(p, &seed, &mut small),
            Err(CryptoError::Internal)
        );
        let mut small = vec![0u8; p.signature_bytes() - 1];
        assert_eq!(
            TestProvider.mldsa_sign_mu(p, &seed, &[0; 64], &[0; 32], &mut small),
            Err(CryptoError::Internal)
        );
    }
}
