//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204) through the crypto backend under test
//! ([`tpm2::crypto::backend::Mlkem`], [`tpm2::crypto::backend::Mldsa`]):
//! known-answer tests for every parameter set (NIST ACVP, Wycheproof and the
//! TCG v185 reference's self-test data, in `pqc_vectors/`), the encapsulation
//! key check, key loading, round trips and tampered signatures.
//!
//! The backend traits are called directly rather than through the dispatch
//! types (`MlkemPublicKey`, `MldsaPrivateKey`, ...), whose parameter sets only
//! exist with the `tpm2` `mlkem_*`/`mldsa_*` features, which these tests must
//! not enable (they would widen the TPM). The sizes of keys, ciphertexts and
//! signatures are const generics of the backend API (fixed-size arrays), so
//! wrong-size inputs and too-small output buffers cannot reach the backend;
//! the tests of those cases became tests of key loading (`load_public`,
//! `load`).

use sha2::{Digest, Sha256};
use tpm2::crypto::Random;
use tpm2::crypto::backend::{Mldsa, MldsaKey, Mlkem, MlkemKey};
use tpm2::{TpmiMldsaParms, TpmiMlkemParms};
use tpm2_crypto_tests::TestProvider;

type C = TestProvider;
/// The RNG of the backend under test.
type R = <C as Random>::Rng;

/// ML-KEM seed `d || z` size.
const MLKEM_SEED_SIZE: usize = TpmiMlkemParms::PRIV_KEY_BYTES;
/// ML-KEM shared secret size.
const MLKEM_SHARED_SECRET_SIZE: usize = TpmiMlkemParms::SHARED_SECRET_BYTES;
/// ML-DSA seed `xi` size.
const MLDSA_SEED_SIZE: usize = TpmiMldsaParms::PRIV_KEY_BYTES;
/// ML-DSA external mu size.
const MLDSA_MU_SIZE: usize = TpmiMldsaParms::MU_BYTES;

/// An ML-KEM parameter set (`TpmiMlkemParms` has no variants without the
/// `tpm2` ML-KEM features).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MlkemSet {
    Mlkem512,
    Mlkem768,
    Mlkem1024,
}

/// An ML-DSA parameter set (`TpmiMldsaParms` has no variants without the
/// `tpm2` ML-DSA features).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MldsaSet {
    Mldsa44,
    Mldsa65,
    Mldsa87,
}

const MLKEM_PARAMS: [MlkemSet; 3] = [MlkemSet::Mlkem512, MlkemSet::Mlkem768, MlkemSet::Mlkem1024];
const MLDSA_PARAMS: [MldsaSet; 3] = [MldsaSet::Mldsa44, MldsaSet::Mldsa65, MldsaSet::Mldsa87];

/// Calls the generic function `$f::<K, PUB, CT>($args)` for the backend key
/// type of the ML-KEM parameter set `$p`.
macro_rules! with_mlkem {
    ($p:expr, $f:ident($($arg:expr),* $(,)?)) => {
        match $p {
            MlkemSet::Mlkem512 => $f::<<C as Mlkem>::Mlkem512, 800, 768>($($arg),*),
            MlkemSet::Mlkem768 => $f::<<C as Mlkem>::Mlkem768, 1184, 1088>($($arg),*),
            MlkemSet::Mlkem1024 => $f::<<C as Mlkem>::Mlkem1024, 1568, 1568>($($arg),*),
        }
    };
}

/// Calls the generic function `$f::<K, PUB, SIG>($args)` for the backend key
/// type of the ML-DSA parameter set `$p`.
macro_rules! with_mldsa {
    ($p:expr, $f:ident($($arg:expr),* $(,)?)) => {
        match $p {
            MldsaSet::Mldsa44 => $f::<<C as Mldsa>::Mldsa44, 1312, 2420>($($arg),*),
            MldsaSet::Mldsa65 => $f::<<C as Mldsa>::Mldsa65, 1952, 3309>($($arg),*),
            MldsaSet::Mldsa87 => $f::<<C as Mldsa>::Mldsa87, 2592, 4627>($($arg),*),
        }
    };
}

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

    fn mlkem(&self) -> MlkemSet {
        match self.str("params") {
            "512" => MlkemSet::Mlkem512,
            "768" => MlkemSet::Mlkem768,
            "1024" => MlkemSet::Mlkem1024,
            p => panic!("unknown ML-KEM parameter set {p}"),
        }
    }

    fn mldsa(&self) -> MldsaSet {
        match self.str("params") {
            "44" => MldsaSet::Mldsa44,
            "65" => MldsaSet::Mldsa65,
            "87" => MldsaSet::Mldsa87,
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

/// The `(public key size, ciphertext size)` of an ML-KEM parameter set (FIPS 203).
fn mlkem_sizes(p: MlkemSet) -> (usize, usize) {
    match p {
        MlkemSet::Mlkem512 => (800, 768),
        MlkemSet::Mlkem768 => (1184, 1088),
        MlkemSet::Mlkem1024 => (1568, 1568),
    }
}

/// The `(public key size, signature size)` of an ML-DSA parameter set (FIPS 204).
fn mldsa_sizes(p: MldsaSet) -> (usize, usize) {
    match p {
        MldsaSet::Mldsa44 => (1312, 2420),
        MldsaSet::Mldsa65 => (1952, 3309),
        MldsaSet::Mldsa87 => (2592, 4627),
    }
}

/// The encapsulation key of the key expanded from `seed`.
fn mlkem_public_key(p: MlkemSet, seed: &[u8; MLKEM_SEED_SIZE]) -> Vec<u8> {
    fn public_key<K: MlkemKey<PUB, CT, R>, const PUB: usize, const CT: usize>(
        seed: &[u8; MLKEM_SEED_SIZE],
    ) -> Vec<u8> {
        let key = K::expand(seed).unwrap();
        let mut ek = [0u8; PUB];
        K::store_public(key.as_public(), &mut ek).unwrap();
        // The seed is the private key, stored back unchanged.
        let mut stored = [0u8; MLKEM_SEED_SIZE];
        key.store(&mut stored).unwrap();
        assert_eq!(&stored, seed);
        ek.to_vec()
    }
    with_mlkem!(p, public_key(seed))
}

/// Encapsulation with the randomness `m` under the encapsulation key `ek`
/// (of the size of the parameter set): `None` if `ek` fails the FIPS 203
/// encapsulation key check of `load_public`.
fn mlkem_encapsulate(
    p: MlkemSet,
    ek: &[u8],
    m: &[u8; 32],
) -> Option<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_SIZE])> {
    fn encapsulate<K: MlkemKey<PUB, CT, R>, const PUB: usize, const CT: usize>(
        ek: &[u8],
        m: &[u8; 32],
    ) -> Option<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_SIZE])> {
        let public = K::load_public((), ek.try_into().unwrap()).unwrap()?;
        let mut ct = [0u8; CT];
        let mut k = [0u8; MLKEM_SHARED_SECRET_SIZE];
        K::encapsulate_internal(&public, m, &mut ct, &mut k).unwrap();
        Some((ct.to_vec(), k))
    }
    with_mlkem!(p, encapsulate(ek, m))
}

/// Decapsulation of `ct` (of the size of the parameter set) with the key
/// expanded from `seed`.
fn mlkem_decapsulate(
    p: MlkemSet,
    seed: &[u8; MLKEM_SEED_SIZE],
    ct: &[u8],
) -> [u8; MLKEM_SHARED_SECRET_SIZE] {
    fn decapsulate<K: MlkemKey<PUB, CT, R>, const PUB: usize, const CT: usize>(
        seed: &[u8; MLKEM_SEED_SIZE],
        ct: &[u8],
    ) -> [u8; MLKEM_SHARED_SECRET_SIZE] {
        let mut k = [0u8; MLKEM_SHARED_SECRET_SIZE];
        K::expand(seed)
            .unwrap()
            .decapsulate(ct.try_into().unwrap(), &mut k)
            .unwrap();
        k
    }
    with_mlkem!(p, decapsulate(seed, ct))
}

/// Whether `seed` loads as the private key of the encapsulation key `ek`
/// (`Some(true)`), does not match it (`Some(false)`), or `ek` is rejected by
/// `load_public` (`None`).
fn mlkem_load(p: MlkemSet, ek: &[u8], seed: &[u8; MLKEM_SEED_SIZE]) -> Option<bool> {
    fn load<K: MlkemKey<PUB, CT, R>, const PUB: usize, const CT: usize>(
        ek: &[u8],
        seed: &[u8; MLKEM_SEED_SIZE],
    ) -> Option<bool> {
        let public = K::load_public((), ek.try_into().unwrap()).unwrap()?;
        Some(K::load(public, seed).unwrap().is_some())
    }
    with_mlkem!(p, load(ek, seed))
}

/// The public key of the key expanded from `seed`.
fn mldsa_public_key(p: MldsaSet, seed: &[u8; MLDSA_SEED_SIZE]) -> Vec<u8> {
    fn public_key<K: MldsaKey<PUB, SIG, R>, const PUB: usize, const SIG: usize>(
        seed: &[u8; MLDSA_SEED_SIZE],
    ) -> Vec<u8> {
        let key = K::expand(seed).unwrap();
        let mut pk = [0u8; PUB];
        K::store_public(key.as_public(), &mut pk).unwrap();
        // The seed is the private key, stored back unchanged.
        let mut stored = [0u8; MLDSA_SEED_SIZE];
        key.store(&mut stored).unwrap();
        assert_eq!(&stored, seed);
        pk.to_vec()
    }
    with_mldsa!(p, public_key(seed))
}

/// Signs the external `mu` with the randomness `rnd` and the key expanded
/// from `seed`.
fn mldsa_sign(
    p: MldsaSet,
    seed: &[u8; MLDSA_SEED_SIZE],
    mu: &[u8; MLDSA_MU_SIZE],
    rnd: &[u8; 32],
) -> Vec<u8> {
    fn sign<K: MldsaKey<PUB, SIG, R>, const PUB: usize, const SIG: usize>(
        seed: &[u8; MLDSA_SEED_SIZE],
        mu: &[u8; MLDSA_MU_SIZE],
        rnd: &[u8; 32],
    ) -> Vec<u8> {
        let mut sig = [0u8; SIG];
        K::expand(seed)
            .unwrap()
            .sign_mu_internal(rnd, mu, &mut sig)
            .unwrap();
        sig.to_vec()
    }
    with_mldsa!(p, sign(seed, mu, rnd))
}

/// Verifies `sig` over the external `mu` under the public key `pk` (both of
/// the sizes of the parameter set). A public key that `load_public` rejects
/// verifies nothing.
fn mldsa_verify(p: MldsaSet, pk: &[u8], mu: &[u8; MLDSA_MU_SIZE], sig: &[u8]) -> bool {
    fn verify<K: MldsaKey<PUB, SIG, R>, const PUB: usize, const SIG: usize>(
        pk: &[u8],
        mu: &[u8; MLDSA_MU_SIZE],
        sig: &[u8],
    ) -> bool {
        match K::load_public((), pk.try_into().unwrap()).unwrap() {
            Some(public) => K::verify_mu(&public, mu, sig.try_into().unwrap()).unwrap(),
            None => false,
        }
    }
    with_mldsa!(p, verify(pk, mu, sig))
}

/// Whether `seed` loads as the private key of the public key `pk`.
fn mldsa_load(p: MldsaSet, pk: &[u8], seed: &[u8; MLDSA_SEED_SIZE]) -> bool {
    fn load<K: MldsaKey<PUB, SIG, R>, const PUB: usize, const SIG: usize>(
        pk: &[u8],
        seed: &[u8; MLDSA_SEED_SIZE],
    ) -> bool {
        let public = K::load_public((), pk.try_into().unwrap()).unwrap().unwrap();
        K::load(public, seed).unwrap().is_some()
    }
    with_mldsa!(p, load(pk, seed))
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
        let k = mlkem_decapsulate(r.mlkem(), &r.array("seed"), &r.bytes("c"));
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
        let k = mlkem_decapsulate(p, &r.array("kat_seed"), &r.bytes("kat_ct"));
        assert_eq!(k.to_vec(), r.bytes("kat_secret"), "{p:?}");
        let (ct, k) = mlkem_encapsulate(p, &r.bytes("test_pub"), &[0x5a; 32]).unwrap();
        assert_eq!(mlkem_decapsulate(p, &seed, &ct), k, "{p:?}");
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
        assert_eq!(mlkem_decapsulate(p, &seed, &ct), k, "{p:?}");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_ne!(mlkem_decapsulate(p, &seed, &bad), k, "{p:?}");
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
/// q = 3329 (the modulus check of FIPS 203, Section 7.2, in `load_public`).
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
        // (Keys of the wrong size, including those of the other parameter sets,
        // cannot be passed to the backend's fixed-size `load_public`.)
        assert_eq!(ek.len(), mlkem_sizes(p).0, "{p:?}");
    }
}

/// (Formerly: decapsulation reports a ciphertext of the wrong size as `Ok(false)`, and output
/// buffers that are too small are internal errors. Both are excluded by the fixed-size arrays
/// of the backend API.) A seed loads with its own encapsulation key only (`load` checks the
/// seed against the public key, as the TPM does when loading a key), and the encapsulation key
/// check of `load_public` also applies to loading.
#[test]
fn mlkem_load_checks_the_seed_against_the_public_key() {
    for p in MLKEM_PARAMS {
        let seed = [0x44; MLKEM_SEED_SIZE];
        let ek = mlkem_public_key(p, &seed);
        assert_eq!(ek.len(), mlkem_sizes(p).0, "{p:?}");
        assert_eq!(mlkem_load(p, &ek, &seed), Some(true), "{p:?}");
        // Another d (another key pair) does not match.
        let mut other = seed;
        other[0] ^= 1;
        assert_eq!(mlkem_load(p, &ek, &other), Some(false), "{p:?}");
        let mut bad = ek.clone();
        bad[0] = 0xff;
        bad[1] |= 0x0f;
        assert_eq!(mlkem_load(p, &bad, &seed), None, "{p:?}");
        // Ciphertexts of the expected size round trip.
        let (ct, k) = mlkem_encapsulate(p, &ek, &[0x55; 32]).unwrap();
        assert_eq!(ct.len(), mlkem_sizes(p).1, "{p:?}");
        assert_eq!(mlkem_decapsulate(p, &seed, &ct), k, "{p:?}");
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

/// (Formerly: verification reports a public key or signature of the wrong size as `Ok(false)`,
/// and output buffers that are too small are internal errors. Both are excluded by the
/// fixed-size arrays of the backend API.) Keys and signatures have the sizes of their
/// parameter set, a seed loads with its own public key only, and a signature by another key
/// of the same parameter set does not verify.
#[test]
fn mldsa_load_checks_the_seed_against_the_public_key() {
    for p in MLDSA_PARAMS {
        let seed = [0x99; MLDSA_SEED_SIZE];
        let pk = mldsa_public_key(p, &seed);
        let mu = [0xaa; MLDSA_MU_SIZE];
        let sig = mldsa_sign(p, &seed, &mu, &[0; 32]);
        assert_eq!((pk.len(), sig.len()), mldsa_sizes(p), "{p:?}");
        assert!(mldsa_load(p, &pk, &seed), "{p:?}");
        let mut other = seed;
        other[31] ^= 1;
        assert!(!mldsa_load(p, &pk, &other), "{p:?}");
        let other_sig = mldsa_sign(p, &other, &mu, &[0; 32]);
        assert!(!mldsa_verify(p, &pk, &mu, &other_sig), "{p:?}");
    }
}
