//! Tests of [`ReferenceRng`]: its lifecycle, its persistent state, the seeded DRBGs, the error
//! mapping, and its use by the `tpm2::crypto` dispatch functions with BoringSSL
//! ([`ReferenceCryptoProvider`]). The random algorithms on it are checked against the C
//! reference's in `oracles.rs` and against C outputs in `vectors.rs`.
//!
//! [`ReferenceCryptoProvider`]: crate::ReferenceCryptoProvider

use tpm2::crypto::{
    MAX_SIGNATURE_BYTES, RsaEncryptScheme, RsaModulusBuffer, RsaPublicKey, SignatureBuffer,
};
use tpm2::{Tpm2bPublicKeyRsa, TpmiAlgHash, TpmiRsaKeyBits, TpmtSigScheme};
use tpm2_engine::asymmetric;

use super::*;
use crate::{ReferenceCryptoProvider as Provider, VirtualClock};

/// The TPM's DRBG of the reference process with pid 814633 that started at real time
/// 123456789 ms, after `_TPM_Init` (seeding the entropy source) and 5 ms later `TPM2_Startup`.
pub(super) fn started_tpm_rng() -> ReferenceRng {
    let clock = VirtualClock::new(123_456_789);
    let mut rng = ReferenceRng::new(ReferenceEntropy::new(814_633, clock.clone()));
    rng.init().unwrap();
    assert!(rng.self_test().unwrap());
    clock.advance(5);
    rng.startup().unwrap();
    rng
}

/// The first 40 bytes `DRBG_Generate()` returns after `DRBG_Instantiate()` in the C reference
/// process of [`started_tpm_rng`] (see `reference.rs`).
const STARTED_OUTPUT: [u8; 40] = hex_literal::hex!(
    "eee5c5e2199479be3a7d623f9dbb8ddcea16b36da3226787e029b8f5dea97972"
    "7666fe21d3375f90"
);

#[test]
fn tpm_rng_draws_what_the_reference_process_draws() {
    let mut rng = started_tpm_rng();
    assert!(!rng.is_seeded());
    assert!(rng.is_instantiated());
    let mut out = [0u8; 40];
    rng.fill_bytes(&mut out).unwrap();
    assert_eq!(out, STARTED_OUTPUT);
}

#[test]
fn a_new_tpm_rng_draws_nothing_until_startup() {
    let clock = VirtualClock::new(1);
    let mut rng = ReferenceRng::new(ReferenceEntropy::new(1, clock));
    assert!(!rng.is_instantiated());
    // An uninstantiated DRBG cannot generate (`TPM_RC_FAILURE`).
    assert_eq!(rng.fill_bytes(&mut [0; 8]), Err(CryptoError::Internal));
    let mut state = [0xffu8; STATE_SIZE];
    rng.save_state(&mut state).unwrap();
    assert_eq!(state, [0; STATE_SIZE]);
    rng.startup().unwrap();
    assert!(rng.is_instantiated());
    rng.fill_bytes(&mut [0; 8]).unwrap();
}

#[test]
fn saved_state_is_drawn_again_after_loading_it() {
    assert_eq!(<ReferenceRng as Rng>::STATE_SIZE, 76);
    let mut rng = started_tpm_rng();
    let mut state = [0u8; STATE_SIZE];
    rng.save_state(&mut state).unwrap();
    // The NV image of `go.drbgState` (`DrbgState::to_bytes`).
    assert_eq!(state, rng.drbg.to_bytes());
    let mut first = [0u8; 32];
    rng.fill_bytes(&mut first).unwrap();

    let mut restored = ReferenceRng::with_os_entropy();
    restored.load_state(&state).unwrap();
    let mut again = [0u8; 32];
    restored.fill_bytes(&mut again).unwrap();
    assert_eq!(again, first);

    // An all-zero state is that of a new DRBG, which `startup` instantiates.
    restored.load_state(&[0; STATE_SIZE]).unwrap();
    assert!(!restored.is_instantiated());
    restored.startup().unwrap();
    assert!(restored.is_instantiated());

    // Wrong sizes.
    assert_eq!(
        restored.load_state(&[0; STATE_SIZE - 1]),
        Err(CryptoError::Internal)
    );
    assert_eq!(
        restored.save_state(&mut [0; STATE_SIZE - 1]),
        Err(CryptoError::Internal)
    );
}

#[test]
fn startup_reseeds_a_restored_drbg() {
    let mut rng = started_tpm_rng();
    let mut state = [0u8; STATE_SIZE];
    rng.save_state(&mut state).unwrap();
    rng.startup().unwrap();
    let mut reseeded = [0u8; STATE_SIZE];
    rng.save_state(&mut reseeded).unwrap();
    assert_ne!(reseeded, state);
    // `CryptRandStartup()` restarts the reseed counter.
    assert_eq!(rng.drbg.reseed_counter, 1);
}

#[test]
fn self_test_resets_the_flags_of_the_tpm_drbg() {
    let mut fresh = ReferenceRng::with_os_entropy();
    assert!(fresh.self_test().unwrap());
    let Kind::Tpm { flags: passed, .. } = fresh.kind else {
        unreachable!()
    };
    assert_ne!(passed, 0, "TESTED");

    let mut rng = ReferenceRng::with_os_entropy();
    if let Kind::Tpm { flags, .. } = &mut rng.kind {
        *flags = u32::MAX;
    }
    assert!(rng.self_test().unwrap());
    let Kind::Tpm { flags, .. } = rng.kind else {
        unreachable!()
    };
    assert_eq!(flags, passed);

    // A seeded DRBG runs the same test.
    let mut seeded = ReferenceRng::from_seed(b"seed").unwrap();
    assert!(seeded.self_test().unwrap());
}

#[test]
fn from_entropy_is_an_instantiated_tpm_drbg_on_os_entropy() {
    let (mut a, mut b) = (
        ReferenceRng::from_entropy().unwrap(),
        ReferenceRng::from_entropy().unwrap(),
    );
    assert!(!a.is_seeded() && a.is_instantiated());
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    a.fill_bytes(&mut x).unwrap();
    b.fill_bytes(&mut y).unwrap();
    assert_ne!(x, y);
    // Stirring reseeds it (`CryptRandomStir()`).
    a.stir_bytes(b"stir").unwrap();
    assert_eq!(a.drbg.reseed_counter, 1);
    // `init` does nothing for OS entropy.
    a.init().unwrap();
    // The provider's one-shot generation.
    <Provider as Random>::rand_bytes(&mut x).unwrap();
}

#[test]
fn seeded_rngs_are_drbg_instantiate_seeded() {
    let mut rng = ReferenceRng::instantiate_seeded(b"seed", b"purpose\0", b"name", b"add").unwrap();
    assert!(rng.is_seeded() && rng.is_instantiated());
    let mut expected = drbg::instantiate_seeded(b"seed", b"purpose\0", b"name", b"add").unwrap();
    assert_eq!(rng.drbg, expected);
    let (mut out, mut c_out) = ([0u8; 40], [0u8; 40]);
    rng.fill_bytes(&mut out).unwrap();
    drbg::fill(&mut RefRng::seeded_only(), Some(&mut expected), &mut c_out).unwrap();
    assert_eq!(out, c_out);

    // `stir_bytes` is `DRBG_AdditionalData()`.
    rng.stir_bytes(b"proof").unwrap();
    drbg::additional_data(&mut expected, b"proof").unwrap();
    assert_eq!(rng.drbg, expected);

    // `from_seed` has empty purpose, name and additional data.
    assert_eq!(
        ReferenceRng::from_seed(b"seed").unwrap().drbg,
        drbg::instantiate_seeded(b"seed", b"", b"", b"").unwrap()
    );
    // Inputs beyond the reference's limit.
    assert!(matches!(
        ReferenceRng::instantiate_seeded(&[0; 1025], b"", b"", b""),
        Err(CryptoError::Unsupported)
    ));
    assert_eq!(rng.stir_bytes(&[0; 1025]), Err(CryptoError::Unsupported));

    // The lifecycle hooks do nothing.
    let before = rng.drbg;
    rng.init().unwrap();
    rng.startup().unwrap();
    assert_eq!(rng.drbg, before);
    assert!(!rng.is_system_rng());
}

#[test]
fn a_seeded_drbg_must_not_need_reseeding() {
    let mut rng = ReferenceRng::from_seed(b"seed").unwrap();
    rng.drbg.reseed_counter = drbg::CTR_DRBG_MAX_REQUESTS_PER_RESEED;
    assert_eq!(rng.fill_bytes(&mut [0; 4]), Err(CryptoError::Internal));
}

/// RSA keys of the engine's `CryptRsaGenerateKey()` and the dispatch functions' OAEP/RSAES
/// encryption and PSS signatures (the reference's encodings) on the reference RNG work with
/// BoringSSL's raw RSA operations.
#[test]
fn rsa_through_the_dispatch_functions() {
    let mut seeded = ReferenceRng::from_seed(b"rsa").unwrap();
    let key =
        asymmetric::rsa_generate_key::<Provider>(&mut seeded, TpmiRsaKeyBits::Rsa1024, 0, true)
            .unwrap();
    // The same key as `CryptRsaGenerateKey()` on the same DRBG.
    let mut c_drbg = drbg::instantiate_seeded(b"rsa", b"", b"", b"").unwrap();
    let (mut n, mut p) = ([0u8; 128], [0u8; 64]);
    rsa::generate_key(
        &mut RefRng::seeded_only(),
        Some(&mut c_drbg),
        1024,
        65537,
        true,
        &mut n,
        &mut p,
    )
    .unwrap();
    assert_eq!(seeded.drbg, c_drbg);
    let mut modulus: RsaModulusBuffer = [0; _];
    assert_eq!(key.modulus(&mut modulus).unwrap().as_slice(), &n[..]);

    let public = RsaPublicKey::<Provider>::load(
        TpmiRsaKeyBits::Rsa1024,
        0,
        Tpm2bPublicKeyRsa::new(&n).unwrap(),
    )
    .unwrap()
    .unwrap();
    let mut tpm = started_tpm_rng();
    let label = c"label";
    for scheme in [
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha256,
            label: Some(label),
        },
        RsaEncryptScheme::Rsaes,
    ] {
        let mut ciphertext: RsaModulusBuffer = [0; _];
        let ciphertext = public
            .encrypt(&mut tpm, scheme, b"secret", &mut ciphertext)
            .unwrap()
            .unwrap();
        let mut plaintext: RsaModulusBuffer = [0; _];
        let plaintext = key
            .decrypt(&mut tpm, scheme, ciphertext.as_slice(), &mut plaintext)
            .unwrap()
            .unwrap();
        assert_eq!(plaintext.as_slice(), b"secret");
    }

    let digest = [0x5au8; 32];
    let mut signature: SignatureBuffer = [0; MAX_SIGNATURE_BYTES];
    let before = tpm.drbg;
    let signature = key
        .sign(
            &mut tpm,
            TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256),
            &digest,
            &mut signature,
        )
        .unwrap();
    // The salt was drawn from the TPM's DRBG.
    assert_ne!(tpm.drbg, before);
    assert!(public.verify(&digest, signature).unwrap());
}

/// [`crate::LinuxPlatform`] hands out the generator given to it once, then new ones.
#[test]
fn linux_platform_hands_out_its_crypto_rng_once() {
    use tpm2_engine::Platform;
    let (mut crypto, mut timer) = (Provider::new(), crate::LinuxTimer::new());
    let mut platform: crate::LinuxPlatform<
        '_,
        Provider,
        tpm2_engine::storage::ram_storage_mock::RamStorageMock<4096>,
    > = crate::LinuxPlatform::new(&mut crypto, &mut timer)
        .with_crypto_rng(ReferenceRng::from_seed(b"platform").unwrap());
    let first = platform.crypto_rng().unwrap();
    assert!(first.is_seeded());
    let second = platform.crypto_rng().unwrap();
    assert!(!second.is_seeded() && second.is_instantiated());
    platform.set_crypto_rng(started_tpm_rng());
    let mut third = platform.crypto_rng().unwrap();
    let mut out = [0u8; 40];
    third.fill_bytes(&mut out).unwrap();
    assert_eq!(out, STARTED_OUTPUT);
}
