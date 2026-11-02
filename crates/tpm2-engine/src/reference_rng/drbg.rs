//! The C reference TPMs' CTR-DRBG (`CryptRand.c` of the TCG reference implementation, the same
//! as `ibmswtpm2`'s), linked from the original C code.
//!
//! The DRBG is the SP 800-90A CTR_DRBG with AES-256 and a derivation function, with the reference
//! code's implementation-specific details (the layout of the derivation-function state, the FIPS
//! continuous self-test, the reseed interval and the request size limit):
//!
//! - [`instantiate`] / [`startup`] / [`reseed`] / [`stir`] operate on the TPM's own DRBG
//!   (`drbgDefault`, kept in `go.drbgState`, [`RefRng::drbg`]), whose entropy comes from the
//!   platform ([`RefRng::entropy`], i.e. `DRBG_GetEntropy()` collecting `_plat__GetEntropy()`
//!   output);
//! - [`instantiate_seeded`] creates the deterministic DRBG used for Primary Objects
//!   (`DRBG_InstantiateSeeded()`), and [`additional_data`] mixes data into it;
//! - [`generate`] / [`fill`] draw from either (`DRBG_Generate()`).
//!
//! The reference's KDF-based `RAND_STATE` (`DRBG_InstantiateSeededKdf()`, for Derived Objects)
//! is not exposed: `tpm-rs` derives those objects itself.

use tpm2::errors::TpmRc;

use super::{RefRng, ffi};
use crate::engine::DrbgState;

/// Size of a DRBG seed (`DRBG_SEED`): an AES-256 key followed by a counter block.
pub const DRBG_SEED_SIZE: usize = 48;
/// `CTR_DRBG_MAX_REQUESTS_PER_RESEED`: the TPM's DRBG reseeds itself after this many requests,
/// a seeded DRBG fails.
pub const CTR_DRBG_MAX_REQUESTS_PER_RESEED: u64 = 1 << 20;

/// A DRBG seed (`DRBG_SEED`).
pub type DrbgSeed = [u8; DRBG_SEED_SIZE];

/// `DRBG_Instantiate(&drbgDefault, 0, NULL)`: instantiates the TPM's DRBG from fresh platform
/// entropy (after running the DRBG self-test once per thread, as the reference does once).
pub fn instantiate(rng: &mut RefRng<'_>) -> Result<(), TpmRc> {
    ffi::instantiate(rng)
}

/// `CryptRandStartup()` with `_DRBG_STATE_SAVE`: reseeds the TPM's DRBG with fresh platform
/// entropy if it is instantiated (restored from NV), and instantiates it otherwise.
pub fn startup(rng: &mut RefRng<'_>) -> Result<(), TpmRc> {
    ffi::startup(rng)
}

/// `DRBG_Reseed()`: reseeds `rand` (`None`: the TPM's DRBG) with `provided_entropy` (or fresh
/// platform entropy if `None`) XORed with `additional`.
pub fn reseed(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    provided_entropy: Option<&DrbgSeed>,
    additional: Option<&DrbgSeed>,
) -> Result<(), TpmRc> {
    ffi::reseed(rng, rand, provided_entropy, additional)
}

/// `CryptRandomStir()` (`TPM2_StirRandom`): reseeds the TPM's DRBG with fresh entropy and the
/// derivation of `additional_data`.
pub fn stir(rng: &mut RefRng<'_>, additional_data: &[u8]) -> Result<(), TpmRc> {
    ffi::stir(rng, additional_data)
}

/// `DRBG_Generate()`: fills a prefix of `out` from `rand` (`None`: the TPM's DRBG) and returns
/// its length.
///
/// The TPM's DRBG reseeds itself from the platform after [`CTR_DRBG_MAX_REQUESTS_PER_RESEED`]
/// requests; for a seeded DRBG, running out of requests is a failure. As in the reference, an
/// empty request still updates the state and counts as a request. At most `u16::MAX` bytes are
/// produced per call (the reference's `UINT16` request size).
pub fn generate(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    out: &mut [u8],
) -> Result<usize, TpmRc> {
    ffi::generate(rng, rand, out)
}

/// [`generate`] that fails unless all of `out` was filled (the callers of `DRBG_Generate()`
/// treat a short result as a failure).
pub fn fill(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    out: &mut [u8],
) -> Result<(), TpmRc> {
    if generate(rng, rand, out)? == out.len() {
        Ok(())
    } else {
        Err(TpmRc::FAILURE)
    }
}

/// `DRBG_InstantiateSeeded()`: a deterministic DRBG seeded from the derivation of
/// `seed || purpose || name || additional` (each at most 1024 bytes).
pub fn instantiate_seeded(
    seed: &[u8],
    purpose: &[u8],
    name: &[u8],
    additional: &[u8],
) -> Result<DrbgState, TpmRc> {
    ffi::instantiate_seeded(seed, purpose, name, additional)
}

/// `DRBG_AdditionalData()`: reseeds an instantiated DRBG with the derivation of `data` (no
/// entropy; a no-op on an uninstantiated state). Used to mix the endorsement hierarchy proofs
/// into the DRBG of an endorsement Primary Object.
pub fn additional_data(state: &mut DrbgState, data: &[u8]) -> Result<(), TpmRc> {
    ffi::additional_data(state, data)
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use crate::engine::DRBG_MAGIC;
    use tpm2::crypto::{CryptoError, Rng};

    /// The NIST CTR_DRBG AES-256 test vector (no derivation function, no prediction
    /// resistance, COUNT = 0) used by the reference code's `DRBG_SelfTest()`
    /// (`PRNG_TestVectors.h`): entropy input followed by the nonce.
    const NIST_ENTROPY: [u8; 48] = hex_literal::hex!(
        "0d15aa80b16c3a10906cfedb795dae0b5b81041c5c5bfacb373d4440d9120f7e"
        "3d6cf90986cf52d85d3e947d8c061f91"
    );
    /// `EntropyInputReseed`.
    const NIST_RESEED_ENTROPY: [u8; 48] = hex_literal::hex!(
        "6ee793a33955d72ad12fd80a8a3fcf95ed3b4dac5795fe25cf869f7c27573bbc"
        "56f1acae13a65042b340093c464a7a22"
    );
    /// `INTERMEDIATE ReturnedBits`.
    const NIST_GENERATED_INTERM: [u8; 16] = hex_literal::hex!("28e0ebb8210166508c8f65f2207bd0a3");
    /// `ReturnedBits`.
    const NIST_GENERATED: [u8; 16] = hex_literal::hex!("946f5182d54510b9461248f571ca06c9");

    /// An entropy source replaying fixed bytes (cycling), counting the bytes drawn.
    pub(crate) struct FixedEntropy(pub &'static [u8], pub usize);

    impl Rng for FixedEntropy {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
            for d in dest.iter_mut() {
                *d = self.0[self.1 % self.0.len()];
                self.1 += 1;
            }
            Ok(())
        }

        fn reseed(&mut self, _: &[u8]) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    /// An entropy source that always fails.
    struct FailingEntropy;

    impl Rng for FailingEntropy {
        fn fill_bytes(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::Internal)
        }

        fn reseed(&mut self, _: &[u8]) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    /// The TPM's DRBG `state` with the entropy source `entropy`.
    fn tpm<'a>(state: &'a mut DrbgState, entropy: &'a mut dyn Rng) -> RefRng<'a> {
        RefRng {
            drbg: Some(state),
            entropy: Some(entropy),
        }
    }

    /// Replays `DRBG_SelfTest()` through the linked C DRBG.
    #[test]
    fn nist_self_test_vector() {
        let mut state = DrbgState::default();
        let mut entropy = FixedEntropy(&NIST_ENTROPY, 0);
        {
            let mut rng = tpm(&mut state, &mut entropy);
            instantiate(&mut rng).unwrap();
            let mut buf = [0u8; 16];
            fill(&mut rng, None, &mut buf).unwrap();
            assert_eq!(buf, NIST_GENERATED_INTERM);
            reseed(&mut rng, None, Some(&NIST_RESEED_ENTROPY), None).unwrap();
            fill(&mut rng, None, &mut buf).unwrap();
            assert_eq!(buf, NIST_GENERATED);
        }
        // Instantiation drew exactly one seed of platform entropy.
        assert_eq!(entropy.1, DRBG_SEED_SIZE);
    }

    #[test]
    fn generate_requires_instantiation_and_counts_requests() {
        let mut state = DrbgState::default();
        let mut entropy = FixedEntropy(&NIST_ENTROPY, 0);
        let mut out = [0u8; 20];
        // An uninstantiated DRBG cannot generate.
        assert_eq!(
            generate(&mut tpm(&mut state, &mut entropy), None, &mut out),
            Err(TpmRc::FAILURE)
        );
        instantiate(&mut tpm(&mut state, &mut entropy)).unwrap();
        assert_eq!(state.magic, DRBG_MAGIC);
        assert_eq!(state.reseed_counter, 1);
        assert_eq!(
            generate(&mut tpm(&mut state, &mut entropy), None, &mut out),
            Ok(20)
        );
        assert_eq!(state.reseed_counter, 2);

        // A seeded DRBG cannot reseed itself.
        let mut seeded = state;
        seeded.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        assert_eq!(
            generate(&mut RefRng::seeded_only(), Some(&mut seeded), &mut out),
            Err(TpmRc::FAILURE)
        );
        // The TPM's DRBG reseeds itself from the platform.
        state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        let drawn = entropy.1;
        generate(&mut tpm(&mut state, &mut entropy), None, &mut out).unwrap();
        assert_eq!(state.reseed_counter, 2);
        assert_eq!(entropy.1, drawn + DRBG_SEED_SIZE);
    }

    #[test]
    fn zero_length_generate_still_counts_and_updates() {
        let mut state = instantiate_seeded(b"seed", b"purpose\0", b"", b"").unwrap();
        let before = state;
        assert_eq!(
            generate(&mut RefRng::seeded_only(), Some(&mut state), &mut []),
            Ok(0)
        );
        assert_eq!(state.reseed_counter, before.reseed_counter + 1);
        assert_ne!(state.seed, before.seed);
        fill(&mut RefRng::seeded_only(), Some(&mut state), &mut []).unwrap();
        assert_eq!(state.reseed_counter, before.reseed_counter + 2);
    }

    #[test]
    fn seeded_drbg_is_deterministic() {
        let draw = |seed: &[u8]| {
            let mut st = instantiate_seeded(seed, b"purpose\0", b"name", b"").unwrap();
            assert_eq!(st.magic, DRBG_MAGIC);
            assert_eq!(st.reseed_counter, 1);
            let mut out = [0u8; 40];
            fill(&mut RefRng::seeded_only(), Some(&mut st), &mut out).unwrap();
            out
        };
        assert_eq!(draw(b"seed"), draw(b"seed"));
        assert_ne!(draw(b"seed"), draw(b"Seed"));
        // The inputs are concatenated before the derivation.
        let a = instantiate_seeded(b"ab", b"c", b"", b"").unwrap();
        let b = instantiate_seeded(b"a", b"bc", b"", b"").unwrap();
        assert_eq!(a, b);
        // Inputs beyond the API limit are rejected.
        assert_eq!(
            instantiate_seeded(&[0; 1025], b"", b"", b""),
            Err(TpmRc::SIZE.to_rc())
        );
    }

    #[test]
    fn entropy_failure_fails_instantiation_and_reseeding() {
        let mut state = DrbgState::default();
        assert_eq!(
            instantiate(&mut tpm(&mut state, &mut FailingEntropy)),
            Err(TpmRc::FAILURE)
        );
        let mut no_entropy = RefRng {
            drbg: Some(&mut state),
            entropy: None,
        };
        assert_eq!(instantiate(&mut no_entropy), Err(TpmRc::FAILURE));
        // A working source after a failure works again (failure mode lasts one call).
        instantiate(&mut tpm(&mut state, &mut FixedEntropy(&NIST_ENTROPY, 0))).unwrap();
        assert_eq!(
            reseed(&mut tpm(&mut state, &mut FailingEntropy), None, None, None),
            Err(TpmRc::FAILURE)
        );
        assert_eq!(
            stir(&mut tpm(&mut state, &mut FailingEntropy), b"data"),
            Err(TpmRc::NO_RESULT)
        );
        // Without a TPM DRBG, drawing from it fails.
        assert_eq!(
            generate(&mut RefRng::seeded_only(), None, &mut [0; 4]),
            Err(TpmRc::FAILURE)
        );
    }

    #[test]
    fn startup_reseeds_an_instantiated_drbg_and_instantiates_otherwise() {
        let mut entropy = FixedEntropy(&NIST_ENTROPY, 0);
        let mut fresh = DrbgState::default();
        startup(&mut tpm(&mut fresh, &mut entropy)).unwrap();
        let mut instantiated = DrbgState::default();
        instantiate(&mut tpm(
            &mut instantiated,
            &mut FixedEntropy(&NIST_ENTROPY, 0),
        ))
        .unwrap();
        assert_eq!(fresh, instantiated);

        fill(&mut tpm(&mut fresh, &mut entropy), None, &mut [0; 8]).unwrap();
        let before = fresh;
        startup(&mut tpm(&mut fresh, &mut entropy)).unwrap();
        assert_eq!(fresh.reseed_counter, 1);
        assert_ne!(fresh.seed, before.seed);
        assert_eq!(entropy.1, 2 * DRBG_SEED_SIZE);
    }

    #[test]
    fn stir_and_additional_data_reseed() {
        let mut entropy = FixedEntropy(&NIST_RESEED_ENTROPY, 0);
        let mut state = DrbgState::default();
        instantiate(&mut tpm(&mut state, &mut entropy)).unwrap();
        fill(&mut tpm(&mut state, &mut entropy), None, &mut [0; 8]).unwrap();
        let before = state;
        stir(&mut tpm(&mut state, &mut entropy), b"stir").unwrap();
        assert_eq!(state.reseed_counter, 1);
        assert_ne!(state.seed, before.seed);

        // The derivation of the data is mixed in deterministically.
        let mut a = instantiate_seeded(b"seed", b"", b"", b"").unwrap();
        let mut b = a;
        additional_data(&mut a, b"proof").unwrap();
        additional_data(&mut b, b"proof").unwrap();
        assert_eq!(a, b);
        let mut c = instantiate_seeded(b"seed", b"", b"", b"").unwrap();
        additional_data(&mut c, b"other").unwrap();
        assert_ne!(a, c);
        // A no-op on an uninstantiated state.
        let mut empty = DrbgState::default();
        additional_data(&mut empty, b"proof").unwrap();
        assert_eq!(empty, DrbgState::default());
    }

    /// An entropy source that calls back into the reference RNG, which must be rejected.
    struct ReentrantEntropy(Option<Result<DrbgState, TpmRc>>);

    impl Rng for ReentrantEntropy {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
            self.0 = Some(instantiate_seeded(b"seed", b"", b"", b""));
            dest.fill(0x5a);
            Ok(())
        }

        fn reseed(&mut self, _: &[u8]) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    #[test]
    fn reentrant_calls_from_the_entropy_source_fail() {
        let mut state = DrbgState::default();
        let mut entropy = ReentrantEntropy(None);
        instantiate(&mut tpm(&mut state, &mut entropy)).unwrap();
        assert_eq!(entropy.0, Some(Err(TpmRc::FAILURE)));
        assert_eq!(state.magic, DRBG_MAGIC);
        // The library is usable again after the call.
        instantiate_seeded(b"seed", b"", b"", b"").unwrap();
    }

    #[test]
    fn threads_draw_independently() {
        let expected = {
            let mut st = instantiate_seeded(b"thread", b"", b"", b"").unwrap();
            let mut out = [0u8; 64];
            fill(&mut RefRng::seeded_only(), Some(&mut st), &mut out).unwrap();
            out
        };
        let handles: std::vec::Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    let mut entropy = FixedEntropy(&NIST_ENTROPY, i);
                    let mut tpm_state = DrbgState::default();
                    let mut out = [0u8; 64];
                    for _ in 0..50 {
                        instantiate(&mut tpm(&mut tpm_state, &mut entropy)).unwrap();
                        let mut st = instantiate_seeded(b"thread", b"", b"", b"").unwrap();
                        fill(&mut RefRng::seeded_only(), Some(&mut st), &mut out).unwrap();
                        assert_eq!(out, expected);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
