//! Algorithm self tests (TPM 2.0 Part 1, "Self-Test Modes"; Part 3, "Testing").
//!
//! The TPM keeps the set of algorithms that still need a test (`g_toTest` of the TCG reference
//! implementation, [`SelfTestState`]). It is initialized at manufacture and on every `_TPM_Init`
//! to the implemented algorithms that have a test ([`SelfTestState::initialize`]) and is changed
//! only by testing, regardless of the outcome of the command that runs the test (Part 1, "Command
//! Dispatch": "an implicit self test invoked to test an algorithm required by the command can mark
//! the algorithm as tested").
//!
//! Testing is synchronous: a command that requires an untested algorithm tests it first ("If a
//! command requires use of an untested algorithm or functional module, the TPM performs the test
//! and then completes the command actions", Part 1), `TPM2_SelfTest` and
//! `TPM2_IncrementalSelfTest` complete the requested tests before they return, so `TPM_RC_TESTING`
//! is never returned (Part 3, TPM2_SelfTest, option b). Where the specification leaves it open,
//! which algorithm uses trigger which test, the order of the tests, the test vectors and which
//! algorithms are "testable" follow the TCG reference implementation (`AlgorithmTests.c`,
//! `CryptSelfTest.c`, `TPM_DO_SELF_TEST()`), so that every response is identical, including the
//! random values drawn after a test that draws random values (the RSAES, OAEP and RSASSA-PSS
//! encryption/signing tests and the ECDSA signing test draw from the TPM's DRBG).
//!
//! The tests run when:
//! - a hash or HMAC computation starts with an untested hash algorithm, a KDFa derivation starts,
//!   a symmetric encryption or decryption uses an untested block cipher, or an ECC point
//!   multiplication runs ([`Tested`], the hooked crypto provider of the engine, see
//!   [`crate::engine::TpmEngine::crypto`]);
//! - an RSA encryption, decryption, signature or signature verification uses an untested scheme,
//!   an ECC key is generated or an ECDSA signature is computed (explicit
//!   [`crate::engine::TpmEngine::self_test`] calls at the counterparts of the reference's
//!   `CryptRsaEncrypt()`, `CryptRsaDecrypt()`, `CryptRsaSign()`, `CryptRsaValidateSignature()`,
//!   `CryptEccGenerateKey()` and `CryptEccSign()`), and for the hashes that the reference's RSA
//!   encodings compute;
//! - `TPM2_SelfTest` and `TPM2_IncrementalSelfTest` request them.
//!
//! A failed test puts the TPM into Failure mode ([`SelfTestState::failed`]).

mod algorithm_tests;
mod tested;
pub(crate) mod vectors;

pub(crate) use algorithm_tests::SelfTester;
pub use tested::Tested;
pub use tested::kdfa_bits;

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::TpmRc;
use tpm2::{Alg, TpmiAlgHash};

use crate::engine::TpmEngine;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;

/// `TPM_ALG_FIRST`: the first algorithm ID that is tested (`TPM_ALG_RSA`).
pub const ALG_FIRST: u16 = 0x0001;
/// `TPM_ALG_LAST`: the last algorithm ID tracked by an [`AlgorithmVector`]. It covers every
/// algorithm ID below the reserved range `0x00C1..=0x00C6` (all algorithms this TPM can
/// implement); the tests iterate over the IDs in ascending order, as the reference does.
pub const ALG_LAST: u16 = 0x00C0;
/// `ALGORITHM_VECTOR_BYTES`: one bit per algorithm ID `0..=ALG_LAST`.
const VECTOR_BYTES: usize = (ALG_LAST as usize + 8) / 8;

/// `MAX_ALG_LIST_SIZE`: the capacity of a `TPML_ALG` (the `toDoList`).
pub(crate) const MAX_ALG_LIST_SIZE: usize = 64;

/// `FATAL_ERROR_SELF_TEST`: the failure code of a failed self test (`TPM2_GetTestResult` in
/// Failure mode).
pub(crate) const FATAL_ERROR_SELF_TEST: u32 = 6;

/// `ALGORITHM_VECTOR`: a set of algorithm IDs (one bit per ID up to [`ALG_LAST`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AlgorithmVector([u8; VECTOR_BYTES]);

impl AlgorithmVector {
    /// `TEST_BIT(alg, vector)`.
    pub fn test(&self, alg: u16) -> bool {
        let i = usize::from(alg);
        i <= usize::from(ALG_LAST) && self.0[i / 8] & (1 << (i % 8)) != 0
    }

    /// `SET_BIT(alg, vector)`; IDs above [`ALG_LAST`] are ignored.
    pub fn set(&mut self, alg: u16) {
        let i = usize::from(alg);
        if i <= usize::from(ALG_LAST) {
            self.0[i / 8] |= 1 << (i % 8);
        }
    }

    /// `CLEAR_BIT(alg, vector)`.
    pub fn clear(&mut self, alg: u16) {
        let i = usize::from(alg);
        if i <= usize::from(ALG_LAST) {
            self.0[i / 8] &= !(1 << (i % 8));
        }
    }

    /// Whether no bit is set.
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// The algorithm IDs in the set, in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        (0..=ALG_LAST).filter(|&alg| self.test(alg))
    }

    /// `g_implementedAlgorithms` (`AlgorithmGetImplementedVector()`): the algorithms of
    /// `TPM_CAP_ALGS`.
    pub fn implemented() -> Self {
        let mut v = Self::default();
        for alg in ALG_FIRST..=ALG_LAST {
            if is_implemented(alg) {
                v.set(alg);
            }
        }
        v
    }
}

/// Whether `alg` is an implemented algorithm (`TEST_BIT(alg, g_implementedAlgorithms)`).
pub(crate) fn is_implemented(alg: u16) -> bool {
    // `Alg::new` rejects the reserved IDs, which are never implemented.
    alg != 0
        && !(0x00C1..=0x00C6).contains(&alg)
        && alg < 0x8000
        && crate::handler::capability::is_implemented_algorithm(Alg::new(alg))
}

/// `DEFAULT_TEST_HASH`: the hash algorithm of the tests that need one (and of the HMAC test):
/// SHA-512, or SHA-384 in a TPM without SHA-512.
pub(crate) fn default_test_hash() -> TpmiAlgHash {
    crate::handler::capability::sha512().unwrap_or(TpmiAlgHash::Sha384)
}

/// The self-test state of the TPM: `g_toTest` (the algorithms that still need a test) and whether
/// a test has failed (Failure mode, until the next `_TPM_Init`).
///
/// It is shared by the hooked crypto provider ([`Tested`]), which runs the tests of the
/// algorithms it is used with through a shared reference, so its fields are atomics (only loads
/// and stores are used).
pub struct SelfTestState {
    to_test: [AtomicU8; VECTOR_BYTES],
    failed: AtomicBool,
}

impl Default for SelfTestState {
    /// A state initialized as at `_TPM_Init` ([`Self::initialize`]).
    fn default() -> Self {
        let state = Self {
            to_test: [const { AtomicU8::new(0) }; VECTOR_BYTES],
            failed: AtomicBool::new(false),
        };
        state.initialize();
        state
    }
}

impl Clone for SelfTestState {
    fn clone(&self) -> Self {
        let state = Self {
            to_test: [const { AtomicU8::new(0) }; VECTOR_BYTES],
            failed: AtomicBool::new(self.failed()),
        };
        state.store(&self.load());
        state
    }
}

impl core::fmt::Debug for SelfTestState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SelfTestState")
            .field("to_test", &self.load())
            .field("failed", &self.failed())
            .finish()
    }
}

impl SelfTestState {
    /// `CryptInitializeToTest()` (`CryptInit()`, at manufacture and on every `_TPM_Init`): every
    /// implemented algorithm that has a test needs one, and no test has failed (Failure mode
    /// ends at `_TPM_Init`).
    pub fn initialize(&self) {
        self.store(&AlgorithmVector::implemented());
        self.failed.store(false, Ordering::Relaxed);
        // `TestAlgorithm(TPM_ALG_ERROR, &g_toTest)`: clears the algorithms that have no test.
        algorithm_tests::clear_untestable(self);
    }

    /// A copy of `g_toTest`.
    pub fn load(&self) -> AlgorithmVector {
        let mut v = AlgorithmVector::default();
        for (byte, bits) in v.0.iter_mut().zip(&self.to_test) {
            *byte = bits.load(Ordering::Relaxed);
        }
        v
    }

    /// Replaces `g_toTest` with `v`.
    pub fn store(&self, v: &AlgorithmVector) {
        for (bits, byte) in self.to_test.iter().zip(&v.0) {
            bits.store(*byte, Ordering::Relaxed);
        }
    }

    /// Whether `alg` still needs a test (`TEST_BIT(alg, g_toTest)`).
    pub fn needs_test(&self, alg: u16) -> bool {
        let i = usize::from(alg);
        i <= usize::from(ALG_LAST)
            && self.to_test[i / 8].load(Ordering::Relaxed) & (1 << (i % 8)) != 0
    }

    fn update(&self, alg: u16, set: bool) {
        let i = usize::from(alg);
        if i <= usize::from(ALG_LAST) {
            let bits = &self.to_test[i / 8];
            let old = bits.load(Ordering::Relaxed);
            let new = if set {
                old | (1 << (i % 8))
            } else {
                old & !(1 << (i % 8))
            };
            bits.store(new, Ordering::Relaxed);
        }
    }

    /// Whether every algorithm has been tested (`g_toTest` is empty).
    pub fn all_tested(&self) -> bool {
        self.to_test.iter().all(|b| b.load(Ordering::Relaxed) == 0)
    }

    /// Whether a self test has failed since the last `_TPM_Init` (the TPM is in Failure mode).
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    /// Records a failed self test (`SELF_TEST_FAILURE`): the TPM enters Failure mode.
    pub fn fail(&self) {
        self.failed.store(true, Ordering::Relaxed);
    }
}

impl<'a, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync> TpmEngine<'a, C, S, T, R> {
    /// The crypto provider with the on-demand self tests of the algorithms it is used with
    /// ([`Tested`]). Every cryptographic operation of the engine and the command handlers uses
    /// it.
    pub fn crypto(&self) -> Tested<'_, C> {
        Tested::new(&*self.platform.crypto, &self.self_test)
    }

    /// The runner of the algorithm self tests, with the TPM's DRBG for the tests that draw random
    /// values.
    pub(crate) fn self_tester(&mut self) -> SelfTester<'_, C> {
        SelfTester {
            crypto: Tested::new(&*self.platform.crypto, &self.self_test),
            #[cfg(feature = "reference-rng")]
            rng: Some(crate::reference_rng::RefRng {
                drbg: Some(&mut self.state.drbg_state),
                entropy: Some(&mut *self.platform.rng),
            }),
        }
    }

    /// The hash self tests of the start of a sequence of `sequence_type` (the reference's
    /// `CryptHashStart()`/`CryptHmacStart()` calls in `ObjectCreateHashSequence()`,
    /// `ObjectCreateHMACSequence()` and `ObjectCreateEventSequence()`, the last one for every
    /// implemented hash). The sequences hash with the engine's own streaming hash state
    /// ([`crate::hash_state`]), which the hooked crypto provider does not see.
    pub(crate) fn self_test_sequence_start(
        &self,
        sequence_type: &crate::SequenceType,
    ) -> Result<(), TpmRc> {
        let crypto = self.crypto();
        let test = |hash: TpmiAlgHash| {
            crypto
                .do_self_test(Alg::from(hash))
                .map_err(|_| TpmRc::FAILURE)
        };
        match sequence_type {
            crate::SequenceType::Hash { alg } => test(*alg),
            crate::SequenceType::Hmac { hash_alg, .. } => test(*hash_alg),
            crate::SequenceType::Event => {
                for alg in [Alg::SHA1, Alg::SHA256, Alg::SHA384, Alg::SHA512] {
                    if let Ok(hash) = TpmiAlgHash::try_from(alg) {
                        test(hash)?;
                    }
                }
                Ok(())
            }
        }
    }

    /// `TPM_DO_SELF_TEST(alg)`: tests `alg` if it still needs a test, for the operations the
    /// hooked crypto provider ([`Self::crypto`]) cannot see (RSA encryption, decryption,
    /// signatures and signature verification, ECC key generation, ECDSA signatures, and the
    /// hashes computed inside the RSA encodings). Fails with `TPM_RC_FAILURE` (Failure mode) if
    /// the test fails.
    pub(crate) fn do_self_test(&mut self, alg: Alg) -> Result<(), TpmRc> {
        if self.self_test.needs_test(alg.id()) {
            self.self_tester().do_self_test(alg.id())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests;
