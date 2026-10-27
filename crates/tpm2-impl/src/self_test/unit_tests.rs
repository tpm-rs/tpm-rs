//! Unit tests of the algorithm self tests.

extern crate std;

use super::*;
use std::vec;
use std::vec::Vec;
#[cfg(feature = "dev_crypto_bssl")]
use tpm2_crypto_bssl::BsslCryptoProvider as Crypto;
#[cfg(feature = "dev_crypto_crux")]
use tpm2_crypto_crux::CruxCryptoProvider as Crypto;
#[cfg(feature = "dev_crypto_rust")]
use tpm2_crypto_rust::RustCryptoProvider as Crypto;

/// The IDs of `algs`.
fn ids(algs: &[Alg]) -> Vec<u16> {
    algs.iter().map(|alg| alg.id()).collect()
}

/// The algorithms that need a test after `_TPM_Init` (`CryptInitializeToTest()`), in ascending
/// order: the implemented hashes, AES and CFB (the other modes are tested with AES when
/// `TPM2_SelfTest(fullTest = YES)` asks for them), the RSA and ECC schemes with a test, ECDH (for
/// ECC) and KDFa. RSA itself is tested with raw RSA (`TPM_ALG_NULL`, which is not implemented and
/// so not listed), HMAC with the default test hash; the algorithms without a test are not listed.
fn initial_to_do_list() -> Vec<u16> {
    let mut algs = vec![Alg::SHA1, Alg::AES, Alg::SHA256, Alg::SHA384];
    if crate::handler::capability::sha512().is_some() {
        algs.push(Alg::SHA512);
    }
    algs.extend([
        Alg::RSASSA,
        Alg::RSAES,
        Alg::RSAPSS,
        Alg::OAEP,
        Alg::ECDSA,
        Alg::ECDH,
        Alg::KDF1_SP800_108,
        Alg::CFB,
    ]);
    ids(&algs)
}

/// Runs `f` with a self tester on the dev crypto provider and `state` (with the
/// `reference-rng` feature, with a DRBG instantiated from fixed entropy).
fn with_tester<T>(state: &SelfTestState, f: impl FnOnce(&mut SelfTester<'_, Crypto>) -> T) -> T {
    let crypto = Crypto;
    #[cfg(feature = "reference-rng")]
    {
        use crate::reference_rng::{RefRng, drbg};
        static ENTROPY: [u8; 64] = [0x5a; 64];
        let mut entropy = drbg::tests::FixedEntropy(&ENTROPY, 0);
        let mut drbg_state = crate::engine::DrbgState::default();
        drbg::instantiate(&mut RefRng {
            drbg: Some(&mut drbg_state),
            entropy: Some(&mut entropy),
        })
        .unwrap();
        let mut tester = SelfTester {
            crypto: Tested::new(&crypto, state),
            rng: Some(RefRng {
                drbg: Some(&mut drbg_state),
                entropy: Some(&mut entropy),
            }),
        };
        f(&mut tester)
    }
    #[cfg(not(feature = "reference-rng"))]
    {
        let mut tester = SelfTester {
            crypto: Tested::new(&crypto, state),
        };
        f(&mut tester)
    }
}

/// The algorithms that still need a test.
fn to_do(state: &SelfTestState) -> Vec<u16> {
    state.load().iter().collect()
}

/// `initial_to_do_list()` without `removed`.
fn initial_without(removed: &[u16]) -> Vec<u16> {
    let mut expected = initial_to_do_list();
    expected.retain(|alg| !removed.contains(alg));
    expected
}

/// After initialization, exactly the testable implemented algorithms need a test.
#[test]
fn initialization_lists_the_testable_algorithms() {
    let state = SelfTestState::default();
    assert_eq!(to_do(&state), initial_to_do_list());
    assert!(!state.failed());
    assert!(!state.all_tested());
}

/// `TPM2_SelfTest(fullTest = YES)` passes every known-answer test (on the dev crypto provider) and leaves
/// nothing to test; so does `fullTest = NO` from the initial state.
#[test]
fn full_and_partial_self_tests_pass_and_test_everything() {
    for full_test in [true, false] {
        let state = SelfTestState::default();
        with_tester(&state, |tester| tester.self_test(full_test)).unwrap();
        assert!(!state.failed());
        assert!(state.all_tested(), "left: {:?}", to_do(&state));
    }
}

/// The first use of AES tests it in the modes that need a test (CFB), which marks every mode as
/// tested.
#[test]
fn first_use_of_aes_tests_aes_and_its_modes() {
    let state = SelfTestState::default();
    with_tester(&state, |tester| tester.do_self_test(Alg::AES.id())).unwrap();
    assert_eq!(
        to_do(&state),
        initial_without(&[Alg::AES.id(), Alg::CFB.id()])
    );
}

/// The ECDSA test tests the default test hash and marks ECDH as tested (the reference's
/// `TestEccSignAndVerify()` clears it without a separate test).
#[test]
fn ecdsa_test_covers_ecdh_and_the_default_hash() {
    let state = SelfTestState::default();
    with_tester(&state, |tester| tester.do_self_test(Alg::ECDSA.id())).unwrap();
    assert_eq!(
        to_do(&state),
        initial_without(&[
            Alg::ECDSA.id(),
            Alg::ECDH.id(),
            Alg::from(default_test_hash()).id(),
        ])
    );
}

/// The RSASSA-PSS test also tests the default test hash (its encoding hashes), the RSASSA test
/// does not.
#[test]
fn rsa_signature_tests_and_the_default_hash() {
    let hash = Alg::from(default_test_hash()).id();
    let state = SelfTestState::default();
    with_tester(&state, |tester| tester.do_self_test(Alg::RSASSA.id())).unwrap();
    assert_eq!(to_do(&state), initial_without(&[Alg::RSASSA.id()]));
    with_tester(&state, |tester| tester.do_self_test(Alg::RSAPSS.id())).unwrap();
    assert_eq!(
        to_do(&state),
        initial_without(&[Alg::RSASSA.id(), Alg::RSAPSS.id(), hash])
    );
}

/// `TPM2_IncrementalSelfTest` of RSA runs only the raw RSA test: the RSA schemes stay untested.
#[test]
fn incremental_test_of_rsa_leaves_its_schemes_untested() {
    let state = SelfTestState::default();
    let mut to_test = AlgorithmVector::default();
    to_test.set(Alg::RSA.id());
    with_tester(&state, |tester| tester.run_self_tests(&mut to_test)).unwrap();
    assert!(to_test.is_empty());
    assert_eq!(to_do(&state), initial_to_do_list());
}

/// `TPM2_IncrementalSelfTest` of a mode without its block cipher marks AES as tested without a
/// test (the reference's `TestSymmetric()`: all modes are done).
#[test]
fn incremental_test_of_cfb_alone_marks_aes() {
    let state = SelfTestState::default();
    let mut to_test = AlgorithmVector::default();
    to_test.set(Alg::CFB.id());
    with_tester(&state, |tester| tester.run_self_tests(&mut to_test)).unwrap();
    assert_eq!(
        to_do(&state),
        initial_without(&[Alg::AES.id(), Alg::CFB.id()])
    );
}

/// The KDFa test also tests its hash (the default test hash) through the hooked HMAC.
#[test]
fn kdfa_test_tests_its_hash() {
    let state = SelfTestState::default();
    with_tester(&state, |tester| {
        tester.do_self_test(Alg::KDF1_SP800_108.id())
    })
    .unwrap();
    assert!(!state.needs_test(Alg::KDF1_SP800_108.id()));
    assert!(!state.needs_test(Alg::from(default_test_hash()).id()));
    assert!(state.needs_test(Alg::SHA256.id()));
}

/// A hash computation with the hooked provider tests the hash first.
#[test]
fn hooked_hash_tests_the_hash() {
    let state = SelfTestState::default();
    let crypto = Crypto;
    let tested = Tested::new(&crypto, &state);
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    tpm2::crypto::hash(&tested, TpmiAlgHash::Sha256, b"abc", &mut out).unwrap();
    assert!(!state.needs_test(Alg::SHA256.id()));
    assert!(state.needs_test(Alg::SHA1.id()));
}

/// Every test of a single algorithm passes on its own.
#[test]
fn every_single_test_passes() {
    for alg in initial_to_do_list() {
        let state = SelfTestState::default();
        with_tester(&state, |tester| tester.do_self_test(alg)).unwrap();
        assert!(!state.needs_test(alg), "{alg:#06x}");
        assert!(!state.failed(), "{alg:#06x}");
    }
}

/// `TPM2_SelfTest(fullTest = YES)` tests every mode with AES, and leaves no algorithm without a
/// test on the list (also those it set again, e.g. KEYEDHASH).
#[test]
fn full_self_test_after_partial_testing_empties_the_list() {
    let state = SelfTestState::default();
    with_tester(&state, |tester| {
        tester.do_self_test(Alg::SHA256.id())?;
        tester.self_test(true)
    })
    .unwrap();
    assert!(state.all_tested());
}

/// An [`AlgorithmVector`] stores its algorithms in ascending order and ignores IDs beyond
/// [`ALG_LAST`].
#[test]
fn algorithm_vector_bits() {
    let mut v = AlgorithmVector::default();
    assert!(v.is_empty());
    v.set(Alg::ECB.id());
    v.set(Alg::RSA.id());
    v.set(ALG_LAST + 1);
    assert_eq!(v.iter().collect::<Vec<_>>(), ids(&[Alg::RSA, Alg::ECB]));
    v.clear(Alg::RSA.id());
    assert!(!v.test(Alg::RSA.id()));
    assert!(!v.test(ALG_LAST + 1));
}
