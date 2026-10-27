//! Algorithm self tests (TPM 2.0 Part 1, "Self-Test Modes"; Part 3, "Testing"): which algorithms
//! `TPM2_IncrementalSelfTest` lists as untested after `_TPM_Init`, after the first use of an
//! algorithm (on-demand tests), after `TPM2_IncrementalSelfTest` and `TPM2_SelfTest`, and the
//! `testResult` of `TPM2_GetTestResult` (`TPM_RC_NEEDS_TEST` while an algorithm is untested).
//! In a differential build every `toDoList`, and every random value drawn after a test that draws
//! random values (RSAES, OAEP, RSASSA-PSS, ECDSA), is compared with the C reference.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

/// The algorithms that need a test after `_TPM_Init`, in ascending order: the implemented hashes,
/// AES with CFB, the RSA and ECC schemes that have a test, ECDH and KDFa.
fn initial_to_do_list() -> Vec<Alg> {
    let mut algs = vec![Alg::SHA1, Alg::AES, Alg::SHA256, Alg::SHA384];
    if TpmiAlgHash::try_from(Alg::SHA512).is_ok() {
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
    algs
}

/// The default test hash of the RSA, ECC and KDFa tests: SHA-512, or SHA-384 without SHA-512.
fn default_test_hash() -> Alg {
    if TpmiAlgHash::try_from(Alg::SHA512).is_ok() {
        Alg::SHA512
    } else {
        Alg::SHA384
    }
}

/// The `toDoList` (without testing anything).
fn to_do_list(sim: &mut Tpm) -> Vec<Alg> {
    incremental_self_test(sim, &[]).expect("TPM2_IncrementalSelfTest")
}

/// The `testResult` of `TPM2_GetTestResult` (whose `outData` is empty outside Failure mode).
fn test_result(sim: &mut Tpm) -> Result<(), TpmRc> {
    let rsp = sim.execute(GetTestResult {}).expect("TPM2_GetTestResult");
    assert_eq!(rsp.out_data.get_buffer(), &[] as &[u8]);
    rsp.test_result
}

/// `TPM2_SelfTest(fullTest)`.
fn self_test(sim: &mut Tpm, full_test: bool) {
    sim.execute(SelfTest { full_test }).expect("TPM2_SelfTest");
}

/// `TPM2_Hash` of a short message with `hash_alg`.
fn hash(sim: &mut Tpm, hash_alg: TpmiAlgHash) {
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"self test").unwrap(),
        hash_alg,
        hierarchy: Handle::RH_NULL,
    };
    sim.execute(cmd).expect("TPM2_Hash");
}

/// `initial_to_do_list()` without `removed`.
fn initial_without(removed: &[Alg]) -> Vec<Alg> {
    let mut algs = initial_to_do_list();
    algs.retain(|alg| !removed.contains(alg));
    algs
}

/// After `TPM2_Startup`, every testable implemented algorithm is untested, and `testResult` is
/// `TPM_RC_NEEDS_TEST`.
#[test]
fn startup_lists_every_testable_algorithm() {
    let mut sim = Tpm::new();
    assert_eq!(to_do_list(&mut sim), initial_to_do_list());
    assert_eq!(test_result(&mut sim), Err(TpmRc::NEEDS_TEST));
}

/// `TPM2_SelfTest(fullTest = NO)` tests every untested algorithm: the `toDoList` is empty and
/// `testResult` is `TPM_RC_SUCCESS`.
#[test]
fn partial_self_test_completes_every_test() {
    let mut sim = Tpm::new();
    self_test(&mut sim, false);
    assert_eq!(to_do_list(&mut sim), Vec::<Alg>::new());
    assert_eq!(test_result(&mut sim), Ok(()));
    // Nothing is left to test.
    self_test(&mut sim, false);
    assert_eq!(to_do_list(&mut sim), Vec::<Alg>::new());
}

/// `TPM2_SelfTest(fullTest = YES)` retests every algorithm, including those already tested and
/// the block cipher modes, and leaves nothing to test (no algorithm without a test stays listed).
#[test]
fn full_self_test_retests_and_completes() {
    let mut sim = Tpm::new();
    hash(&mut sim, TpmiAlgHash::Sha256);
    self_test(&mut sim, true);
    assert_eq!(to_do_list(&mut sim), Vec::<Alg>::new());
    assert_eq!(test_result(&mut sim), Ok(()));
    self_test(&mut sim, true);
    assert_eq!(to_do_list(&mut sim), Vec::<Alg>::new());
}

/// `_TPM_Init` makes every algorithm untested again.
#[test]
fn power_cycle_resets_the_tests() {
    let mut sim = Tpm::new();
    self_test(&mut sim, false);
    power_cycle_orderly(&mut sim, true);
    assert_eq!(to_do_list(&mut sim), initial_to_do_list());
    assert_eq!(test_result(&mut sim), Err(TpmRc::NEEDS_TEST));
}

/// The first hash computation with an algorithm tests that algorithm only.
#[test]
fn first_hash_tests_its_algorithm() {
    let mut sim = Tpm::new();
    hash(&mut sim, TpmiAlgHash::Sha256);
    assert_eq!(to_do_list(&mut sim), initial_without(&[Alg::SHA256]));
    hash(&mut sim, TpmiAlgHash::Sha1);
    assert_eq!(
        to_do_list(&mut sim),
        initial_without(&[Alg::SHA256, Alg::SHA1])
    );
}

/// A hash sequence and an event sequence test their hashes when they start.
#[test]
fn sequences_test_their_hashes_at_start() {
    let mut sim = Tpm::new();
    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha384),
    };
    sim.execute(cmd).expect("TPM2_HashSequenceStart");
    assert_eq!(to_do_list(&mut sim), initial_without(&[Alg::SHA384]));
    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: None,
    };
    sim.execute(cmd).expect("TPM2_HashSequenceStart (event)");
    let hashes = [Alg::SHA1, Alg::SHA256, Alg::SHA384, Alg::SHA512];
    assert_eq!(to_do_list(&mut sim), initial_without(&hashes));
}

/// `TPM2_IncrementalSelfTest` tests the requested algorithms and returns the rest; testing an
/// algorithm that has already been tested changes nothing.
#[test]
fn incremental_self_test_tests_the_requested_algorithms() {
    let mut sim = Tpm::new();
    let to_do = incremental_self_test(&mut sim, &[Alg::SHA1, Alg::ECDSA]).unwrap();
    // The ECDSA test also tests ECDH and its hash.
    let expected = initial_without(&[Alg::SHA1, Alg::ECDSA, Alg::ECDH, default_test_hash()]);
    assert_eq!(to_do, expected);
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::SHA1]).unwrap(),
        expected
    );
}

/// `TPM2_IncrementalSelfTest` of RSA runs the raw RSA test only (the RSA schemes stay untested);
/// of CFB alone, it marks AES as tested (every mode is then tested); of an algorithm without a
/// test (KEYEDHASH), nothing changes.
#[test]
fn incremental_self_test_of_umbrella_algorithms() {
    let mut sim = Tpm::new();
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::RSA, Alg::KEYEDHASH]).unwrap(),
        initial_to_do_list()
    );
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::CFB]).unwrap(),
        initial_without(&[Alg::AES, Alg::CFB])
    );
}

/// An unimplemented algorithm in `toTest` is `TPM_RC_VALUE + RC_P1`, and no requested algorithm
/// is tested.
#[test]
fn incremental_self_test_rejects_unimplemented_algorithms_before_testing() {
    let mut sim = Tpm::new();
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::SHA1, Alg::SHA3_256]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    assert_eq!(to_do_list(&mut sim), initial_to_do_list());
}

/// Creating an ECC key runs the ECDSA test first (which draws random values from the DRBG); the
/// key and every later random value match the reference.
#[test]
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
fn ecc_key_creation_tests_ecdsa() {
    let mut sim = Tpm::new();
    let key = create_primary_key_with_auth(&mut sim, b"");
    let to_do = to_do_list(&mut sim);
    for alg in [Alg::ECDSA, Alg::ECDH, default_test_hash()] {
        assert!(!to_do.contains(&alg), "{alg:?} untested in {to_do:?}");
    }
    for alg in [Alg::RSASSA, Alg::RSAES, Alg::RSAPSS, Alg::OAEP] {
        assert!(to_do.contains(&alg), "{alg:?} tested in {to_do:?}");
    }
    // Signing draws after the test.
    let digest = [0x5a; 32];
    let sign = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    execute_with_password_sessions(&mut sim, &sign, 1, &[]).expect("TPM2_Sign");
    assert_eq!(to_do_list(&mut sim), to_do);
}

/// RSA encryption tests its scheme (OAEP: also the OAEP hash; RSAES: no hash) before it draws
/// the padding, and the raw RSA scheme (`TPM_ALG_NULL`) needs no test of its own.
#[test]
fn rsa_encryption_tests_its_scheme() {
    let mut sim = Tpm::new();
    let key = create_primary_with_auth(&mut sim, rsa_decrypt_public(2048), b"");
    let before = to_do_list(&mut sim);
    let encrypt = |sim: &mut Tpm, in_scheme| {
        let cmd = RSAEncrypt {
            key_handle: key,
            message: Tpm2bPublicKeyRsa::from_bytes(&[0x11; 16]).unwrap(),
            in_scheme,
            label: Tpm2bData::default(),
        };
        sim.execute(cmd).expect("TPM2_RSA_Encrypt")
    };
    encrypt(&mut sim, Some(TpmtRsaDecrypt::Rsaes));
    let mut expected = before.clone();
    expected.retain(|&alg| alg != Alg::RSAES);
    assert_eq!(to_do_list(&mut sim), expected);
    encrypt(&mut sim, Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha1)));
    expected.retain(|&alg| alg != Alg::OAEP && alg != Alg::SHA1 && alg != default_test_hash());
    assert_eq!(to_do_list(&mut sim), expected);
    encrypt(&mut sim, None);
    assert_eq!(to_do_list(&mut sim), expected);
}

/// A failed RSA decryption still runs the scheme's test (the state of the self tests changes
/// regardless of the response code).
#[test]
fn failed_rsa_decryption_still_tests_the_scheme() {
    let mut sim = Tpm::new();
    let key = create_primary_with_auth(&mut sim, rsa_decrypt_public(2048), b"");
    let cmd = RSADecrypt {
        key_handle: key,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: Some(TpmtRsaDecrypt::Rsaes),
        label: Tpm2bData::default(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &cmd, 1, &[]).map(|_| ()),
        Err(TpmRc::VALUE.to_rc().get())
    );
    assert!(!to_do_list(&mut sim).contains(&Alg::RSAES));
}

/// Saving a context encrypts it with AES in CFB mode: the first use of AES tests it with the
/// modes to test, after which neither is listed.
#[test]
fn first_aes_use_tests_aes_and_cfb() {
    let mut sim = Tpm::new();
    let key = create_primary_key_with_auth(&mut sim, b"");
    assert!(to_do_list(&mut sim).contains(&Alg::AES));
    sim.execute(ContextSave { save_handle: key })
        .expect("TPM2_ContextSave");
    let to_do = to_do_list(&mut sim);
    assert!(!to_do.contains(&Alg::AES) && !to_do.contains(&Alg::CFB));
}

/// `testResult` becomes `TPM_RC_SUCCESS` once every algorithm has been tested on demand or by
/// `TPM2_IncrementalSelfTest`, without `TPM2_SelfTest`.
#[test]
fn test_result_succeeds_once_everything_is_tested() {
    let mut sim = Tpm::new();
    // Everything but AES and its modes (testing AES tests CFB too).
    let rest = initial_without(&[Alg::AES, Alg::CFB]);
    assert_eq!(
        incremental_self_test(&mut sim, &rest).unwrap(),
        vec![Alg::AES, Alg::CFB]
    );
    assert_eq!(test_result(&mut sim), Err(TpmRc::NEEDS_TEST));
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::AES]).unwrap(),
        Vec::<Alg>::new()
    );
    assert_eq!(test_result(&mut sim), Ok(()));
}

/// The modulus of an external RSA-2048 public key (only its size and top bit matter here).
const EXTERNAL_RSA_MODULUS: [u8; 256] = {
    let mut n = [0xc3; 256];
    n[255] = 0x01;
    n
};

/// The NIST P-256 generator: a valid external ECC public key.
const P256_GX: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_GY: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/// The attributes of the external keys (signing and decryption).
fn external_attributes() -> TpmaObject {
    TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH
}

/// Loads the external RSA-2048 public key (nameAlg SHA-256).
fn load_external_rsa(sim: &mut Tpm) -> Handle {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: external_attributes(),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&EXTERNAL_RSA_MODULUS).unwrap(),
        ),
    };
    load_external_public(sim, public)
}

/// Loads the P-256 generator as an external ECC public key (nameAlg SHA-256).
fn load_external_ecc(sim: &mut Tpm) -> Handle {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: external_attributes(),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&P256_GX).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&P256_GY).unwrap(),
            },
        ),
    };
    load_external_public(sim, public)
}

/// Checks the `toDoList` and draws random bytes, which (in a differential build) shows that the
/// DRBG is where the reference's is after the tests that ran.
fn check_after(sim: &mut Tpm, removed: &[Alg]) {
    assert_eq!(to_do_list(sim), initial_without(removed));
    sim.execute(GetRandom {
        bytes_requested: 32,
    })
    .expect("TPM2_GetRandom");
}

/// `TPM2_VerifySignature` with `signature` and the external key `key`: the signature is not
/// genuine, but the verification runs the scheme's self test.
#[allow(deprecated)] // TPM2_VerifySignature is deprecated upstream, but the TPM implements it.
fn verify_bad_signature(sim: &mut Tpm, key: Handle, signature: TpmtSignature<'static>) {
    let cmd = VerifySignature {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&[0x42; 32]).unwrap(),
        signature,
    };
    assert!(sim.execute(cmd).is_err());
}

/// The first RSASSA signature verification tests RSASSA (no random values, no hash).
#[test]
fn first_rsassa_verification_tests_rsassa() {
    let mut sim = Tpm::new();
    let key = load_external_rsa(&mut sim);
    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
    };
    verify_bad_signature(&mut sim, key, TpmtSignature::Rsassa(sig));
    check_after(&mut sim, &[Alg::SHA256, Alg::RSASSA]);
}

/// The first RSASSA-PSS signature verification (of a signature below the modulus) tests RSAPSS,
/// which draws a salt and tests the default test hash.
#[test]
fn first_rsapss_verification_tests_rsapss() {
    let mut sim = Tpm::new();
    let key = load_external_rsa(&mut sim);
    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
    };
    verify_bad_signature(&mut sim, key, TpmtSignature::Rsapss(sig));
    check_after(&mut sim, &[Alg::SHA256, Alg::RSAPSS, default_test_hash()]);
}

/// The first ECDSA signature verification (r and s in range) multiplies points, which tests ECDH
/// only (ECDSA is tested by signing).
#[test]
fn first_ecdsa_verification_tests_ecdh() {
    let mut sim = Tpm::new();
    let key = load_external_ecc(&mut sim);
    let sig = TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: Tpm2bEccParameter::from_bytes(&[0x01]).unwrap(),
        signature_s: Tpm2bEccParameter::from_bytes(&[0x01]).unwrap(),
    };
    verify_bad_signature(&mut sim, key, TpmtSignature::Ecdsa(sig));
    check_after(&mut sim, &[Alg::SHA256, Alg::ECDH]);
}

/// The first OAEP encryption tests OAEP (drawing a seed, with the default test hash) and hashes
/// with the OAEP hash.
#[test]
fn first_oaep_encryption_tests_oaep_and_its_hash() {
    let mut sim = Tpm::new();
    let key = load_external_rsa(&mut sim);
    let cmd = RSAEncrypt {
        key_handle: key,
        message: Tpm2bPublicKeyRsa::from_bytes(&[0x11; 16]).unwrap(),
        in_scheme: Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha384)),
        label: Tpm2bData::default(),
    };
    sim.execute(cmd).expect("TPM2_RSA_Encrypt");
    check_after(
        &mut sim,
        &[Alg::SHA256, Alg::OAEP, Alg::SHA384, default_test_hash()],
    );
}

/// `TPM2_ECDH_KeyGen` tests ECDH before it draws the ephemeral key.
#[test]
fn ecdh_key_generation_tests_ecdh() {
    let mut sim = Tpm::new();
    let key = load_external_ecc(&mut sim);
    sim.execute(ECDHKeyGen { key_handle: key })
        .expect("TPM2_ECDH_KeyGen");
    check_after(&mut sim, &[Alg::SHA256, Alg::ECDH]);
}

/// Creating an RSA key tests nothing of RSA (its raw RSA test is not listed); the first RSASSA
/// signature tests RSASSA.
#[test]
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
fn first_rsassa_signature_tests_rsassa() {
    let mut sim = Tpm::new();
    let key = create_primary_with_auth(
        &mut sim,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
        b"",
    );
    let before = to_do_list(&mut sim);
    for alg in [Alg::RSASSA, Alg::RSAES, Alg::RSAPSS, Alg::OAEP] {
        assert!(before.contains(&alg), "{alg:?} tested in {before:?}");
    }
    let sign = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&[0x5a; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    execute_with_password_sessions(&mut sim, &sign, 1, &[]).expect("TPM2_Sign");
    let mut expected = before;
    expected.retain(|&alg| alg != Alg::RSASSA);
    assert_eq!(to_do_list(&mut sim), expected);
    sim.execute(GetRandom {
        bytes_requested: 32,
    })
    .expect("TPM2_GetRandom");
}
