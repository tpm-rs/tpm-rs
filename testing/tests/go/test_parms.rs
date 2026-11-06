#[cfg(not(all(feature = "rsa3072", feature = "rsa4096")))]
use crate::test_utils::{execute_test_parms_corrupted, put_u16};
use testing::tpm::Tpm;
use tpm2::TpmEccCurve;
use tpm2::commands::TestParms;
#[cfg(not(all(feature = "rsa3072", feature = "rsa4096")))]
use tpm2::errors::TpmRc;
use tpm2::{TpmiRsaKeyBits, TpmsEccParms, TpmsRsaParms, TpmtPublicParms};

// Original Go test: test_parms_test.go - TestTestParms/p256
#[test]
fn test_test_parms_p256() {
    let mut sim = Tpm::new();
    let cmd = TestParms {
        parameters: TpmtPublicParms::Ecc(TpmsEccParms {
            symmetric: None,
            scheme: None,
            curve_id: TpmEccCurve::NistP256,
            kdf: None,
        }),
    };
    sim.execute(cmd).unwrap();
}

// Original Go test: test_parms_test.go - TestTestParms/p364
#[test]
fn test_test_parms_p364() {
    let mut sim = Tpm::new();
    let cmd = TestParms {
        parameters: TpmtPublicParms::Ecc(TpmsEccParms {
            symmetric: None,
            scheme: None,
            curve_id: TpmEccCurve::NistP384,
            kdf: None,
        }),
    };
    sim.execute(cmd).unwrap();
}

// Original Go test: test_parms_test.go - TestTestParms/p521
#[test]
fn test_test_parms_p521() {
    let mut sim = Tpm::new();
    let cmd = TestParms {
        parameters: TpmtPublicParms::Ecc(TpmsEccParms {
            symmetric: None,
            scheme: None,
            curve_id: TpmEccCurve::NistP521,
            kdf: None,
        }),
    };
    sim.execute(cmd).unwrap();
}

// Original Go test: test_parms_test.go - TestTestParms/rsa2048
#[test]
fn test_test_parms_rsa2048() {
    let mut sim = Tpm::new();
    let cmd = TestParms {
        parameters: TpmtPublicParms::Rsa(TpmsRsaParms {
            symmetric: None,
            scheme: None,
            key_bits: TpmiRsaKeyBits::Rsa2048,
            exponent: 0,
        }),
    };
    sim.execute(cmd).unwrap();
}

// Only without the `rsa3072` feature; with it, RSA-3072 is a key size of the profile.
#[cfg(not(feature = "rsa3072"))]
// Original Go test: test_parms_test.go - TestTestParms/rsa3072 - unsupported
#[test]
fn test_test_parms_rsa3072_unsupported() {
    let mut sim = Tpm::new();
    // RSA-3072 is not a `TPMI_RSA_KEY_BITS` value of this build, so the key size is patched
    // into the marshaled parameters (keyBits follows the type and the two NULL selectors).
    let parameters = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 0,
    });
    let err = execute_test_parms_corrupted(&mut sim, parameters, |buf| {
        put_u16(buf, 6, 3072);
    })
    .unwrap_err();
    // Go: errors.Is(err, TPMRCValue), which compares the canonical format-one
    // code and ignores the handle/session/parameter position.
    let rc = TpmRc::new(err).expect("a TPM error");
    assert_eq!(rc.to_fmt1().map(|(rc, _)| rc), Some(TpmRc::VALUE));
}

// Only without the `rsa4096` feature; with it, RSA-4096 is a key size of the profile.
#[cfg(not(feature = "rsa4096"))]
// Original Go test: test_parms_test.go - TestTestParms/rsa4096 - unsupported
#[test]
fn test_test_parms_rsa4096_unsupported() {
    let mut sim = Tpm::new();
    // RSA-4096 is not a `TPMI_RSA_KEY_BITS` value of this build, so the key size is patched
    // into the marshaled parameters (keyBits follows the type and the two NULL selectors).
    let parameters = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 0,
    });
    let err = execute_test_parms_corrupted(&mut sim, parameters, |buf| {
        put_u16(buf, 6, 4096);
    })
    .unwrap_err();
    // Go: errors.Is(err, TPMRCValue), which compares the canonical format-one
    // code and ignores the handle/session/parameter position.
    let rc = TpmRc::new(err).expect("a TPM error");
    assert_eq!(rc.to_fmt1().map(|(rc, _)| rc), Some(TpmRc::VALUE));
}
