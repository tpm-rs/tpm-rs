use tpm2::TpmEccCurve;
use tpm2::commands::TestParms;
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmiRsaKeyBits, TpmsEccParms, TpmsRsaParms, TpmtPublicParms};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// Original Go test: test_parms_test.go - TestTestParms/p256
#[test]
fn test_test_parms_p256() {
    let mut sim = create_simulator!();
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
fn test_test_parms_p384() {
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
    let cmd = TestParms {
        parameters: TpmtPublicParms::Rsa(TpmsRsaParms {
            symmetric: None,
            scheme: None,
            key_bits: TpmiRsaKeyBits(2048),
            exponent: 0,
        }),
    };
    sim.execute(cmd).unwrap();
}

// Original Go test: test_parms_test.go - TestTestParms/rsa3072 - unsupported
#[test]
fn test_test_parms_rsa3072() {
    let mut sim = create_simulator!();
    let cmd = TestParms {
        parameters: TpmtPublicParms::Rsa(TpmsRsaParms {
            symmetric: None,
            scheme: None,
            key_bits: TpmiRsaKeyBits(3072),
            exponent: 0,
        }),
    };
    let err = sim.execute(cmd).unwrap_err();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(1)));
}

// Original Go test: test_parms_test.go - TestTestParms/rsa4096 - unsupported
#[test]
fn test_test_parms_rsa4096() {
    let mut sim = create_simulator!();
    let cmd = TestParms {
        parameters: TpmtPublicParms::Rsa(TpmsRsaParms {
            symmetric: None,
            scheme: None,
            key_bits: TpmiRsaKeyBits(4096),
            exponent: 0,
        }),
    };
    let err = sim.execute(cmd).unwrap_err();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(1)));
}
