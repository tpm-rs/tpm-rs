//! TPM2_TestParms with ECC parameters: KDF, scheme and symmetric definitions.

use crate::_common::{execute_test_parms, execute_test_parms_corrupted, hex_checked, raw_rc};
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmsEccParms,
    TpmtEccScheme, TpmtKdfScheme, TpmtPublicParms, TpmtSymDefObject,
};

/// TPM2_TestParms accepts valid ECC parameters.
#[test]
fn accepts_valid_ecc() {
    let mut sim = Tpm::new();

    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    });

    let res = execute_test_parms(&mut sim, ecc_parms);
    assert_eq!(res, Ok(()));
}

/// Regression test for CPCTPM_TC2_0_32_03_06:
/// TPM2_TestParms with ECC KDF specifying an unsupported hash algorithm (e.g. TPM_ALG_AES = 0x0006)
/// must return TPM_RC_HASH (Parameter 1, 0x01C3).
#[test]
fn ecc_kdf_invalid_hash_rejected() {
    let mut sim = Tpm::new();

    // TestParms ECC: sym=Null, scheme=Null, curve=NistP256, kdf=KDF1_SP800_56A with hash=AES(0x0006)
    let req = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "00000016", // size: 22 bytes
        "0000018a", // TPM_CC_TestParms
        "0023",     // TPM_ALG_ECC
        "0010",     // sym: TPM_ALG_NULL
        "0010",     // scheme: TPM_ALG_NULL
        "0003",     // curveID: NIST_P256
        "0020",     // kdf: TPM_ALG_KDF1_SP800_56A
        "0006",     // kdf hashAlg: TPM_ALG_AES (invalid hash)
    ));
    let rc = raw_rc(&mut sim, &req);
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "Expected TPM_RC_HASH (0x01C3) for ECC KDF with invalid hash algorithm"
    );
}

/// TPM2_TestParms accepts MGF1 as ECC KDF: `TPMI_ALG_KDF` includes every implemented KDF/MGF
/// and TestParms reports only unmarshaling errors (an ECC key needs a NULL KDF at creation).
#[test]
fn accepts_mgf1_ecc_kdf() {
    let mut sim = Tpm::new();

    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: Some(TpmtKdfScheme::Mgf1(TpmiAlgHash::Sha256)),
    });

    let res = execute_test_parms(&mut sim, ecc_parms);
    assert_eq!(res, Ok(()));
}

/// TPM2_TestParms rejects the ECC schemes this TPM does not implement (SM2, EC-Schnorr, ECMQV;
/// not in TPM_CAP_ALGS) with TPM_RC_SCHEME + P1: `TPMI_ALG_ECC_SCHEME` only includes
/// implemented schemes.
#[test]
fn rejects_unimplemented_ecc_schemes() {
    let mut sim = Tpm::new();
    for scheme in [
        TpmtEccScheme::Sm2(TpmiAlgHash::Sha256),
        TpmtEccScheme::Ecschnorr(TpmiAlgHash::Sha256),
        TpmtEccScheme::Ecmqv(TpmiAlgHash::Sha256),
    ] {
        let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
            symmetric: None,
            scheme: Some(scheme),
            curve_id: TpmEccCurve::NistP256,
            kdf: None,
        });
        assert_eq!(
            execute_test_parms(&mut sim, ecc_parms),
            Err(TpmRc::SCHEME.with(Position::parameter(1)).get()),
            "{scheme:?}"
        );
    }
}

/// TPM2_TestParms rejects an ECC KDF with an invalid hash with TPM_RC_HASH.
#[test]
fn rejects_ecc_kdf_hash() {
    let mut sim = Tpm::new();

    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: Some(TpmtKdfScheme::Kdf1Sp800_56a(TpmiAlgHash::Sha256)),
    });

    let res = execute_test_parms_corrupted(&mut sim, ecc_parms, |buf| {
        buf[10..12].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects an ECC scheme with an invalid hash with TPM_RC_HASH.
#[test]
fn rejects_ecc_scheme_hash() {
    let mut sim = Tpm::new();

    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    });

    let res = execute_test_parms_corrupted(&mut sim, ecc_parms, |buf| {
        buf[6..8].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects ECC parms with invalid symmetric key bits with TPM_RC_VALUE.
#[test]
fn rejects_ecc_symmetric_key_bits() {
    let mut sim = Tpm::new();

    // ECC with invalid symmetric cipher key bits
    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        }),
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    });

    let res = execute_test_parms_corrupted(&mut sim, ecc_parms, |buf| {
        buf[4..6].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects ECC parms with an RSAPSS scheme with TPM_RC_SCHEME + P1.
#[test]
fn rejects_ecc_with_rsapss_scheme() {
    let mut sim = Tpm::new();

    // ECC with RSAPSS scheme (invalid for ECC)
    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    });

    let res = execute_test_parms_corrupted(&mut sim, ecc_parms, |buf| {
        buf[4..6].copy_from_slice(&0x0016u16.to_be_bytes());
    });
    // C TPMI_ALG_ECC_SCHEME_Unmarshal: TPM_RC_SCHEME (+ RC_P1).
    assert_eq!(res, Err(TpmRc::SCHEME.with(Position::parameter(1)).get()));
}
