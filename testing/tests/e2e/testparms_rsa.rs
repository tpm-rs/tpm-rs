//! TPM2_TestParms with RSA parameters: key sizes, exponent, schemes and symmetric definitions.

use crate::_common::{execute_test_parms, execute_test_parms_corrupted};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmsRsaParms,
    TpmtPublicParms, TpmtRsaScheme, TpmtSymDefObject,
};
use tpm2_simulator::create_simulator;

/// TPM2_TestParms accepts valid RSA parameters.
#[test]
fn accepts_valid_rsa() {
    let mut sim = create_simulator!();

    // Valid RSA parameters
    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    });

    let res = execute_test_parms(&mut sim, rsa_parms);
    assert_eq!(res, Ok(()));
}

/// TPM2_TestParms accepts any RSA exponent: the field is a plain UINT32 and TestParms reports
/// only unmarshaling errors (Part 3, TPM2_TestParms).
#[test]
fn accepts_any_rsa_exponent() {
    let mut sim = create_simulator!();

    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 3, // Unusable for key creation, but it unmarshals
    });

    let res = execute_test_parms(&mut sim, rsa_parms);
    assert_eq!(res, Ok(()));
}

/// TPM2_TestParms rejects unsupported RSA key bits with TPM_RC_VALUE.
#[test]
fn rejects_rsa_key_bits() {
    let mut sim = create_simulator!();

    // Invalid RSA key bits
    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(999),
        exponent: 0,
    });

    let res = execute_test_parms(&mut sim, rsa_parms);
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects an RSA scheme with an invalid hash with TPM_RC_HASH.
#[test]
fn rejects_rsa_scheme_hash() {
    let mut sim = create_simulator!();

    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut sim, rsa_parms, |buf| {
        buf[6..8].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects RSA parms with 999-bit symmetric key with TPM_RC_VALUE.
#[test]
fn rejects_rsa_symmetric_key_bits() {
    let mut sim = create_simulator!();

    // RSA with invalid symmetric block cipher key bits (999)
    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        }),
        scheme: None,
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut sim, rsa_parms, |buf| {
        buf[4..6].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects RSA parms with an ECDSA scheme with TPM_RC_VALUE.
#[test]
fn rejects_rsa_with_ecdsa_scheme() {
    let mut sim = create_simulator!();

    // RSA with ECDSA scheme (invalid for RSA)
    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut sim, rsa_parms, |buf| {
        buf[4..6].copy_from_slice(&0x0018u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects RSA parms with XOR as symmetric algorithm with TPM_RC_SYMMETRIC.
#[test]
fn rejects_rsa_xor_symmetric() {
    let mut sim = create_simulator!();

    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut sim, rsa_parms, |buf| {
        buf[2..4].copy_from_slice(&0x000Au16.to_be_bytes());
    });
    // C TPMI_ALG_SYM_OBJECT_Unmarshal: XOR is not a symmetric object algorithm -> TPM_RC_SYMMETRIC.
    assert_eq!(
        res,
        Err(TpmRc::SYMMETRIC.with(Position::parameter(1)).get())
    );
}
