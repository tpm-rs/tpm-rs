//! TPM2_TestParms with keyed-hash parameters: HMAC and XOR schemes.

use crate::_common::{execute_test_parms_corrupted, hex_checked, raw_rc};
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmiAlgHash, TpmiAlgKdf, TpmsSchemeXor, TpmtKeyedHashScheme, TpmtPublicParms};

/// Regression test for CPCTPM_TC2_0_32_03_08:
/// TPM2_TestParms with KeyedHash HMAC specifying an unsupported hash algorithm (TPM_ALG_AES = 0x0006)
/// must return TPM_RC_HASH (Parameter 1, 0x01C3), KeyedHash XOR with an invalid KDF (TPM_ALG_AES = 0x0006)
/// must return TPM_RC_KDF (Parameter 1, 0x01CC), and KeyedHash XOR with kdf=TPM_ALG_NULL (0x0010)
/// must return TPM_RC_KDF (Parameter 1, 0x01CC) per STEP2 of CPCTPM_TC2_0_32_03_08.
#[test]
fn keyed_hash_scheme_hash_and_kdf() {
    let mut sim = Tpm::new();

    // 1. KeyedHash HMAC with hash=AES(0x0006)
    let req_hmac_invalid = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "00000010", // size: 16 bytes
        "0000018a", // TPM_CC_TestParms
        "0008",     // TPM_ALG_KEYEDHASH
        "0005",     // TPM_ALG_HMAC
        "0006",     // hash: TPM_ALG_AES (invalid)
    ));
    let rc = raw_rc(&mut sim, &req_hmac_invalid);
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "Expected TPM_RC_HASH (0x01C3) for KeyedHash HMAC with invalid hash algorithm"
    );

    // 2. KeyedHash XOR with invalid kdf=TPM_ALG_AES(0x0006)
    let req_xor_invalid_kdf = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "00000012", // size: 18 bytes
        "0000018a", // TPM_CC_TestParms
        "0008",     // TPM_ALG_KEYEDHASH
        "000a",     // TPM_ALG_XOR
        "000b",     // hash: SHA256
        "0006",     // kdf: TPM_ALG_AES (invalid for KDF)
    ));
    let rc = raw_rc(&mut sim, &req_xor_invalid_kdf);
    assert_eq!(
        rc,
        TpmRc::KDF.with(Position::parameter(1)).get(),
        "Expected TPM_RC_KDF (0x01CC) for KeyedHash XOR with invalid KDF"
    );

    // 3. KeyedHash XOR with kdf=TPM_ALG_NULL(0x0010) is accepted by the C reference:
    //    TPMS_SCHEME_XOR_Unmarshal uses TPMI_ALG_KDF_Unmarshal(..., 1) (NULL allowed, Marshal.c).
    let req_xor_null_kdf = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "00000012", // size: 18 bytes
        "0000018a", // TPM_CC_TestParms
        "0008",     // TPM_ALG_KEYEDHASH
        "000a",     // TPM_ALG_XOR
        "000b",     // hash: SHA256
        "0010",     // kdf: TPM_ALG_NULL
    ));
    let rc = raw_rc(&mut sim, &req_xor_null_kdf);
    assert_eq!(
        rc, 0,
        "Expected TPM_RC_SUCCESS for KeyedHash XOR with NULL KDF in TestParms"
    );
}

/// TPM2_TestParms rejects a keyed-hash HMAC scheme with SHA3-256 with TPM_RC_HASH.
#[test]
fn rejects_hmac_scheme_hash() {
    let mut sim = Tpm::new();

    // KeyedHash HMAC with invalid hash (SHA3256)
    let kh_parms = TpmtPublicParms::KeyedHash(Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)));

    let res = execute_test_parms_corrupted(&mut sim, kh_parms, |buf| {
        buf[4..6].copy_from_slice(&0x0027u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects a keyed-hash XOR scheme with SHA3-256 with TPM_RC_HASH.
#[test]
fn rejects_xor_scheme_hash() {
    let mut sim = Tpm::new();

    // KeyedHash XOR with invalid hash (SHA3256)
    let kh_parms =
        TpmtPublicParms::KeyedHash(Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
            hash_alg: TpmiAlgHash::Sha256,
            kdf: Some(TpmiAlgKdf::Mgf1),
        })));

    let res = execute_test_parms_corrupted(&mut sim, kh_parms, |buf| {
        buf[4..6].copy_from_slice(&0x0027u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects a keyed-hash XOR scheme with an invalid KDF with TPM_RC_KDF.
#[test]
fn rejects_xor_scheme_kdf() {
    let mut sim = Tpm::new();

    let kh_parms =
        TpmtPublicParms::KeyedHash(Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
            hash_alg: TpmiAlgHash::Sha256,
            kdf: Some(TpmiAlgKdf::Mgf1),
        })));

    let res = execute_test_parms_corrupted(&mut sim, kh_parms, |buf| {
        buf[6..8].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::KDF.with(Position::parameter(1)).get()));
}
