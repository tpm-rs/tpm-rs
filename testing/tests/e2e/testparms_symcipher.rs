//! TPM2_TestParms with symmetric cipher parameters: algorithms, key sizes and modes.

use crate::_common::{
    execute_test_parms_corrupted, no_session_command, rc_of, rsa_parms, run_raw, symcipher_parms,
    test_parms,
};
use testing::tpm::Tpm;
use tpm2::commands::TestParms;
use tpm2::errors::{Position, TpmRc};
use tpm2::{AlgSym, TpmCc, TpmiAlgCipherMode, TpmiAlgSymMode, TpmtPublicParms, TpmtSymDefObject};

/// `TPM2_TestParms` accepts every implemented block-cipher mode (also as the symmetric
/// definition of an RSA key). RSA-3072/4096 stay unsupported (see the log: go-tpm parity).
#[test]
fn all_block_modes_accepted() {
    let mut sim = Tpm::new();
    for mode in [0x0040u16, 0x0041, 0x0042, 0x0043, 0x0044, 0x0010] {
        assert_eq!(
            test_parms(&mut sim, &symcipher_parms(mode)),
            0,
            "mode {mode:#x}"
        );
    }
    assert_eq!(
        test_parms(&mut sim, &rsa_parms(&0x0010u16.to_be_bytes(), 2048)),
        0
    );
    // RSA with an AES-128-CTR symmetric definition.
    let mut sym = 0x0006u16.to_be_bytes().to_vec();
    sym.extend_from_slice(&128u16.to_be_bytes());
    sym.extend_from_slice(&0x0040u16.to_be_bytes());
    assert_eq!(test_parms(&mut sim, &rsa_parms(&sym, 2048)), 0);
}

/// TestParms rejects AES-192 (TPM_RC_VALUE: not a TPMI_AES_KEY_BITS value of this TPM) and
/// accepts AES-CBC.
#[test]
fn invalid_aes_key_size_rejected() {
    let mut sim = Tpm::new();

    // Test invalid AES key size (192 bits; not an `AlgSym` of this TPM): AES-128 is marshaled
    // and its keyBits replaced (header, then type and algorithm).
    let parms = TpmtPublicParms::Sym(TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    });
    let cmd = TestParms { parameters: parms };
    let mut command = no_session_command(TpmCc::TestParms, &cmd);
    command[14..16].copy_from_slice(&192u16.to_be_bytes());
    let response = run_raw(&mut sim, &command);
    let expected_rc = TpmRc::VALUE.with(Position::parameter(1)).get();
    assert_eq!(rc_of(&response), expected_rc);

    // AES-CBC is a valid symmetric mode for TPM2_TestParms: C only checks it while unmarshaling
    // `TPMU_SYM_MODE` (`TPMI_ALG_SYM_MODE_Unmarshal` accepts CTR/OFB/CBC/CFB/ECB), so it
    // succeeds. The CFB restriction applies to restricted decryption keys at object creation.
    let parms_mode = TpmtPublicParms::Sym(TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cbc)),
    });
    let cmd_mode = TestParms {
        parameters: parms_mode,
    };
    let response = run_raw(&mut sim, &no_session_command(TpmCc::TestParms, &cmd_mode));
    assert_eq!(rc_of(&response), 0);
}

/// TPM2_TestParms rejects a symcipher with invalid key bits with TPM_RC_VALUE.
#[test]
fn rejects_symcipher_key_bits() {
    let mut sim = Tpm::new();

    let sym_parms = TpmtPublicParms::Sym(TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    });

    let res = execute_test_parms_corrupted(&mut sim, sym_parms, |buf| {
        buf[4..6].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects an undefined symcipher mode with TPM_RC_MODE.
#[test]
fn rejects_symcipher_mode() {
    let mut sim = Tpm::new();

    // CBC is an implemented mode and TestParms only unmarshals (C TestParms.c), so use an
    // undefined mode value instead (C TPMI_ALG_SYM_MODE_Unmarshal -> TPM_RC_MODE).
    let sym_parms = TpmtPublicParms::Sym(TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    });

    let res = execute_test_parms_corrupted(&mut sim, sym_parms, |buf| {
        buf[6..8].copy_from_slice(&0x0099u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::MODE.with(Position::parameter(1)).get()));
}

/// TPM2_TestParms rejects a symcipher with TPM_ALG_NULL algorithm with TPM_RC_SYMMETRIC.
#[test]
fn rejects_symcipher_null_algorithm() {
    let mut sim = Tpm::new();

    let sym_parms = TpmtPublicParms::Sym(TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    });

    let res = execute_test_parms_corrupted(&mut sim, sym_parms, |buf| {
        buf[2..4].copy_from_slice(&0x0010u16.to_be_bytes());
    });
    // C TPMI_ALG_SYM_OBJECT_Unmarshal (no NULL for SYMCIPHER parms) -> TPM_RC_SYMMETRIC.
    assert_eq!(
        res,
        Err(TpmRc::SYMMETRIC.with(Position::parameter(1)).get())
    );
}
