#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer, marshal_to_slice};
use hex_literal::hex;
use tpm2::TpmEccCurve;
use tpm2::commands::{Command, TestParms};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgKdf, TpmiAlgSymMode, TpmiRsaKeyBits,
    TpmsEccParms, TpmsRsaParms, TpmsSchemeXor, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedHashScheme,
    TpmtPublicParms, TpmtRsaScheme, TpmtSymDefObject,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

const fn sym_def(alg: AlgSym, mode: TpmiAlgCipherMode) -> TpmtSymDefObject {
    TpmtSymDefObject {
        alg,
        mode: Some(TpmiAlgSymMode::Cipher(mode)),
    }
}

fn setup_tpm<'a>(
    crypto: &'a FakeCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: FakeRng,
) -> (
    TpmEngine<'a, FakeCrypto, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_test_parms(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    parameters: TpmtPublicParms,
) -> Result<(), u32> {
    let cmd = TestParms { parameters };
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    // Tag
    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());

    // Command code
    request_buf[6..10].copy_from_slice(&u32::from(TestParms::CMD_CODE).to_be_bytes());

    // Marshal command parameters
    offset += marshal_to_slice(&cmd, &mut request_buf[offset..]);

    // Fill in total Size
    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let _resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

fn execute_test_parms_corrupted(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    parameters: TpmtPublicParms,
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<(), u32> {
    let cmd = TestParms { parameters };
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&u32::from(TestParms::CMD_CODE).to_be_bytes());

    let payload_start = offset;
    offset += marshal_to_slice(&cmd, &mut request_buf[offset..]);

    corrupt_fn(&mut request_buf[payload_start..offset]);

    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let _resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

#[test]
fn test_parms_rsa_valid() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Valid RSA parameters
    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 0,
    });

    let res = execute_test_parms(&mut tpm, &mut global_state, rsa_parms);
    assert_eq!(res, Ok(()));
}

#[test]
fn test_parms_rsa_invalid_key_bits() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Invalid RSA key bits (999)
    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, rsa_parms, |buf| {
        buf[6..8].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_rsa_invalid_exponent() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 3, // Invalid exponent
    });

    let res = execute_test_parms(&mut tpm, &mut global_state, rsa_parms);
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_rsa_invalid_symmetric() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // RSA with invalid symmetric block cipher key bits (999)
    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: Some(sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cfb)),
        scheme: None,
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, rsa_parms, |buf| {
        buf[4..6].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_rsa_invalid_scheme() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // RSA with ECDSA scheme (invalid for RSA)
    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, rsa_parms, |buf| {
        buf[4..6].copy_from_slice(&0x0018u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_ecc_valid() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    });

    let res = execute_test_parms(&mut tpm, &mut global_state, ecc_parms);
    assert_eq!(res, Ok(()));
}

#[test]
fn test_parms_ecc_invalid_symmetric() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // ECC with invalid symmetric cipher key bits
    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: Some(sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cfb)),
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, ecc_parms, |buf| {
        buf[4..6].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_ecc_invalid_scheme() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // ECC with RSAPSS scheme (invalid for ECC)
    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, ecc_parms, |buf| {
        buf[4..6].copy_from_slice(&0x0016u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_ecc_invalid_kdf() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: Some(TpmtKdfScheme::Mgf1(TpmiAlgHash::Sha256)),
    });

    let res = execute_test_parms(&mut tpm, &mut global_state, ecc_parms);
    assert_eq!(res, Err(TpmRc::KDF.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_keyed_hash_hmac_invalid_hash() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // KeyedHash HMAC with invalid hash (SHA3256)
    let kh_parms = TpmtPublicParms::KeyedHash(Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)));

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, kh_parms, |buf| {
        buf[4..6].copy_from_slice(&0x0027u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_keyed_hash_xor_invalid_hash() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // KeyedHash XOR with invalid hash (SHA3256)
    let kh_parms = TpmtPublicParms::KeyedHash(Some(TpmtKeyedHashScheme::Xor(TpmsSchemeXor {
        hash_alg: TpmiAlgHash::Sha256,
        kdf: Some(TpmiAlgKdf::Mgf1),
    })));

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, kh_parms, |buf| {
        buf[4..6].copy_from_slice(&0x0027u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_keyed_hash_xor_invalid_kdf() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let kh_parms = TpmtPublicParms::KeyedHash(Some(TpmtKeyedHashScheme::Xor(TpmsSchemeXor {
        hash_alg: TpmiAlgHash::Sha256,
        kdf: Some(TpmiAlgKdf::Mgf1),
    })));

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, kh_parms, |buf| {
        buf[6..8].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::KDF.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_sym_invalid_key_size() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let sym_parms = TpmtPublicParms::Sym(sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cfb));

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, sym_parms, |buf| {
        buf[4..6].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_sym_invalid_mode() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let sym_parms = TpmtPublicParms::Sym(sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cbc));

    let res = execute_test_parms(&mut tpm, &mut global_state, sym_parms);
    assert_eq!(res, Err(TpmRc::MODE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_sym_invalid_type() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let sym_parms = TpmtPublicParms::Sym(sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cfb));

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, sym_parms, |buf| {
        buf[2..4].copy_from_slice(&0x0010u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_rsa_invalid_scheme_hash() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, rsa_parms, |buf| {
        buf[6..8].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_ecc_invalid_scheme_hash() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, ecc_parms, |buf| {
        buf[6..8].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_ecc_invalid_kdf_hash() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let ecc_parms = TpmtPublicParms::Ecc(TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: Some(TpmtKdfScheme::Kdf1Sp800_56a(TpmiAlgHash::Sha256)),
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, ecc_parms, |buf| {
        buf[10..12].copy_from_slice(&999u16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::HASH.with(Position::parameter(1)).get()));
}

#[test]
fn test_parms_rsa_invalid_symmetric_xor() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let rsa_parms = TpmtPublicParms::Rsa(TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 0,
    });

    let res = execute_test_parms_corrupted(&mut tpm, &mut global_state, rsa_parms, |buf| {
        buf[2..4].copy_from_slice(&0x000Au16.to_be_bytes());
    });
    assert_eq!(res, Err(TpmRc::VALUE.with(Position::parameter(1)).get()));
}
