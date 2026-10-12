#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer, marshal_to_slice};
use tpm2::commands::{GetCapability, SetPrimaryPolicy, TestParms};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Handle, Tpm2bDigest, TpmCap, TpmCc, TpmPt, TpmPtPcr, TpmiAlgCipherMode, TpmiAlgHash,
    TpmiAlgSymMode, TpmsAuthCommand, TpmsCapabilityData, TpmtHa, TpmtPublicParms, TpmtSymDefObject,
    Unmarshal,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

#[test]
fn test_get_capability_commands_parity() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x44, // cc: TPM_CC_Startup (0x144)
        0x00, 0x00, // startup_type: TPM_SU_CLEAR
    ];
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(
        u32::from_be_bytes([
            startup_response[6],
            startup_response[7],
            startup_response[8],
            startup_response[9]
        ]),
        0
    );

    let cmd = GetCapability {
        capability: TpmCap::Commands,
        property: u32::from(TpmCc::Startup),
        property_count: 5,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]); // Placeholder for size
    offset += marshal_to_slice(&TpmCc::GetCapability, &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    let _ = marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert!(res_len > 10);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
}

#[test]
fn test_test_parms_error_codes() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x44, // cc: TPM_CC_Startup (0x144)
        0x00, 0x00, // startup_type: TPM_SU_CLEAR
    ];
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(
        u32::from_be_bytes([
            startup_response[6],
            startup_response[7],
            startup_response[8],
            startup_response[9]
        ]),
        0
    );

    // Test invalid AES key size (192 bits)
    let parms = TpmtPublicParms::Sym(TpmtSymDefObject {
        alg: AlgSym::Aes192,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    });
    let cmd = TestParms { parameters: parms };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&TpmCc::TestParms, &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    let _ = marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    let expected_rc = TpmRc::SYMMETRIC.with(Position::parameter(1)).get();
    assert_eq!(rc, expected_rc);

    // Test invalid AES mode (CBC instead of CFB)
    let parms_mode = TpmtPublicParms::Sym(TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cbc)),
    });
    let cmd_mode = TestParms {
        parameters: parms_mode,
    };
    let mut offset_m = 0;
    offset_m += marshal_to_slice(&(0x8001u16), &mut request[offset_m..]);
    offset_m += marshal_to_slice(&(0u32), &mut request[offset_m..]);
    offset_m += marshal_to_slice(&TpmCc::TestParms, &mut request[offset_m..]);
    offset_m += marshal_to_slice(&(cmd_mode), &mut request[offset_m..]);
    let total_size_m = u32::try_from(offset_m).unwrap();
    let _ = marshal_to_slice(&(total_size_m), &mut request[2..6]);

    tpm.execute_command_separate(&mut global_state, &request[..offset_m], &mut response);
    let rc_m = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    let expected_rc_m = TpmRc::MODE.with(Position::parameter(1)).get();
    assert_eq!(rc_m, expected_rc_m);
}

#[test]
fn test_get_capability_pcr_extend_l2() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x44, // cc: TPM_CC_Startup (0x144)
        0x00, 0x00, // startup_type: TPM_SU_CLEAR
    ];
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    let cmd = GetCapability {
        capability: TpmCap::PCRProperties,
        property: u32::from(TpmPtPcr::ExtendL2),
        property_count: 1,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&TpmCc::GetCapability, &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    let _ = marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(
        rc, 0,
        "GetCapability failed with rc=0x{:08x}, res_len={}",
        rc, res_len
    );
    assert!(res_len > 10, "res_len <= 10 despite rc=0");
    // Unmarshal response data and verify PCR properties for EXTEND_L2
    let mut unmarsh = &response[10..res_len];
    let more_data = u8::unmarshal(&mut unmarsh).unwrap();
    assert_eq!(more_data, 1);
    let cap_data = TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let TpmsCapabilityData::PcrProperties(props) = cap_data {
        let slice = props.as_slice();
        assert_eq!(slice.len(), 1);
        assert_eq!(slice[0].tag, TpmPtPcr::ExtendL2);
        assert_eq!(slice[0].selection.pcrs(), &[0xff, 0xff, 0xff]);
    } else {
        panic!("Expected PcrProperties capability data");
    }
}

#[test]
fn test_get_capability_pcr_reset_l2() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x44, // cc: TPM_CC_Startup (0x144)
        0x00, 0x00, // startup_type: TPM_SU_CLEAR
    ];
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    let cmd = GetCapability {
        capability: TpmCap::PCRProperties,
        property: u32::from(TpmPtPcr::ResetL2),
        property_count: 1,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&TpmCc::GetCapability, &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    let _ = marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(rc, 0);
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let TpmsCapabilityData::PcrProperties(props) = cap_data {
        let slice = props.as_slice();
        assert_eq!(slice.len(), 1);
        assert_eq!(slice[0].tag, TpmPtPcr::ResetL2);
        assert_eq!(slice[0].selection.pcrs(), &[0x00, 0x00, 0xf1]);
    } else {
        panic!("Expected PcrProperties capability data");
    }
}

#[test]
fn test_get_capability_loaded_and_saved_sessions() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    // Start 1 HMAC session and 1 Policy session
    let start_hmac = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40,
        0x00, 0x00, 0x07, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0B,
    ];
    let _res_len = tpm.execute_command_separate(&mut global_state, &start_hmac[..], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let handle_hmac = u32::from_be_bytes([response[10], response[11], response[12], response[13]]);

    let start_policy = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40,
        0x00, 0x00, 0x07, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x0B,
    ];
    let _res_len =
        tpm.execute_command_separate(&mut global_state, &start_policy[..], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let handle_policy =
        u32::from_be_bytes([response[10], response[11], response[12], response[13]]);

    // Query loaded sessions (TPM_HT_LOADED_SESSION = 0x02)
    let cmd = GetCapability {
        capability: TpmCap::Handles,
        property: 0x02000000,
        property_count: 10,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&TpmCc::GetCapability, &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    let _ = marshal_to_slice(&(total_size), &mut request[2..6]);

    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let TpmsCapabilityData::Handles(handles) = cap_data {
        let slice = handles.as_slice();
        assert_eq!(slice.len(), 2);
        assert!(slice.iter().any(|h| h.0 == handle_hmac));
        assert!(slice.iter().any(|h| h.0 == handle_policy));
    } else {
        panic!("Expected Handles capability data");
    }

    // Save both sessions using ContextSave (0x0162)
    for handle in [handle_hmac, handle_policy] {
        let mut cs_req = [0u8; 1024];
        let mut cs_off = 0;
        cs_off += marshal_to_slice(&(0x8001u16), &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&(0u32), &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&TpmCc::ContextSave, &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&(handle), &mut cs_req[cs_off..]);
        let total_cs = u32::try_from(cs_off).unwrap();
        let _ = marshal_to_slice(&(total_cs), &mut cs_req[2..6]);
        let _res_len =
            tpm.execute_command_separate(&mut global_state, &cs_req[..cs_off], &mut response);
        assert_eq!(
            u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
            0
        );
    }

    // Query saved sessions (TPM_HT_SAVED_SESSION = 0x03)
    let cmd_saved = GetCapability {
        capability: TpmCap::Handles,
        property: 0x03000000,
        property_count: 10,
    };
    let mut request_s = [0u8; 1024];
    let mut offset_s = 0;
    offset_s += marshal_to_slice(&(0x8001u16), &mut request_s[offset_s..]);
    offset_s += marshal_to_slice(&(0u32), &mut request_s[offset_s..]);
    offset_s += marshal_to_slice(&TpmCc::GetCapability, &mut request_s[offset_s..]);
    offset_s += marshal_to_slice(&(cmd_saved), &mut request_s[offset_s..]);
    let total_size_s = u32::try_from(offset_s).unwrap();
    let _ = marshal_to_slice(&(total_size_s), &mut request_s[2..6]);

    let res_len =
        tpm.execute_command_separate(&mut global_state, &request_s[..offset_s], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let TpmsCapabilityData::Handles(handles) = cap_data {
        let slice = handles.as_slice();
        assert_eq!(slice.len(), 2);
        // All returned saved session handles must have MSO 0x02 per spec Part 3
        for h in slice {
            assert_eq!(h.0 >> 24, 0x02);
        }
    } else {
        panic!("Expected Handles capability data for saved sessions");
    }
}

#[test]
fn test_ecc_parameters_invalid_curves() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x44, // cc: TPM_CC_Startup (0x144)
        0x00, 0x00, // startup_type: TPM_SU_CLEAR
    ];
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(
        u32::from_be_bytes([
            startup_response[6],
            startup_response[7],
            startup_response[8],
            startup_response[9]
        ]),
        0
    );

    // 1. Test TPM_ECC_NONE (0x0000) -> TPM_RC_CURVE (0x1A6)
    let req_none = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x78, // cc: TPM_CC_ECC_Parameters (0x178)
        0x00, 0x00, // curveID: TPM_ECC_NONE
    ];
    let mut response = [0u8; 256];
    let res_len = tpm.execute_command_separate(&mut global_state, &req_none[..], &mut response);
    assert!(res_len >= 10);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        TpmRc::CURVE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_CURVE at Pos1 (0x1A6) for TPM_ECC_NONE"
    );

    // 2. Test unsupported curve 0x0022 -> TPM_RC_CURVE (0x1A6)
    let req_unsupported = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x78, // cc: TPM_CC_ECC_Parameters (0x178)
        0x00, 0x22, // curveID: 0x0022
    ];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &req_unsupported[..], &mut response);
    assert!(res_len >= 10);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        TpmRc::CURVE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_CURVE at Pos1 (0x1A6) for curve 0x0022"
    );

    // 3. Test valid curve NIST_P256 (0x0003) -> TPM_RC_SUCCESS (0x000)
    let req_valid = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x78, // cc: TPM_CC_ECC_Parameters (0x178)
        0x00, 0x03, // curveID: NIST_P256
    ];
    let res_len = tpm.execute_command_separate(&mut global_state, &req_valid[..], &mut response);
    assert!(res_len >= 10);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0,
        "Expected TPM_RC_SUCCESS for NIST_P256"
    );
}

#[test]
fn test_get_capability_vendor_string() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x44, // cc: TPM_CC_Startup (0x144)
        0x00, 0x00, // startup_type: TPM_SU_CLEAR
    ];
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::VendorString1),
        property_count: 4,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&TpmCc::GetCapability, &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    let _ = marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let TpmsCapabilityData::TpmProperties(props) = cap_data {
        let slice = props.as_slice();
        assert_eq!(slice.len(), 4);
        assert_eq!(slice[0].property, TpmPt::VendorString1);
        assert_eq!(slice[0].value, 0x54504D2D); // "TPM-"
        assert_eq!(slice[1].property, TpmPt::VendorString2);
        assert_eq!(slice[1].value, 0x52555354); // "RUST"
        assert_eq!(slice[2].property, TpmPt::VendorString3);
        assert_eq!(slice[2].value, 0);
        assert_eq!(slice[3].property, TpmPt::VendorString4);
        assert_eq!(slice[3].value, 0);
    } else {
        panic!("Expected TpmProperties capability data");
    }
}

#[test]
fn test_get_capability_auth_policies_nullable_and_set_primary_policy() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    // Startup CLEAR
    let startup_request = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x44, // cc: TPM_CC_Startup (0x144)
        0x00, 0x00, // startup_type: TPM_SU_CLEAR
    ];
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(
        u32::from_be_bytes([
            startup_response[6],
            startup_response[7],
            startup_response[8],
            startup_response[9],
        ]),
        0
    );

    // 1. Query TPM2_GetCapability(TPM_CAP_AUTH_POLICIES, 0x40000001, 4)
    // Initially, all permanent handles have no policy set.
    let cmd = GetCapability {
        capability: TpmCap::AuthPolicies,
        property: 0x40000001,
        property_count: 4,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]); // Placeholder for size
    offset += marshal_to_slice(&TpmCc::GetCapability, &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    let _ = marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );

    let mut unmarsh = &response[10..res_len];
    let more_data = bool::unmarshal(&mut unmarsh).unwrap();
    assert!(!more_data);
    let cap = TpmCap::unmarshal(&mut unmarsh).unwrap();
    assert_eq!(cap, TpmCap::AuthPolicies);
    let count = u32::unmarshal(&mut unmarsh).unwrap();
    assert_eq!(count, 4);

    let expected_handles = [
        Handle::RH_OWNER,
        Handle::RH_LOCKOUT,
        Handle::RH_ENDORSEMENT,
        Handle::RH_PLATFORM,
    ];

    for &expected_handle in &expected_handles {
        let h = Handle::unmarshal(&mut unmarsh).unwrap();
        let policy_hash = Option::<TpmtHa>::unmarshal(&mut unmarsh).unwrap();
        assert_eq!(h, expected_handle);
        // All unassigned policies MUST report policy_hash == None (TPM_ALG_NULL)
        assert_eq!(policy_hash, None);
    }
    assert!(unmarsh.is_empty());

    // Verify wire format: 4 policies of 6 bytes each (4 handle + 2 TPM_ALG_NULL)
    // capability (4) + count (4) + 4 * 6 = 32 bytes capability data
    // header (10) + more_data (1) + 32 = 43 bytes total
    assert_eq!(res_len, 10 + 1 + 4 + 4 + 4 * 6);

    // 2. Set an authPolicy on RH_OWNER via TPM2_SetPrimaryPolicy
    let dummy_policy = [0x42u8; 32];
    let policy_digest = Tpm2bDigest::new(&dummy_policy).unwrap();
    let set_cmd = SetPrimaryPolicy {
        auth_handle: Handle::RH_OWNER,
        auth_policy: policy_digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let mut set_req = [0u8; 1024];
    let mut s_off = 0;
    s_off += marshal_to_slice(&(0x8002u16), &mut set_req[s_off..]);
    let len_offset = s_off;
    s_off += marshal_to_slice(&(0u32), &mut set_req[s_off..]);
    s_off += marshal_to_slice(&TpmCc::SetPrimaryPolicy, &mut set_req[s_off..]);
    s_off += marshal_to_slice(&set_cmd.auth_handle, &mut set_req[s_off..]);
    let auth_len_offset = s_off;
    s_off += marshal_to_slice(&(0u32), &mut set_req[s_off..]);
    let auth_start = s_off;
    let pw_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Default::default(),
        session_attributes: Default::default(),
        hmac: Default::default(),
    };
    s_off += marshal_to_slice(&pw_auth, &mut set_req[s_off..]);
    let auth_len = u32::try_from(s_off - auth_start).unwrap();
    s_off += marshal_to_slice(&set_cmd, &mut set_req[s_off..]);
    let total_len = u32::try_from(s_off).unwrap();
    set_req[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    set_req[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let mut set_resp = [0u8; 256];
    let _set_res_len =
        tpm.execute_command_separate(&mut global_state, &set_req[..s_off], &mut set_resp);
    assert_eq!(
        u32::from_be_bytes([set_resp[6], set_resp[7], set_resp[8], set_resp[9]]),
        0
    );

    // 3. Query TPM2_GetCapability(TPM_CAP_AUTH_POLICIES) again
    let res_len2 =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh2 = &response[10..res_len2];
    let _more_data2 = bool::unmarshal(&mut unmarsh2).unwrap();
    let cap2 = TpmCap::unmarshal(&mut unmarsh2).unwrap();
    assert_eq!(cap2, TpmCap::AuthPolicies);
    let count2 = u32::unmarshal(&mut unmarsh2).unwrap();
    assert_eq!(count2, 4);

    // RH_OWNER must now have Some(Sha256) policy
    assert_eq!(Handle::unmarshal(&mut unmarsh2).unwrap(), Handle::RH_OWNER);
    assert_eq!(
        Option::<TpmtHa>::unmarshal(&mut unmarsh2).unwrap(),
        Some(TpmtHa::Sha256(&dummy_policy))
    );

    // Others must still be None
    assert_eq!(
        Handle::unmarshal(&mut unmarsh2).unwrap(),
        Handle::RH_LOCKOUT
    );
    assert_eq!(Option::<TpmtHa>::unmarshal(&mut unmarsh2).unwrap(), None);
    assert_eq!(
        Handle::unmarshal(&mut unmarsh2).unwrap(),
        Handle::RH_ENDORSEMENT
    );
    assert_eq!(Option::<TpmtHa>::unmarshal(&mut unmarsh2).unwrap(), None);
    assert_eq!(
        Handle::unmarshal(&mut unmarsh2).unwrap(),
        Handle::RH_PLATFORM
    );
    assert_eq!(Option::<TpmtHa>::unmarshal(&mut unmarsh2).unwrap(), None);
    assert!(unmarsh2.is_empty());
}

#[test]
fn test_get_capability_tpm_spec_properties() {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x44, // cc: TPM_CC_Startup (0x144)
        0x00, 0x00, // startup_type: TPM_SU_CLEAR
    ];
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FamilyIndicator),
        property_count: 5,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&TpmCc::GetCapability, &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    let _ = marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let TpmsCapabilityData::TpmProperties(props) = cap_data {
        let slice = props.as_slice();
        assert_eq!(slice.len(), 5);
        assert_eq!(slice[0].property, TpmPt::FamilyIndicator);
        assert_eq!(slice[0].value, 0x322E_3000);
        assert_eq!(slice[1].property, TpmPt::Level);
        assert_eq!(slice[1].value, 0);
        assert_eq!(slice[2].property, TpmPt::Revision);
        assert_eq!(slice[2].value, 185);
        assert_eq!(slice[3].property, TpmPt::DayofYear);
        assert_eq!(slice[3].value, 0);
        assert_eq!(slice[4].property, TpmPt::Year);
        assert_eq!(slice[4].value, 0);
    } else {
        panic!("Expected TpmProperties capability data");
    }
}
