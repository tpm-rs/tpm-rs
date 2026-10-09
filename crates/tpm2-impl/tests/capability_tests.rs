use common::marshal_to_slice;

use tpm2::Unmarshal;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{GetCapability, TestParms};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCap, TpmCc};
use tpm2::{TpmiAlgSymMode, TpmtPublicParms, TpmtSymDefObject};
use tpm2_impl::{TpmEngine, TpmPlatform};

#[test]
fn test_get_capability_commands_parity() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
        property: TpmCc::Startup.code(),
        property_count: 5,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]); // Placeholder for size
    offset += marshal_to_slice(&(TpmCc::GetCapability.code()), &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = offset as u32;
    marshal_to_slice(&(total_size), &mut request[2..6]);

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
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
    let parms = TpmtPublicParms::Sym(TpmtSymDefObject::Aes192(Some(TpmiAlgSymMode::CFB)));
    let cmd = TestParms { parameters: parms };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&(TpmCc::TestParms.code()), &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = offset as u32;
    marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    let expected_rc = TpmRc::SYMMETRIC.with(Position::parameter(1)).get();
    assert_eq!(rc, expected_rc);

    // AES-CBC is a valid symmetric mode for TPM2_TestParms: C only checks it while unmarshaling
    // `TPMU_SYM_MODE` (`TPMI_ALG_SYM_MODE_Unmarshal` accepts CTR/OFB/CBC/CFB/ECB), so it
    // succeeds. The CFB restriction applies to restricted decryption keys at object creation.
    let parms_mode = TpmtPublicParms::Sym(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CBC)));
    let cmd_mode = TestParms {
        parameters: parms_mode,
    };
    let mut offset_m = 0;
    offset_m += marshal_to_slice(&(0x8001u16), &mut request[offset_m..]);
    offset_m += marshal_to_slice(&(0u32), &mut request[offset_m..]);
    offset_m += marshal_to_slice(&(TpmCc::TestParms.code()), &mut request[offset_m..]);
    offset_m += marshal_to_slice(&(cmd_mode), &mut request[offset_m..]);
    let total_size_m = offset_m as u32;
    marshal_to_slice(&(total_size_m), &mut request[2..6]);

    tpm.execute_command_separate(&mut global_state, &request[..offset_m], &mut response);
    let rc_m = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(rc_m, 0);
}

#[test]
fn test_get_capability_pcr_extend_l2() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
        property: u32::from(tpm2::TpmPtPcr::EXTEND_L2),
        property_count: 1,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&(TpmCc::GetCapability.code()), &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = offset as u32;
    marshal_to_slice(&(total_size), &mut request[2..6]);

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
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::PcrProperties(props) = cap_data {
        assert_eq!(props.count(), 1);
        assert_eq!(props.pcr_property()[0].tag, tpm2::TpmPtPcr::EXTEND_L2);
        assert_eq!(props.pcr_property()[0].pcr_select[..3], [0xff, 0xff, 0xff]);
    } else {
        panic!("Expected PcrProperties capability data");
    }
}

#[test]
fn test_get_capability_pcr_reset_l2() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
        property: u32::from(tpm2::TpmPtPcr::RESET_L2),
        property_count: 1,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&(TpmCc::GetCapability.code()), &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = offset as u32;
    marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(rc, 0);
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::PcrProperties(props) = cap_data {
        assert_eq!(props.count(), 1);
        assert_eq!(props.pcr_property()[0].tag, tpm2::TpmPtPcr::RESET_L2);
        assert_eq!(props.pcr_property()[0].pcr_select[..3], [0x00, 0x00, 0xf1]);
    } else {
        panic!("Expected PcrProperties capability data");
    }
}

#[test]
fn test_get_capability_loaded_and_saved_sessions() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
    offset += marshal_to_slice(&(TpmCc::GetCapability.code()), &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = offset as u32;
    marshal_to_slice(&(total_size), &mut request[2..6]);

    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::Handles(handles) = cap_data {
        assert_eq!(handles.count(), 2);
        assert!(handles.handle().iter().any(|h| h.0 == handle_hmac));
        assert!(handles.handle().iter().any(|h| h.0 == handle_policy));
    } else {
        panic!("Expected Handles capability data");
    }

    // Save both sessions using ContextSave (0x0162)
    for handle in [handle_hmac, handle_policy] {
        let mut cs_req = [0u8; 1024];
        let mut cs_off = 0;
        cs_off += marshal_to_slice(&(0x8001u16), &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&(0u32), &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&(TpmCc::ContextSave.code()), &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&(handle), &mut cs_req[cs_off..]);
        let total_cs = cs_off as u32;
        marshal_to_slice(&(total_cs), &mut cs_req[2..6]);
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
    offset_s += marshal_to_slice(&(TpmCc::GetCapability.code()), &mut request_s[offset_s..]);
    offset_s += marshal_to_slice(&(cmd_saved), &mut request_s[offset_s..]);
    let total_size_s = offset_s as u32;
    marshal_to_slice(&(total_size_s), &mut request_s[2..6]);

    let res_len =
        tpm.execute_command_separate(&mut global_state, &request_s[..offset_s], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::Handles(handles) = cap_data {
        assert_eq!(handles.count(), 2);
        // All returned saved session handles must have MSO 0x02 per spec Part 3
        for h in handles.handle().iter().take(handles.count()) {
            assert_eq!(h.0 >> 24, 0x02);
        }
    } else {
        panic!("Expected Handles capability data for saved sessions");
    }
}

#[test]
fn test_ecc_parameters_invalid_curves() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
        property: u32::from(tpm2::TpmPt::VENDOR_STRING_1),
        property_count: 4,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&(TpmCc::GetCapability.code()), &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = offset as u32;
    marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::TpmProperties(props) = cap_data {
        assert_eq!(props.count(), 4);
        assert_eq!(
            props.tpm_property()[0].property,
            tpm2::TpmPt::VENDOR_STRING_1
        );
        assert_eq!(props.tpm_property()[0].value, 0x54504D2D); // "TPM-"
        assert_eq!(
            props.tpm_property()[1].property,
            tpm2::TpmPt::VENDOR_STRING_2
        );
        assert_eq!(props.tpm_property()[1].value, 0x52555354); // "RUST"
        assert_eq!(
            props.tpm_property()[2].property,
            tpm2::TpmPt::VENDOR_STRING_3
        );
        assert_eq!(props.tpm_property()[2].value, 0);
        assert_eq!(
            props.tpm_property()[3].property,
            tpm2::TpmPt::VENDOR_STRING_4
        );
        assert_eq!(props.tpm_property()[3].value, 0);
    } else {
        panic!("Expected TpmProperties capability data");
    }
}

#[test]
fn test_get_capability_auth_policies_nullable_and_set_primary_policy() {
    use tpm2::commands::{SetPrimaryPolicy, SetPrimaryPolicyHandles};
    use tpm2::{Handle, Tpm2bDigest, TpmiAlgHash, TpmsAuthCommand, TpmtHa};

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
    offset += marshal_to_slice(&(TpmCc::GetCapability.code()), &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = offset as u32;
    marshal_to_slice(&(total_size), &mut request[2..6]);

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
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    assert!(unmarsh.is_empty());

    if let tpm2::TpmsCapabilityData::AuthPolicies(tagged_policies) = cap_data {
        assert_eq!(tagged_policies.count(), 4);
        let policies = tagged_policies.as_slice();

        let expected_handles = [
            Handle::RH_OWNER,
            Handle::RH_LOCKOUT,
            Handle::RH_ENDORSEMENT,
            Handle::RH_PLATFORM,
        ];

        for (i, &expected_handle) in expected_handles.iter().enumerate() {
            assert_eq!(policies[i].handle, expected_handle);
            // All unassigned policies MUST report policy_hash == None (TPM_ALG_NULL)
            assert_eq!(policies[i].policy_hash, None);
        }

        // Verify wire format: 4 policies of 6 bytes each (4 handle + 2 TPM_ALG_NULL)
        // capability (4) + count (4) + 4 * 6 = 32 bytes capability data
        // header (10) + more_data (1) + 32 = 43 bytes total
        assert_eq!(res_len, 10 + 1 + 4 + 4 + 4 * 6);
    } else {
        panic!("Expected AuthPolicies capability data");
    }

    // 2. Set an authPolicy on RH_OWNER via TPM2_SetPrimaryPolicy
    let dummy_policy = [0x42u8; 32];
    let policy_digest = Tpm2bDigest::from_bytes(&dummy_policy).unwrap();
    let set_cmd = SetPrimaryPolicy {
        auth_policy: policy_digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let set_handles = SetPrimaryPolicyHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let mut set_req = [0u8; 1024];
    let mut s_off = 0;
    s_off += marshal_to_slice(&(0x8002u16), &mut set_req[s_off..]);
    let len_offset = s_off;
    s_off += marshal_to_slice(&(0u32), &mut set_req[s_off..]);
    s_off += marshal_to_slice(&(TpmCc::SetPrimaryPolicy.code()), &mut set_req[s_off..]);
    s_off += marshal_to_slice(&set_handles, &mut set_req[s_off..]);
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
    let auth_len = (s_off - auth_start) as u32;
    s_off += marshal_to_slice(&set_cmd, &mut set_req[s_off..]);
    let total_len = s_off as u32;
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
    let cap_data2 = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh2).unwrap();
    if let tpm2::TpmsCapabilityData::AuthPolicies(tagged_policies) = cap_data2 {
        assert_eq!(tagged_policies.count(), 4);
        let policies = tagged_policies.as_slice();

        // RH_OWNER must now have Some(Sha256) policy
        assert_eq!(policies[0].handle, Handle::RH_OWNER);
        assert_eq!(policies[0].policy_hash, Some(TpmtHa::Sha256(&dummy_policy)));

        // Others must still be None
        assert_eq!(policies[1].handle, Handle::RH_LOCKOUT);
        assert_eq!(policies[1].policy_hash, None);
        assert_eq!(policies[2].handle, Handle::RH_ENDORSEMENT);
        assert_eq!(policies[2].policy_hash, None);
        assert_eq!(policies[3].handle, Handle::RH_PLATFORM);
        assert_eq!(policies[3].policy_hash, None);
    } else {
        panic!("Expected AuthPolicies capability data");
    }
}

#[test]
fn test_get_capability_tpm_spec_properties() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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
        property: u32::from(tpm2::TpmPt::FAMILY_INDICATOR),
        property_count: 5,
    };
    let mut request = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut request[offset..]);
    offset += marshal_to_slice(&(0u32), &mut request[offset..]);
    offset += marshal_to_slice(&(TpmCc::GetCapability.code()), &mut request[offset..]);
    offset += marshal_to_slice(&cmd, &mut request[offset..]);
    let total_size = offset as u32;
    marshal_to_slice(&(total_size), &mut request[2..6]);

    let mut response = [0u8; 1024];
    let res_len =
        tpm.execute_command_separate(&mut global_state, &request[..offset], &mut response);
    assert_eq!(
        u32::from_be_bytes([response[6], response[7], response[8], response[9]]),
        0
    );
    let mut unmarsh = &response[10..res_len];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::TpmProperties(props) = cap_data {
        assert_eq!(props.count(), 5);
        assert_eq!(
            props.tpm_property()[0].property,
            tpm2::TpmPt::FAMILY_INDICATOR
        );
        assert_eq!(props.tpm_property()[0].value, tpm2::TPM_SPEC_FAMILY);
        assert_eq!(props.tpm_property()[1].property, tpm2::TpmPt::LEVEL);
        assert_eq!(props.tpm_property()[1].value, tpm2::TPM_SPEC_LEVEL);
        assert_eq!(props.tpm_property()[2].property, tpm2::TpmPt::REVISION);
        assert_eq!(props.tpm_property()[2].value, tpm2::TPM_SPEC_VERSION);
        assert_eq!(props.tpm_property()[3].property, tpm2::TpmPt::ERRATA);
        assert_eq!(props.tpm_property()[3].value, tpm2::TPM_SPEC_ERRATA);
        assert_eq!(props.tpm_property()[4].property, tpm2::TpmPt::YEAR);
        assert_eq!(props.tpm_property()[4].value, tpm2::TPM_SPEC_YEAR);
    } else {
        panic!("Expected TpmProperties capability data");
    }
}
