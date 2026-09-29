use common::marshal_to_slice;

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::errors::TpmRc;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

#[test]
fn test_clear_overflow() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    // Set clear_count to MAX
    global_state.clear_count = u32::MAX;

    // Clear command: authHandle=0x4000000A (TPM_RH_PLATFORM)
    // 8001 (tag) 0000000e (size) 00000126 (cc) 4000000a (handle)
    let clear_request = hex!(
        "8001" // tag
        "0000000e" // size
        "00000126" // TPM_CC_Clear
        "4000000a" // TPM_RH_PLATFORM
    );
    let mut clear_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &clear_request[..],
        &mut clear_response[..],
    );

    // Should not panic, should return Success
    assert_eq!(&clear_response[6..10], &[0, 0, 0, 0]);
}

fn create_test_primary(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
) -> u32 {
    use tpm2::Handle;
    use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};
    use tpm2::{
        PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash,
        TpmlPcrSelection, TpmsSensitiveCreate, TpmtPublic,
    };
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let attrs = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
    let pub_tmpl = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };
    let in_public = tpm2::Tpm2b(pub_tmpl);
    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreatePrimaryHandles {
        primary_handle: Handle(0x40000001),
    };
    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(0x00000131u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);
    use tpm2::{Tpm2bNonce, TpmaSession, TpmsAuthCommand};
    let auth_len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    let auth_start = offset;
    let pw_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    offset += marshal_to_slice(&(pw_auth), &mut req_buf[offset..]);
    let auth_len = (offset - auth_start) as u32;
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);
    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    req_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    let mut resp_buf = [0u8; 1024];
    let _ = tpm.execute_command_separate(global_state, &req_buf[..offset], &mut resp_buf[..]);
    u32::from_be_bytes(resp_buf[10..14].try_into().unwrap())
}

#[test]
fn test_import_table31_attribute_precedence() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    let parent_handle = create_test_primary(&mut tpm, &mut global_state);

    // Construct TPM2_Import command with fixedTPM attribute set on object_public (Pos2)
    // Table 31 mandates that fixedTPM MUST be clear for imported objects, returning TPM_RC_ATTRIBUTES at Pos2 (0x240)
    use tpm2::Handle;
    use tpm2::commands::{Import, ImportHandles};
    use tpm2::errors::{Position, TpmRc};
    use tpm2::{
        PublicParmsAndId, Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, TpmaObject, TpmiAlgHash,
        TpmiRsaKeyBits, TpmsRsaParms, TpmtPublic, TpmtSymDefObject,
    };

    let bad_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::FIXED_TPM,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };

    let import_handles = ImportHandles {
        parent_handle: Handle(parent_handle),
    };
    let import_cmd = Import {
        encryption_key: Tpm2bData::from_bytes(&[0u8; 16]).unwrap(),
        object_public: tpm2::Tpm2b(bad_pub),
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB))),
    };

    let mut cmd_buf = [0u8; 2048];
    let mut offset = 0;
    cmd_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes()); // tag = Sessions
    offset += 6; // skip size for now
    cmd_buf[6..10].copy_from_slice(&0x00000156u32.to_be_bytes()); // CC_Import
    offset += 4;
    offset += marshal_to_slice(&(import_handles), &mut cmd_buf[offset..]);
    use tpm2::{Tpm2bAuth, Tpm2bNonce, TpmaSession, TpmsAuthCommand};
    let auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buf = [0u8; 100];
    let auth_len = marshal_to_slice(&auth, &mut auth_buf);
    cmd_buf[offset..offset + 4].copy_from_slice(&(auth_len as u32).to_be_bytes());
    offset += 4;
    cmd_buf[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
    offset += auth_len;
    offset += marshal_to_slice(&(import_cmd), &mut cmd_buf[offset..]);
    cmd_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut rsp_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &cmd_buf[..offset], &mut rsp_buf[..]);
    let rc = u32::from_be_bytes([rsp_buf[6], rsp_buf[7], rsp_buf[8], rsp_buf[9]]);
    assert_eq!(
        rc,
        TpmRc::ATTRIBUTES.with(Position::parameter(2)).get(),
        "TPM2_Import with fixedTPM set must return TPM_RC_ATTRIBUTES at Pos2 per Table 31"
    );
}

#[test]
fn test_evict_control_table31_precedence() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    use tpm2::Handle;
    use tpm2::commands::{EvictControl, EvictControlHandles};
    // Call EvictControl on transient handle 0x80000001 (which does not exist) -> must check range / existence cleanly
    let ec_handles = EvictControlHandles {
        auth: Handle(0x40000001),
        object_handle: Handle(0x80000001),
    };
    let ec_cmd = EvictControl {
        persistent_handle: Handle(0x81000000),
    };

    let mut cmd_buf = [0u8; 256];
    let mut offset = 0;
    cmd_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes()); // tag = Sessions
    offset += 6;
    cmd_buf[6..10].copy_from_slice(&0x00000120u32.to_be_bytes()); // CC_EvictControl
    offset += 4;
    offset += marshal_to_slice(&(ec_handles), &mut cmd_buf[offset..]);
    use tpm2::{Tpm2bAuth, Tpm2bNonce, TpmaSession, TpmsAuthCommand};
    let auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buf = [0u8; 100];
    let auth_len = marshal_to_slice(&auth, &mut auth_buf);
    cmd_buf[offset..offset + 4].copy_from_slice(&(auth_len as u32).to_be_bytes());
    offset += 4;
    cmd_buf[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
    offset += auth_len;
    offset += marshal_to_slice(&(ec_cmd), &mut cmd_buf[offset..]);
    cmd_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut rsp_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &cmd_buf[..offset], &mut rsp_buf[..]);
    let rc = u32::from_be_bytes([rsp_buf[6], rsp_buf[7], rsp_buf[8], rsp_buf[9]]);
    assert_eq!(
        rc,
        TpmRc::REFERENCE_H1.get(),
        "TPM2_EvictControl on missing transient handle returns TPM_RC_REFERENCE_H1 cleanly for handle 1"
    );
}

#[test]
fn test_testing_commands_engine_execution() {
    use tpm2::commands::{
        GetTestResult, GetTestResultRsp, IncrementalSelfTest, IncrementalSelfTestRsp, SelfTest,
    };
    use tpm2::{Alg, Command, CommandHeader, ResponseHeader, TpmiStCommandTag, TpmlAlg, Unmarshal};

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    // 1. IncrementalSelfTest
    let inc_cmd = IncrementalSelfTest {
        to_test: TpmlAlg::from_slice(&[Alg::RSA]).unwrap(),
    };
    let mut cmd_buf = [0u8; 256];
    let body_len = marshal_to_slice(&inc_cmd, &mut cmd_buf[10..]);
    let hdr = CommandHeader {
        tag: TpmiStCommandTag::NoSessions,
        size: (10 + body_len) as u32,
        code: IncrementalSelfTest::CMD_CODE,
    };
    marshal_to_slice(&hdr, &mut cmd_buf[..10]);
    let mut rsp_buf = [0u8; 256];
    let rsp_len = tpm.execute_command_separate(
        &mut global_state,
        &cmd_buf[..10 + body_len],
        &mut rsp_buf[..],
    );
    let mut slice = &rsp_buf[..rsp_len];
    let rsp_hdr = ResponseHeader::unmarshal(&mut slice).unwrap();
    assert_eq!(rsp_hdr.rc, Ok(()));
    let inc_rsp = IncrementalSelfTestRsp::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    assert!(inc_rsp.to_do_list.count() <= 32);

    // 2. SelfTest
    let st_cmd = SelfTest { full_test: true };
    let body_len = marshal_to_slice(&st_cmd, &mut cmd_buf[10..]);
    let hdr = CommandHeader {
        tag: TpmiStCommandTag::NoSessions,
        size: (10 + body_len) as u32,
        code: SelfTest::CMD_CODE,
    };
    marshal_to_slice(&hdr, &mut cmd_buf[..10]);
    let rsp_len = tpm.execute_command_separate(
        &mut global_state,
        &cmd_buf[..10 + body_len],
        &mut rsp_buf[..],
    );
    let mut slice = &rsp_buf[..rsp_len];
    let rsp_hdr = ResponseHeader::unmarshal(&mut slice).unwrap();
    assert_eq!(rsp_hdr.rc, Ok(()));
    assert!(slice.is_empty());

    // 3. GetTestResult
    let gtr_cmd = GetTestResult {};
    let body_len = marshal_to_slice(&gtr_cmd, &mut cmd_buf[10..]);
    let hdr = CommandHeader {
        tag: TpmiStCommandTag::NoSessions,
        size: (10 + body_len) as u32,
        code: GetTestResult::CMD_CODE,
    };
    marshal_to_slice(&hdr, &mut cmd_buf[..10]);
    let rsp_len = tpm.execute_command_separate(
        &mut global_state,
        &cmd_buf[..10 + body_len],
        &mut rsp_buf[..],
    );
    let mut slice = &rsp_buf[..rsp_len];
    let rsp_hdr = ResponseHeader::unmarshal(&mut slice).unwrap();
    assert_eq!(rsp_hdr.rc, Ok(()));
    let gtr_rsp = GetTestResultRsp::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    assert_eq!(gtr_rsp.test_result, Ok(()));

    // 4. IncrementalSelfTest with reserved Alg ID (0x0000):
    // - Exact buffer -> fails during command execution with VALUE | P | 1
    // - Trailing bytes -> fails during dispatch with SIZE (not VALUE)
    // - Truncated buffer after reserved alg[0] -> fails during unmarshal with INSUFFICIENT (not VALUE)
    let reserved_exact = hex!("8001 00000010 00000142 00000001 0000");
    let rsp_len =
        tpm.execute_command_separate(&mut global_state, &reserved_exact[..], &mut rsp_buf[..]);
    let mut slice = &rsp_buf[..rsp_len];
    let rsp_hdr = ResponseHeader::unmarshal(&mut slice).unwrap();
    assert_eq!(
        rsp_hdr.rc,
        Err(tpm2::errors::TpmRc::VALUE.with(tpm2::errors::Position::parameter(1)))
    );

    let reserved_trailing = hex!("8001 00000011 00000142 00000001 0000 FF");
    let rsp_len =
        tpm.execute_command_separate(&mut global_state, &reserved_trailing[..], &mut rsp_buf[..]);
    let mut slice = &rsp_buf[..rsp_len];
    let rsp_hdr = ResponseHeader::unmarshal(&mut slice).unwrap();
    assert_eq!(rsp_hdr.rc, Err(tpm2::errors::TpmRc::SIZE.to_rc()));

    let reserved_truncated = hex!("8001 00000011 00000142 00000002 0000 00");
    let rsp_len =
        tpm.execute_command_separate(&mut global_state, &reserved_truncated[..], &mut rsp_buf[..]);
    let mut slice = &rsp_buf[..rsp_len];
    let rsp_hdr = ResponseHeader::unmarshal(&mut slice).unwrap();
    assert_eq!(
        rsp_hdr.rc,
        Err(tpm2::errors::TpmRc::INSUFFICIENT.with(tpm2::errors::Position::parameter(1)))
    );
}
