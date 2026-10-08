use common::marshal_to_slice;
use tpm2::commands::{Command, ContextSave};

use tpm2::Unmarshal;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

#[test]
fn test_adv_context_save_keystream_reuse() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.initialized = true;
    global_state.locality = 0;
    global_state.sp_seed_size = 32;
    for (i, byte) in global_state.sp_seed.iter_mut().enumerate().take(32) {
        *byte = i as u8;
    }

    let handle: u32 = 0x80000001;

    let mut tpmt_public_buf = [0u8; 1024];
    tpmt_public_buf[0] = 0x00;
    tpmt_public_buf[1] = 0x08; // KeyedHash
    tpmt_public_buf[2] = 0x00;
    tpmt_public_buf[3] = 0x0B; // Sha256
    tpmt_public_buf[10] = 0x00;
    tpmt_public_buf[11] = 0x10; // Null scheme

    global_state.transient_objects[0] = Some(TransientObject {
        handle,
        seed: [0u8; 32],
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: (tpm2::TpmtPublic::unmarshal(&mut (&tpmt_public_buf[..])).unwrap()).into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });

    // We execute ContextSave command twice
    // Format of ContextSave command:
    // Tag: 0x8001
    // Size: 14 (10 + 4 for handle)
    // Command code: 0x00000162 (TPM_CC_ContextSave)
    // Handles: save_handle (4 bytes)
    let mut req1 = [0u8; 14];
    marshal_to_slice(&(0x8001u16), &mut req1[0..2]);
    marshal_to_slice(&(14u32), &mut req1[2..6]);
    marshal_to_slice(&(0x162u32), &mut req1[6..10]);
    marshal_to_slice(&(handle), &mut req1[10..14]);

    let mut rsp1 = [0u8; 4096];
    let rsp1_len = tpm.execute_command_separate(&mut global_state, &req1[..], &mut rsp1[..]);

    // Check success response header
    assert_eq!(u16::from_be_bytes([rsp1[0], rsp1[1]]), 0x8001);
    assert_eq!(u32::from_be_bytes([rsp1[6], rsp1[7], rsp1[8], rsp1[9]]), 0); // Success

    // Unmarshal the ContextSave response parameters starting at offset 10
    let mut unmarshal_buf1 = &rsp1[10..rsp1_len];
    let rsp1_parsed = <ContextSave as Command>::Response::unmarshal(&mut unmarshal_buf1).unwrap();

    let mut rsp2 = [0u8; 4096];
    let rsp2_len = tpm.execute_command_separate(&mut global_state, &req1[..], &mut rsp2[..]);

    // Check success response header
    assert_eq!(u16::from_be_bytes([rsp2[0], rsp2[1]]), 0x8001);
    assert_eq!(u32::from_be_bytes([rsp2[6], rsp2[7], rsp2[8], rsp2[9]]), 0); // Success

    // Unmarshal the ContextSave response parameters starting at offset 10
    let mut unmarshal_buf2 = &rsp2[10..rsp2_len];
    let rsp2_parsed = <ContextSave as Command>::Response::unmarshal(&mut unmarshal_buf2).unwrap();

    let mut data1_unmarshal = rsp1_parsed.context.context_blob.get_buffer();
    let ctx1 = tpm2::TpmsContextData::unmarshal(&mut data1_unmarshal).unwrap();

    let mut data2_unmarshal = rsp2_parsed.context.context_blob.get_buffer();
    let ctx2 = tpm2::TpmsContextData::unmarshal(&mut data2_unmarshal).unwrap();

    assert_ne!(
        rsp1_parsed.context.sequence, rsp2_parsed.context.sequence,
        "Sequence must increment"
    );
    assert_ne!(
        ctx1.encrypted.get_buffer(),
        ctx2.encrypted.get_buffer(),
        "Keystream reuse detected!"
    );
}

#[test]
fn test_context_save_session_success() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.initialized = true;
    global_state.sp_seed_size = 32;

    let session_handle: u32 = 0x03000000;
    global_state
        .add_session(tpm2_impl::handler::SessionState {
            session_handle,
            session_type: tpm2::TpmSe::Policy,
            auth_hash: tpm2::TpmiAlgHash::Sha256,
            nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
            nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
            session_key: [0u8; 128],
            session_key_len: 32,
            symmetric: None,
            bind_entity: tpm2::Handle::RH_NULL,
            bound_entity: (tpm2::Tpm2bName::default()).into(),
            audit_digest: None,
            audit_digest_len: 0,
            audit_cp_hash: [0u8; 64],
            audit_cp_hash_len: 0,
            policy_hash: [0u8; 64],
            policy_hash_len: 0,
            is_cp_hash_defined: false,
            is_name_hash_defined: false,
            is_template_hash_defined: false,
            policy_digest: [0u8; 64],
            policy_digest_len: 32,
            command_code: 0,
            start_time: 0,
            timeout: 0,
            epoch: 0,
            is_auth_value_needed: false,
            is_password_needed: false,
            pcr_counter: None,
            check_nv_written: false,
            nv_written_state: false,
            command_locality: 0,
            include_auth: false,
        })
        .unwrap();

    assert!(global_state.session(session_handle).is_some());

    // ContextSave command
    let mut req = [0u8; 14];
    marshal_to_slice(&(0x8001u16), &mut req[0..2]);
    marshal_to_slice(&(14u32), &mut req[2..6]);
    marshal_to_slice(&(0x162u32), &mut req[6..10]);
    marshal_to_slice(&(session_handle), &mut req[10..14]);

    let mut rsp = [0u8; 4096];
    let rsp_len = tpm.execute_command_separate(&mut global_state, &req[..], &mut rsp[..]);

    assert_eq!(u16::from_be_bytes([rsp[0], rsp[1]]), 0x8001);
    assert_eq!(u32::from_be_bytes([rsp[6], rsp[7], rsp[8], rsp[9]]), 0); // Success

    let mut unmarshal_buf = &rsp[10..rsp_len];
    let rsp_parsed = <ContextSave as Command>::Response::unmarshal(&mut unmarshal_buf).unwrap();

    assert_eq!(rsp_parsed.context.saved_handle.0, session_handle);
    assert_eq!(rsp_parsed.context.hierarchy, tpm2::Handle::RH_NULL);

    // Verify session is flushed from active RAM
    assert!(global_state.session(session_handle).is_none());
}
