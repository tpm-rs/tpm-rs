use common::marshal_to_slice;
use tpm2::errors::{Position, TpmRc};

use tpm2::Unmarshal;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

#[test]
fn test_adv_context_load_hmac_tampering() {
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

    let handle: u32 = 0x80000001;
    let mut tpmt_public_buf = [0u8; 1024];
    tpmt_public_buf[0] = 0x00;
    tpmt_public_buf[1] = 0x08;
    tpmt_public_buf[2] = 0x00;
    tpmt_public_buf[3] = 0x0B;
    tpmt_public_buf[10] = 0x00;
    tpmt_public_buf[11] = 0x10;

    global_state.transient_objects[0] = Some(TransientObject {
        handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: (tpm2::TpmtPublic::unmarshal(&mut (&tpmt_public_buf[..])).unwrap()).into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });

    // We execute ContextSave command
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
    let mut unmarshal_buf = &rsp1[10..rsp1_len];
    let rsp1_parsed =
        <tpm2::commands::ContextSave as tpm2::commands::Command>::Response::unmarshal(
            &mut unmarshal_buf,
        )
        .unwrap();

    let mut tampered_context = rsp1_parsed.context;
    tampered_context.saved_handle.0 ^= 0x01; // Tamper with the handle

    let req2_cmd = tpm2::commands::ContextLoad {
        context: tampered_context,
    };

    // Format of ContextLoad command:
    // Tag: 0x8001
    // Size: 10 + size of ContextLoad parameters
    // Command code: 0x00000161 (TPM_CC_ContextLoad)
    let mut req2 = [0u8; 4096];
    marshal_to_slice(&(0x8001u16), &mut req2[0..2]);
    marshal_to_slice(
        &(
            // we'll write size later
            0x161u32
        ),
        &mut req2[6..10],
    );
    let parameters_len = marshal_to_slice(&(req2_cmd), &mut req2[10..]);
    let total_len2 = (10 + parameters_len) as u32;
    marshal_to_slice(&(total_len2), &mut req2[2..6]);

    let mut rsp2 = [0u8; 4096];
    tpm.execute_command_separate(
        &mut global_state,
        &req2[..total_len2 as usize],
        &mut rsp2[..],
    );

    // Check response error code (offset 6..10)
    let rc = u32::from_be_bytes([rsp2[6], rsp2[7], rsp2[8], rsp2[9]]);
    // C: TPM_RCS_INTEGRITY + RC_ContextLoad_context (0x1DF), ContextLoad.c:76.
    assert_eq!(
        rc,
        TpmRc::INTEGRITY.with(Position::parameter(1)).get(),
        "HMAC check should fail!"
    );
}

#[test]
fn test_context_save_load_uses_hierarchy_proof_and_ignores_sp_seed() {
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
    global_state.sh_proof = [0x42; 64];
    global_state.sh_proof_size = 64;

    let handle: u32 = 0x80000001;
    let mut tpmt_public_buf = [0u8; 1024];
    tpmt_public_buf[0] = 0x00;
    tpmt_public_buf[1] = 0x08;
    tpmt_public_buf[2] = 0x00;
    tpmt_public_buf[3] = 0x0B;
    tpmt_public_buf[10] = 0x00;
    tpmt_public_buf[11] = 0x10;

    global_state.transient_objects[0] = Some(TransientObject {
        handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: (tpm2::TpmtPublic::unmarshal(&mut (&tpmt_public_buf[..])).unwrap()).into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001, // RH_OWNER
        st_clear: false,
    });

    let mut req1 = [0u8; 14];
    marshal_to_slice(&(0x8001u16), &mut req1[0..2]);
    marshal_to_slice(&(14u32), &mut req1[2..6]);
    marshal_to_slice(&(0x162u32), &mut req1[6..10]);
    marshal_to_slice(&(handle), &mut req1[10..14]);

    let mut rsp1 = [0u8; 4096];
    let rsp1_len = tpm.execute_command_separate(&mut global_state, &req1[..], &mut rsp1[..]);
    assert_eq!(u32::from_be_bytes([rsp1[6], rsp1[7], rsp1[8], rsp1[9]]), 0);

    let mut unmarshal_buf = &rsp1[10..rsp1_len];
    let rsp1_parsed =
        <tpm2::commands::ContextSave as tpm2::commands::Command>::Response::unmarshal(
            &mut unmarshal_buf,
        )
        .unwrap();

    // Mutate sp_seed completely: ContextLoad should still succeed since proof is used instead of sp_seed
    global_state.sp_seed = [0xFF; 64];

    let req2_cmd = tpm2::commands::ContextLoad {
        context: rsp1_parsed.context,
    };
    let mut req2 = [0u8; 4096];
    marshal_to_slice(&(0x8001u16), &mut req2[0..2]);
    marshal_to_slice(&(0x161u32), &mut req2[6..10]);
    let parameters_len = marshal_to_slice(&(req2_cmd), &mut req2[10..]);
    let total_len2 = (10 + parameters_len) as u32;
    marshal_to_slice(&(total_len2), &mut req2[2..6]);

    let mut rsp2 = [0u8; 4096];
    tpm.execute_command_separate(
        &mut global_state,
        &req2[..total_len2 as usize],
        &mut rsp2[..],
    );
    let rc_success = u32::from_be_bytes([rsp2[6], rsp2[7], rsp2[8], rsp2[9]]);
    assert_eq!(
        rc_success, 0,
        "ContextLoad should succeed even if sp_seed changed"
    );

    // Mutate sh_proof: ContextLoad should fail with INTEGRITY
    global_state.sh_proof[0] ^= 0x01;
    let mut rsp3 = [0u8; 4096];
    tpm.execute_command_separate(
        &mut global_state,
        &req2[..total_len2 as usize],
        &mut rsp3[..],
    );
    let rc_fail = u32::from_be_bytes([rsp3[6], rsp3[7], rsp3[8], rsp3[9]]);
    assert_eq!(
        rc_fail,
        // C: TPM_RCS_INTEGRITY + RC_ContextLoad_context (0x1DF), ContextLoad.c:76.
        TpmRc::INTEGRITY.with(Position::parameter(1)).get(),
        "ContextLoad must fail when hierarchy proof changes"
    );
}

#[test]
fn test_context_load_fails_on_total_reset_count_and_st_clear_count_changes() {
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
    global_state.total_reset_count = 10;
    global_state.clear_count = 5;

    let handle: u32 = 0x80000001;
    let mut tpmt_public_buf = [0u8; 1024];
    tpmt_public_buf[0] = 0x00;
    tpmt_public_buf[1] = 0x08;
    tpmt_public_buf[2] = 0x00;
    tpmt_public_buf[3] = 0x0B;
    // Set ST_CLEAR (bit 1 = 0x00000002) in objectAttributes (offset 4..8)
    tpmt_public_buf[7] = 0x02;
    tpmt_public_buf[10] = 0x00;
    tpmt_public_buf[11] = 0x10;

    global_state.transient_objects[0] = Some(TransientObject {
        handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: (tpm2::TpmtPublic::unmarshal(&mut (&tpmt_public_buf[..])).unwrap()).into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: true,
    });

    let mut req1 = [0u8; 14];
    marshal_to_slice(&(0x8001u16), &mut req1[0..2]);
    marshal_to_slice(&(14u32), &mut req1[2..6]);
    marshal_to_slice(&(0x162u32), &mut req1[6..10]);
    marshal_to_slice(&(handle), &mut req1[10..14]);

    let mut rsp1 = [0u8; 4096];
    let rsp1_len = tpm.execute_command_separate(&mut global_state, &req1[..], &mut rsp1[..]);
    assert_eq!(u32::from_be_bytes([rsp1[6], rsp1[7], rsp1[8], rsp1[9]]), 0);

    let mut unmarshal_buf = &rsp1[10..rsp1_len];
    let rsp1_parsed =
        <tpm2::commands::ContextSave as tpm2::commands::Command>::Response::unmarshal(
            &mut unmarshal_buf,
        )
        .unwrap();
    assert_eq!(rsp1_parsed.context.saved_handle.0, 0x80000002);

    let req2_cmd = tpm2::commands::ContextLoad {
        context: rsp1_parsed.context,
    };
    let mut req2 = [0u8; 4096];
    marshal_to_slice(&(0x8001u16), &mut req2[0..2]);
    marshal_to_slice(&(0x161u32), &mut req2[6..10]);
    let parameters_len = marshal_to_slice(&(req2_cmd), &mut req2[10..]);
    let total_len2 = (10 + parameters_len) as u32;
    marshal_to_slice(&(total_len2), &mut req2[2..6]);

    // 1. Incrementing clear_count should invalidate ST_CLEAR context (0x80000002)
    global_state.clear_count = 6;
    let mut rsp2 = [0u8; 4096];
    tpm.execute_command_separate(
        &mut global_state,
        &req2[..total_len2 as usize],
        &mut rsp2[..],
    );
    let rc_clear = u32::from_be_bytes([rsp2[6], rsp2[7], rsp2[8], rsp2[9]]);
    assert_eq!(
        rc_clear,
        // C: TPM_RCS_INTEGRITY + RC_ContextLoad_context (0x1DF), ContextLoad.c:76.
        TpmRc::INTEGRITY.with(Position::parameter(1)).get(),
        "ST_CLEAR context must fail when clear_count increments"
    );

    // Restore clear_count, increment total_reset_count: must fail with INTEGRITY
    global_state.clear_count = 5;
    global_state.total_reset_count = 11;
    let mut rsp3 = [0u8; 4096];
    tpm.execute_command_separate(
        &mut global_state,
        &req2[..total_len2 as usize],
        &mut rsp3[..],
    );
    let rc_reset = u32::from_be_bytes([rsp3[6], rsp3[7], rsp3[8], rsp3[9]]);
    assert_eq!(
        rc_reset,
        // C: TPM_RCS_INTEGRITY + RC_ContextLoad_context (0x1DF), ContextLoad.c:76.
        TpmRc::INTEGRITY.with(Position::parameter(1)).get(),
        "Context must fail when total_reset_count increments"
    );
}
