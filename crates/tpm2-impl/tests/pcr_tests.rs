use common::marshal_to_slice;
use tpm2::errors::TpmRc;

use tpm2::Unmarshal;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{Command, PCRAllocate, PCRAllocateHandles};
use tpm2::{Handle, TpmCc};
use tpm2::{TpmiAlgHash, TpmlPcrSelection, TpmsPcrSelection};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a mut FakeCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;
    global_state.ph_enable = true;

    // Startup(CLEAR)
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(&startup_response[6..10], &[0, 0, 0, 0]);
    (tpm, global_state)
}

#[test]
fn test_pcr_allocate_success() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap();
    let pcr_allocation = TpmlPcrSelection::from_slice(&[sha256_sel]).unwrap();

    let cmd = PCRAllocate { pcr_allocation };
    let handles = PCRAllocateHandles {
        auth_handle: Handle::RH_PLATFORM,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::PCRAllocate.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc, 0,
        "TPM2_PCR_Allocate under Platform hierarchy should succeed"
    );

    let mut resp_slice = &resp_buf[10..];
    let rsp = <PCRAllocate as Command>::Response::unmarshal(&mut resp_slice)
        .expect("unmarshal <PCRAllocate as Command>::Response");
    assert!(rsp.allocation_success);
    assert_eq!(rsp.max_pcr, 24);
    assert_eq!(rsp.size_needed, 0);
    assert_eq!(rsp.size_available, 1024);
}

#[test]
fn test_pcr_allocate_unauthorized_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap();
    let pcr_allocation = TpmlPcrSelection::from_slice(&[sha256_sel]).unwrap();

    let cmd = PCRAllocate { pcr_allocation };
    let handles = PCRAllocateHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::PCRAllocate.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_ne!(rc, 0, "TPM2_PCR_Allocate under Owner hierarchy should fail");
}

#[test]
fn test_pcr_allocate_missing_drtm_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let sha1_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[0x00, 0x00, 0x00]).unwrap();
    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x00, 0x00, 0x00]).unwrap();
    let sha384_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha384, &[0x00, 0x00, 0x00]).unwrap();
    let pcr_allocation = TpmlPcrSelection::from_slice(&[sha1_sel, sha256_sel, sha384_sel]).unwrap();

    let cmd = PCRAllocate { pcr_allocation };
    let handles = PCRAllocateHandles {
        auth_handle: Handle::RH_PLATFORM,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::PCRAllocate.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::PCR.get(),
        "TPM2_PCR_Allocate missing HCRTM or DRTM PCR should return TPM_RC_PCR"
    );
}

#[test]
fn test_pcr_reconfig_blocks_shutdown_state() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Reallocate PCRs
    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap();
    let pcr_allocation = TpmlPcrSelection::from_slice(&[sha256_sel]).unwrap();
    let cmd = PCRAllocate { pcr_allocation };
    let handles = PCRAllocateHandles {
        auth_handle: Handle::RH_PLATFORM,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::PCRAllocate.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_eq!(rc, 0);

    // 2. Try TPM2_Shutdown(STATE) -> should fail with TpmRc::TYPE
    let shutdown_req = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size
        0x00, 0x00, 0x01, 0x45, // TPM_CC_Shutdown
        0x00, 0x01, // TPM_SU_STATE
    ];
    let mut shutdown_resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &shutdown_req[..], &mut shutdown_resp[..]);

    let rc = u32::from_be_bytes(shutdown_resp[6..10].try_into().unwrap());
    // It should be TpmRc::TYPE for parameter 1 (shutdownType)
    assert_eq!(
        rc,
        TpmRc::TYPE.with(tpm2::errors::Position::parameter(1)).get(),
        "TPM2_Shutdown(STATE) should fail if PCR reconfig is pending"
    );

    // 3. Try TPM2_Shutdown(CLEAR) -> should succeed
    let shutdown_clear_req = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size
        0x00, 0x00, 0x01, 0x45, // TPM_CC_Shutdown
        0x00, 0x00, // TPM_SU_CLEAR
    ];
    let mut shutdown_clear_resp = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &shutdown_clear_req[..],
        &mut shutdown_clear_resp[..],
    );
    let rc = u32::from_be_bytes(shutdown_clear_resp[6..10].try_into().unwrap());
    assert_eq!(
        rc, 0,
        "TPM2_Shutdown(CLEAR) should succeed even with PCR reconfig pending"
    );
}

#[test]
fn test_drtm_post_startup_sequence_and_termination() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let mut resp = [0u8; 256];
    assert_eq!(global_state.drtm_handle, Handle::RH_UNASSIGNED.0);

    // Pre-populate PCR 18 with non-zero data to verify PCRResetDynamics resets 17..=22
    global_state.pcrs.sha256[18] = [0xAA; 32];
    let initial_restart_count = global_state.restart_count;

    // 2. Start DRTM sequence (_TPM_Hash_Start)
    assert!(tpm.hash_start(&mut global_state));
    assert_eq!(global_state.drtm_handle, 0x80000000);
    assert!(global_state.find_active_sequence(0x80000000).is_some());

    // 3. Feed data (_TPM_Hash_Data)
    let payload = b"DRTM Measurement Payload";
    assert!(tpm.hash_data(&mut global_state, payload));

    // 4. Complete DRTM sequence (_TPM_Hash_End)
    assert!(tpm.hash_end(&mut global_state));
    assert_eq!(global_state.drtm_handle, Handle::RH_UNASSIGNED.0);
    assert!(global_state.find_active_sequence(0x80000000).is_none());

    // Dynamic PCRs 17..=22 were reset; PCR 18 must be 0x00
    assert_eq!(global_state.pcrs.sha256[18], [0x00; 32]);
    // restart_count must have incremented
    assert_eq!(global_state.restart_count, initial_restart_count + 1);

    // Compute expected PCR 17 value: Hash(0x00..00 || Hash(payload))
    use tpm2_impl::hash_state::StreamingHashState;
    let mut h_payload = StreamingHashState::new(TpmiAlgHash::Sha256);
    h_payload.update(payload);
    let (digest, _) = h_payload.finalize();

    let mut h_pcr17 = StreamingHashState::new(TpmiAlgHash::Sha256);
    h_pcr17.update(&[0u8; 32]);
    h_pcr17.update(&digest[..32]);
    let (expected_pcr17, _) = h_pcr17.finalize();
    assert_eq!(global_state.pcrs.sha256[17], expected_pcr17[..32]);

    // 5. Verify that executing any regular TPM command aborts an in-flight DRTM sequence
    assert!(tpm.hash_start(&mut global_state));
    assert_eq!(global_state.drtm_handle, 0x80000000);
    assert!(tpm.hash_data(&mut global_state, b"interrupted"));

    // Send TPM2_GetRandom command -> must terminate DRTM sequence via ObjectTerminateEvent
    let get_random_req = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x08,
    ];
    tpm.execute_command_separate(&mut global_state, &get_random_req, &mut resp);
    assert_eq!(global_state.drtm_handle, Handle::RH_UNASSIGNED.0);
    assert!(global_state.find_active_sequence(0x80000000).is_none());
    // Subsequent hash_end must return false without modifying PCR 17
    assert!(!tpm.hash_end(&mut global_state));
    assert_eq!(global_state.pcrs.sha256[17], expected_pcr17[..32]);
}

#[test]
fn test_hcrtm_pre_startup_sequence_and_slot_eviction() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;
    global_state.ph_enable = true;

    // Fill all 3 sequence/transient slots before starting H-CRTM sequence
    for (i, slot) in global_state.active_sequences.iter_mut().enumerate().take(3) {
        *slot = Some(tpm2_impl::ActiveSequence::new(
            0x8000_0000 | (i as u32),
            tpm2::Tpm2bAuth::default(),
            tpm2_impl::SequenceType::Event,
        ));
    }

    // 1. Pre-startup _TPM_Hash_Start must evict slot 0 (0x80000000) and succeed
    assert!(tpm.hash_start(&mut global_state));
    assert_eq!(global_state.drtm_handle, 0x80000000);

    // 2. Feed H-CRTM data
    let hcrtm_data = b"H-CRTM Bootloader Measurement";
    assert!(tpm.hash_data(&mut global_state, hcrtm_data));

    // 3. Complete H-CRTM before TPM2_Startup
    assert!(tpm.hash_end(&mut global_state));
    assert!(global_state.drtm_pre_startup);
    assert_eq!(global_state.drtm_handle, Handle::RH_UNASSIGNED.0);

    // Expected PCR 0 before and after Startup(CLEAR): Hash(0x00..04 || Hash(hcrtm_data))
    use tpm2_impl::hash_state::StreamingHashState;
    let mut h_payload = StreamingHashState::new(TpmiAlgHash::Sha256);
    h_payload.update(hcrtm_data);
    let (digest, _) = h_payload.finalize();

    let mut initial_pcr0 = [0u8; 32];
    initial_pcr0[31] = 4;
    let mut h_pcr0 = StreamingHashState::new(TpmiAlgHash::Sha256);
    h_pcr0.update(&initial_pcr0);
    h_pcr0.update(&digest[..32]);
    let (expected_pcr0, _) = h_pcr0.finalize();
    assert_eq!(global_state.pcrs.sha256[0], expected_pcr0[..32]);

    // 4. Issue TPM2_Startup(CLEAR) and verify PCR 0 is preserved
    let startup_req = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_req, &mut resp);
    assert_eq!(u32::from_be_bytes(resp[6..10].try_into().unwrap()), 0);
    assert_eq!(global_state.pcrs.sha256[0], expected_pcr0[..32]);
}

#[test]
fn test_pcr_allocate_persists_across_startup_clear() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Allocate PCRs: enable sha256 with [0xFF, 0xFF, 0xFF] and sha384 with [0xFF, 0xFF, 0xFF]
    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap();
    let sha384_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha384, &[0xFF, 0xFF, 0xFF]).unwrap();
    let pcr_allocation = TpmlPcrSelection::from_slice(&[sha256_sel, sha384_sel]).unwrap();

    let cmd = PCRAllocate { pcr_allocation };
    let handles = PCRAllocateHandles {
        auth_handle: Handle::RH_PLATFORM,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8001u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::PCRAllocate.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_eq!(rc, 0, "TPM2_PCR_Allocate should succeed");

    // Verify allocation in global_state before shutdown: Sha384 was modified to [0xFF, 0xFF, 0xFF]
    let allocated_before_shutdown = global_state.pcrs.pcr_allocation;
    let sha384_selection = allocated_before_shutdown
        .pcr_selections()
        .find(|s| s.hash() == TpmiAlgHash::Sha384)
        .expect("Sha384 selection exists");
    assert_eq!(sha384_selection.pcr_select(), &[0xFF, 0xFF, 0xFF]);

    // 2. Shutdown(CLEAR)
    let shutdown_clear_req = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size
        0x00, 0x00, 0x01, 0x45, // TPM_CC_Shutdown
        0x00, 0x00, // TPM_SU_CLEAR
    ];
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &shutdown_clear_req[..], &mut resp[..]);
    assert_eq!(u32::from_be_bytes(resp[6..10].try_into().unwrap()), 0);

    // 3. Platform reset (_TPM_Init) followed by Startup(CLEAR)
    global_state.initialized = false;
    let startup_req = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    tpm.execute_command_separate(&mut global_state, &startup_req, &mut resp);
    assert_eq!(u32::from_be_bytes(resp[6..10].try_into().unwrap()), 0);

    // 4. Verify that configured PCR allocation was preserved across Startup(CLEAR)
    assert_eq!(
        global_state.pcrs.pcr_allocation, allocated_before_shutdown,
        "Startup(CLEAR) must not wipe configured PCR allocation"
    );
    let sha384_after_startup = global_state
        .pcrs
        .pcr_allocation
        .pcr_selections()
        .find(|s| s.hash() == TpmiAlgHash::Sha384)
        .expect("Sha384 selection exists");
    assert_eq!(sha384_after_startup.pcr_select(), &[0xFF, 0xFF, 0xFF]);
}
