use tpm2::{Handle, TpmSe, TpmiAlgHash};
use tpm2_impl::handler::SessionState;
use tpm2_impl::storage::manager::StorageManager;
use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
use tpm2_impl::storage::transcoder::{
    HIERARCHY_AUTH_HANDLE, NV_MEMORY_SIZE, transcode_s_nv_to_storage, transcode_storage_to_s_nv,
};
use tpm2_impl::storage::translator::{
    Ibmswtpm2StateDto, S_OBJECTS_SIZE, S_PCRS_SIZE, S_SESSIONS_SIZE, TpmStateTranslator,
};
use tpm2_impl::storage::{NvStorage, StorageError, Tpm2Storage};
use tpm2_impl::{ActiveSequence, GlobalState, SequenceType};

// =========================================================================
// Tests from src/storage/ram_storage_mock.rs
// =========================================================================

#[test]
fn test_ram_storage() {
    let mut storage = RamStorageMock::<128>::new();
    let write_buf = b"hello tpm2";
    storage.write_nv(10, write_buf).unwrap();

    let mut read_buf = [0u8; 10];
    storage.read_nv(10, &mut read_buf).unwrap();
    assert_eq!(&read_buf, write_buf);

    // Out of bounds
    assert!(storage.read_nv(120, &mut [0u8; 20]).is_err());
    assert!(storage.write_nv(120, &[0u8; 20]).is_err());
}

// =========================================================================
// Tests from src/storage/manager.rs
// =========================================================================

#[test]
fn test_manager_define_write_read() {
    let mut ram = RamStorageMock::<1024>::new();
    let mut manager = StorageManager::new(&mut ram);

    // Define a 64 byte NV index
    manager.define_space(0x01500000, 64, 0).unwrap();

    let msg = b"TPM test message";
    manager.write_item(0x01500000, 0, msg).unwrap();

    let mut out = [0u8; 16];
    manager.read_item(0x01500000, 0, &mut out).unwrap();
    assert_eq!(&out, msg);

    let meta = manager.get_metadata(0x01500000).unwrap();
    assert_eq!(meta.data_size, 64);
    assert_eq!(meta.attributes, 0);
}

#[test]
fn test_manager_compaction() {
    let mut ram = RamStorageMock::<1024>::new();
    let mut manager = StorageManager::new(&mut ram);

    manager.define_space(0x81000001, 10, 0).unwrap(); // Persistent Key 1
    manager.define_space(0x81000002, 20, 0).unwrap(); // Persistent Key 2
    manager.define_space(0x81000003, 10, 0).unwrap(); // Persistent Key 3

    manager.write_item(0x81000001, 0, &[1; 10]).unwrap();
    manager.write_item(0x81000002, 0, &[2; 20]).unwrap();
    manager.write_item(0x81000003, 0, &[3; 10]).unwrap();

    // Remove the middle one
    manager.undefine_space(0x81000002).unwrap();

    // Ensure key 3 shifted correctly and is still readable
    let mut out = [0u8; 10];
    manager.read_item(0x81000003, 0, &mut out).unwrap();
    assert_eq!(&out, &[3; 10]);

    // Key 2 should be gone
    assert_eq!(
        manager.read_item(0x81000002, 0, &mut out),
        Err(StorageError::AccessDenied)
    );
}

// =========================================================================
// Tests from src/storage/transcoder.rs
// =========================================================================

#[test]
fn test_bidirectional_s_nv_transcoder_roundtrip() {
    let mut storage_src = RamStorageMock::<16384>::new();

    // Populate reserved header fields in `storage_src` (0..128)
    storage_src.write_nv(0, &42u32.to_be_bytes()).unwrap(); // reset_count
    storage_src.write_nv(4, &0x0001u16.to_be_bytes()).unwrap(); // orderly_state (SU_STATE)
    storage_src.write_nv(8, &105u32.to_be_bytes()).unwrap(); // total_reset_count
    storage_src
        .write_nv(16, &0x0123456789ABCDEFu64.to_be_bytes())
        .unwrap(); // max_counter
    storage_src
        .write_nv(24, &0x1122334455667788u64.to_be_bytes())
        .unwrap(); // time_epoch
    storage_src.write_nv(32, &7u32.to_be_bytes()).unwrap(); // failed_tries

    let mut drbg_buf = [0u8; 76];
    drbg_buf[0..8].copy_from_slice(&0x47425244u64.to_be_bytes()); // DRBG_MAGIC
    drbg_buf[8..16].copy_from_slice(&99u64.to_be_bytes()); // reseed_counter
    storage_src.write_nv(36, &drbg_buf).unwrap();

    let mut timers_buf = [0u8; 16];
    timers_buf[0..8].copy_from_slice(&(-500i64).to_be_bytes()); // self_heal_timer
    timers_buf[8..16].copy_from_slice(&(-1200i64).to_be_bytes()); // lockout_timer
    storage_src.write_nv(112, &timers_buf).unwrap();

    // Populate dynamic TOC items via StorageManager
    {
        let mut mgr = StorageManager::new(&mut storage_src);

        // Define a persistent object (0x81000001)
        mgr.define_space(0x81000001, 32, 0x00040072).unwrap();
        mgr.write_item(0x81000001, 0, &[0xAB; 32]).unwrap();

        // Define a dynamic NV index (0x01500001)
        mgr.define_space(0x01500001, 16, 0x02000002).unwrap();
        mgr.write_item(0x01500001, 0, &[0xCD; 16]).unwrap();
    }

    // Transcode `storage_src` -> monolithic 16 KB `s_NV`
    let mut s_nv = [0u8; NV_MEMORY_SIZE];
    transcode_storage_to_s_nv(&mut storage_src, &mut s_nv).unwrap();

    // Verify scalar offsets in `s_NV`
    assert_eq!(u32::from_be_bytes(s_nv[740..744].try_into().unwrap()), 42);
    assert_eq!(u32::from_be_bytes(s_nv[732..736].try_into().unwrap()), 105);
    assert_eq!(
        u16::from_be_bytes(s_nv[748..750].try_into().unwrap()),
        0x0001
    );
    assert_eq!(
        u64::from_be_bytes(s_nv[750..758].try_into().unwrap()),
        0x1122334455667788
    );
    assert_eq!(u32::from_be_bytes(s_nv[744..748].try_into().unwrap()), 7);

    // Transcode monolithic 16 KB `s_NV` -> new `storage_dst`
    let mut storage_dst = RamStorageMock::<16384>::new();
    transcode_s_nv_to_storage(&s_nv, &mut storage_dst).unwrap();

    // Verify reserved header in `storage_dst`
    let mut buf4 = [0u8; 4];
    storage_dst.read_nv(0, &mut buf4).unwrap();
    assert_eq!(u32::from_be_bytes(buf4), 42);

    let mut buf2 = [0u8; 2];
    storage_dst.read_nv(4, &mut buf2).unwrap();
    assert_eq!(u16::from_be_bytes(buf2), 0x0001);

    storage_dst.read_nv(8, &mut buf4).unwrap();
    assert_eq!(u32::from_be_bytes(buf4), 105);

    let mut buf8 = [0u8; 8];
    storage_dst.read_nv(16, &mut buf8).unwrap();
    assert_eq!(u64::from_be_bytes(buf8), 0x0123456789ABCDEF);

    storage_dst.read_nv(24, &mut buf8).unwrap();
    assert_eq!(u64::from_be_bytes(buf8), 0x1122334455667788);

    storage_dst.read_nv(32, &mut buf4).unwrap();
    assert_eq!(u32::from_be_bytes(buf4), 7);

    let mut timers_out = [0u8; 16];
    storage_dst.read_nv(112, &mut timers_out).unwrap();
    assert_eq!(
        i64::from_be_bytes(timers_out[0..8].try_into().unwrap()),
        -500
    );
    assert_eq!(
        i64::from_be_bytes(timers_out[8..16].try_into().unwrap()),
        -1200
    );

    // Verify dynamic items in `storage_dst` via StorageManager
    let mgr_dst = StorageManager::new(&mut storage_dst);
    let meta1 = mgr_dst.get_metadata(0x81000001).unwrap();
    assert_eq!(meta1.data_size, 32);
    assert_eq!(meta1.attributes, 0x00040072);
    let mut item1_data = [0u8; 32];
    mgr_dst.read_item(0x81000001, 0, &mut item1_data).unwrap();
    assert_eq!(item1_data, [0xAB; 32]);

    let meta2 = mgr_dst.get_metadata(0x01500001).unwrap();
    assert_eq!(meta2.data_size, 16);
    assert_eq!(meta2.attributes, 0x02000002);
    let mut item2_data = [0u8; 16];
    mgr_dst.read_item(0x01500001, 0, &mut item2_data).unwrap();
    assert_eq!(item2_data, [0xCD; 16]);
}

#[test]
fn test_hierarchy_auth_handle_transcoding() {
    let mut storage_src = RamStorageMock::<16384>::new();
    {
        let mut mgr = StorageManager::new(&mut storage_src);
        mgr.define_space(HIERARCHY_AUTH_HANDLE, 1024, 0).unwrap();

        // Construct a synthetic `0x00FFFFFF` hierarchy auth payload matching engine.rs layout
        let mut auth_buf = [0u8; 1024];
        let mut off = 0usize;
        // 4 Auths (each 2B len + 4B data)
        for val in [0x11u8, 0x22, 0x33, 0x44] {
            auth_buf[off..off + 2].copy_from_slice(&4u16.to_be_bytes());
            auth_buf[off + 2..off + 6].copy_from_slice(&[val; 4]);
            off += 6;
        }
        // 4 Policies (each 2B len + 8B data)
        for val in [0x55u8, 0x66, 0x77, 0x88] {
            auth_buf[off..off + 2].copy_from_slice(&8u16.to_be_bytes());
            auth_buf[off + 2..off + 10].copy_from_slice(&[val; 8]);
            off += 10;
        }
        // 4 Algs (2B each)
        for alg in [0x000Bu16, 0x000B, 0x0010, 0x000B] {
            auth_buf[off..off + 2].copy_from_slice(&alg.to_be_bytes());
            off += 2;
        }
        // 405-byte tail: sh_enable=1, eh_enable=1, ph_enable_nv=0, magic=0xAA
        auth_buf[off] = 1;
        auth_buf[off + 1] = 1;
        auth_buf[off + 2] = 0;
        auth_buf[off + 3] = 0xAA;
        off += 4;

        // sp_seed (66B), sh_proof (66B), eh_proof (66B), clear_count (4B), pp_seed (66B), ph_proof (66B), ep_seed (66B)
        auth_buf[off..off + 2].copy_from_slice(&32u16.to_be_bytes());
        auth_buf[off + 2..off + 34].copy_from_slice(&[0xA1; 32]);
        off += 66;
        auth_buf[off..off + 2].copy_from_slice(&32u16.to_be_bytes());
        auth_buf[off + 2..off + 34].copy_from_slice(&[0xA2; 32]);
        off += 66;
        auth_buf[off..off + 2].copy_from_slice(&32u16.to_be_bytes());
        auth_buf[off + 2..off + 34].copy_from_slice(&[0xA3; 32]);
        off += 66;
        auth_buf[off..off + 4].copy_from_slice(&77u32.to_be_bytes());
        off += 4;
        auth_buf[off..off + 2].copy_from_slice(&32u16.to_be_bytes());
        auth_buf[off + 2..off + 34].copy_from_slice(&[0xA4; 32]);
        off += 66;
        auth_buf[off..off + 2].copy_from_slice(&32u16.to_be_bytes());
        auth_buf[off + 2..off + 34].copy_from_slice(&[0xA5; 32]);
        off += 66;
        auth_buf[off..off + 2].copy_from_slice(&32u16.to_be_bytes());
        auth_buf[off + 2..off + 34].copy_from_slice(&[0xA6; 32]);
        off += 66;

        // PCR policy alg (2B), PCR policy (2B len + 32B data), PCR auth value (2B len + 8B data)
        auth_buf[off..off + 2].copy_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
        off += 2;
        auth_buf[off..off + 2].copy_from_slice(&32u16.to_be_bytes());
        auth_buf[off + 2..off + 34].copy_from_slice(&[0xB1; 32]);
        off += 34;
        auth_buf[off..off + 2].copy_from_slice(&8u16.to_be_bytes());
        auth_buf[off + 2..off + 10].copy_from_slice(&[0xC2; 8]);
        off += 10;

        mgr.write_item(HIERARCHY_AUTH_HANDLE, 0, &auth_buf[..off])
            .unwrap();
    }

    let mut s_nv = [0u8; NV_MEMORY_SIZE];
    transcode_storage_to_s_nv(&mut storage_src, &mut s_nv).unwrap();

    let mut storage_dst = RamStorageMock::<16384>::new();
    transcode_s_nv_to_storage(&s_nv, &mut storage_dst).unwrap();

    let mgr_dst = StorageManager::new(&mut storage_dst);
    let mut out_buf = [0u8; 1152];
    mgr_dst
        .read_item(HIERARCHY_AUTH_HANDLE, 0, &mut out_buf)
        .unwrap();

    // Verify roundtrip of owner_auth (first TPM2B_AUTH in buffer)
    assert_eq!(u16::from_be_bytes([out_buf[0], out_buf[1]]), 4);
    assert_eq!(&out_buf[2..6], &[0x11; 4]);

    // Verify roundtrip of PCR policy alg, policy digest, and auth value at end of payload
    // Offset after 4 auths (24B) + 4 policies (40B) + 4 algs (8B) + 404B tail = 476
    let pcr_off = 24 + 40 + 8 + 404;
    assert_eq!(
        u16::from_be_bytes([out_buf[pcr_off], out_buf[pcr_off + 1]]),
        0x000B
    );
    assert_eq!(
        u16::from_be_bytes([out_buf[pcr_off + 2], out_buf[pcr_off + 3]]),
        32
    );
    assert_eq!(&out_buf[pcr_off + 4..pcr_off + 36], &[0xB1; 32]);
    assert_eq!(
        u16::from_be_bytes([out_buf[pcr_off + 36], out_buf[pcr_off + 37]]),
        8
    );
    assert_eq!(&out_buf[pcr_off + 38..pcr_off + 46], &[0xC2; 8]);
}

// =========================================================================
// Tests from src/storage/translator.rs
// =========================================================================

#[test]
fn test_live_migration_state_translator_roundtrip() {
    let mut src_storage = RamStorageMock::<16384>::new();

    // Populate volatile and non-volatile state in source
    let mut src_state = GlobalState {
        tpm_time_ms: 123_456_789,
        time_epoch: 99,
        reset_count: 7,
        total_reset_count: 42,
        failed_tries: 2,
        self_heal_timer: 5000,
        lockout_timer: 10000,
        max_counter: 555,
        drtm_handle: 0x8000_0001,
        update_nv: 1,
        clear_orderly: true,
        da_pending_on_nv: true,
        locality: 3,
        ..Default::default()
    };
    src_state.pcrs.sha256[0] = [0xAA; 32];
    src_state.pcrs.sha384[23] = [0xBB; 48];
    src_state.pcrs.update_counter = 15;

    // Add an active authorization session
    let nonce_tpm = tpm2::Tpm2bNonce::from_bytes(&[0x33; 32]).unwrap();
    let sess = SessionState {
        session_handle: 0x0200_0000,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: nonce_tpm.into(),
        nonce_caller: tpm2::Tpm2bNonce::default().into(),
        session_key: [0x11; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: Handle(0x4000_0001),
        bound_entity: tpm2::Tpm2bName::default().into(),
        audit_digest: None,
        audit_digest_len: 0,
        audit_cp_hash: [0; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: true,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0x22; 64],
        policy_digest_len: 32,
        command_code: 0x0000_017A,
        start_time: 1000,
        timeout: 50000,
        epoch: 99,
        is_auth_value_needed: true,
        is_password_needed: false,
        pcr_counter: Some(15),
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 3,
        include_auth: true,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    src_state.active_sessions[0] = Some(sess);

    // Serialize to `"974"` DTO
    let mut dto = Ibmswtpm2StateDto::default();
    TpmStateTranslator::serialize_state(&src_state, &mut src_storage, &mut dto)
        .expect("serialize_state should succeed");

    // Verify `"974"` key-value access
    assert_eq!(dto.get_field("g_time").unwrap().len(), 8);
    assert_eq!(dto.get_field("s_pcrs").unwrap().len(), S_PCRS_SIZE);
    assert_eq!(dto.get_field("s_objects").unwrap().len(), S_OBJECTS_SIZE);
    assert_eq!(dto.get_field("s_sessions").unwrap().len(), S_SESSIONS_SIZE);
    assert_eq!(dto.get_field("s_NV").unwrap().len(), NV_MEMORY_SIZE);

    // Unserialize into fresh target state & storage
    let mut dst_storage = RamStorageMock::<16384>::new();
    let mut dst_state = GlobalState::default();
    TpmStateTranslator::unserialize_state(&dto, &mut dst_state, &mut dst_storage)
        .expect("unserialize_state should succeed");

    // Verify roundtrip fidelity
    assert_eq!(dst_state.tpm_time_ms, 123_456_789);
    assert_eq!(dst_state.time_epoch, 99);
    assert_eq!(dst_state.reset_count, 7);
    assert_eq!(dst_state.total_reset_count, 42);
    assert_eq!(dst_state.failed_tries, 2);
    assert_eq!(dst_state.self_heal_timer, 5000);
    assert_eq!(dst_state.lockout_timer, 10000);
    assert_eq!(dst_state.max_counter, 555);
    assert_eq!(dst_state.drtm_handle, 0x8000_0001);
    assert_eq!(dst_state.update_nv, 1);
    assert!(dst_state.clear_orderly);
    assert!(dst_state.da_pending_on_nv);
    assert_eq!(dst_state.locality, 3);
    assert_eq!(dst_state.pcrs.sha256[0], [0xAA; 32]);
    assert_eq!(dst_state.pcrs.sha384[23], [0xBB; 48]);
    assert_eq!(dst_state.pcrs.update_counter, 15);

    let restored_sess = dst_state.active_sessions[0]
        .as_ref()
        .expect("session should be restored");
    assert_eq!(restored_sess.session_handle, 0x0200_0000);
    assert_eq!(restored_sess.session_type, TpmSe::Policy);
    assert_eq!(restored_sess.auth_hash, TpmiAlgHash::Sha256);
    assert_eq!(restored_sess.nonce_tpm.get_buffer(), &[0x33; 32]);
    assert_eq!(restored_sess.session_key[..32], [0x11; 32]);
    assert_eq!(restored_sess.policy_digest[..32], [0x22; 32]);
    assert!(restored_sess.is_cp_hash_defined);
    assert!(restored_sess.is_auth_value_needed);
    assert_eq!(restored_sess.pcr_counter, Some(15));
    assert_eq!(restored_sess.command_locality, 3);
}

#[test]
fn test_live_migration_active_sequence_roundtrip() {
    let mut src_storage = RamStorageMock::<16384>::new();
    let mut src_state = GlobalState::default();

    let seq_auth = tpm2::Tpm2bAuth::from_bytes(&[0x55; 16]).unwrap();
    let mut seq = ActiveSequence::new(
        0x8000_0000,
        seq_auth,
        SequenceType::Hash {
            alg: TpmiAlgHash::Sha256,
        },
    );
    seq.sequence_len = 64;
    seq.first_bytes = [1, 2, 3, 4];
    seq.first_bytes_len = 4;
    src_state.active_sequences[0] = Some(seq);

    let mut dto = Ibmswtpm2StateDto::default();
    TpmStateTranslator::serialize_state(&src_state, &mut src_storage, &mut dto)
        .expect("serialize_state should succeed");

    let mut dst_storage = RamStorageMock::<16384>::new();
    let mut dst_state = GlobalState::default();
    TpmStateTranslator::unserialize_state(&dto, &mut dst_state, &mut dst_storage)
        .expect("unserialize_state should succeed");

    let restored_seq = dst_state.active_sequences[0]
        .as_ref()
        .expect("active sequence should be restored");
    assert_eq!(restored_seq.handle, 0x8000_0000);
    assert_eq!(restored_seq.auth.get_buffer(), &[0x55; 16]);
    assert_eq!(restored_seq.sequence_len, 64);
    assert_eq!(restored_seq.first_bytes, [1, 2, 3, 4]);
    assert_eq!(restored_seq.first_bytes_len, 4);
}
