use tpm2::Unmarshal;
use tpm2::errors::TpmRc;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

#[test]
fn get_random_in_place() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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

    let request = hex!(
        "8001" // tag
        "0000000c" // size
        "0000017B" // command code
        "000c" // requested random bytes
    );
    let expected_response = &hex!(
        "8001" // session
        "00000018" // size
        "00000000" // successful response
        "000c"     // 2B size prefix
        // Random bytes after 256 FakeRng draws at Startup (null_proof, null_seed, drbg_state
        // instantiation, plus the 64-byte commit nonce drawn at TPM Reset, as in C
        // TPM_Reset -> CryptStartup/commitNonce); FakeRng's u8 counter wraps back to 0x01.
        "0102030405060708090a0b0c"
    );

    let mut response = request.to_vec();
    response.resize(256, 0xFF);
    let size =
        tpm.execute_command_in_place(&mut global_state, response.as_mut_slice(), request.len());
    assert_eq!(&response[..size], expected_response);
}

#[test]
fn get_random_separate() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

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

    let request = hex!(
        "8001" // tag
        "0000000c" // size
        "0000017B" // command code
        "000c" // requested random bytes
    );
    let expected_response = hex!(
        "8001" // session
        "00000018" // size
        "00000000" // successful response
        "000c"     // 2B size prefix
        // Random bytes after 256 FakeRng draws at Startup (null_proof, null_seed, drbg_state
        // instantiation, plus the 64-byte commit nonce drawn at TPM Reset, as in C
        // TPM_Reset -> CryptStartup/commitNonce); FakeRng's u8 counter wraps back to 0x01.
        "0102030405060708090a0b0c"
    );

    let mut response = [0u8; 256];
    let size =
        tpm.execute_command_separate(&mut global_state, request.as_slice(), &mut response[..]);
    assert_eq!(&response[..size], expected_response);
}

#[test]
fn test_unmapped_command_code_returns_error() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first to initialize the TPM state
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

    // Send an unmapped command code (0x00000999)
    // tag: 8001
    // size: 0000000c
    // cc: 00000999 (unmapped)
    // params: 0000
    let request = hex!(
        "8001"
        "0000000c"
        "00000999"
        "0000"
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    // Should return CommandCode error (0x143)
    assert_eq!(&response[6..10], &0x143u32.to_be_bytes());
}

#[test]
fn test_find_empty_transient_slot_primary_vs_child_and_fallback_reuse() {
    let mut global_state = tpm2_impl::GlobalState::default();

    // 1. When empty, both primary and child allocations assign sequential slots starting at index 0
    let (slot0, handle0) = global_state.find_empty_transient_slot(true).unwrap();
    assert_eq!(slot0, 0);
    assert_eq!(handle0, 0x80000000);

    // 2. Fill all 16 slots to test capacity behavior when transient RAM is exhausted
    let mut tpmt_public_buf = [0u8; 1024];
    tpmt_public_buf[0] = 0x00;
    tpmt_public_buf[1] = 0x08; // KeyedHash
    tpmt_public_buf[2] = 0x00;
    tpmt_public_buf[3] = 0x0B; // Sha256
    tpmt_public_buf[10] = 0x00;
    tpmt_public_buf[11] = 0x10; // Null scheme

    for (i, slot) in global_state
        .transient_objects
        .iter_mut()
        .enumerate()
        .take(16)
    {
        *slot = Some(TransientObject {
            handle: 0x80000000 | (i as u32),
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
    }

    // 3. Creating a Primary Key when RAM is full MUST return ObjectMemory (0x902) to preserve strict limits
    let primary_err = global_state.find_empty_transient_slot(true);
    assert_eq!(primary_err, Err(TpmRc::OBJECT_MEMORY));

    // 4. Creating a non-primary child key when RAM is full also returns ObjectMemory
    let child_err = global_state.find_empty_transient_slot(false);
    assert_eq!(child_err, Err(TpmRc::OBJECT_MEMORY));
}

#[test]
fn test_drbg_state_persistence_and_reseed_across_shutdown_startup() {
    use tpm2::platform::storage::NvStorage;

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.g_nv_ok = true;

    // 1. Initial Startup (SU_CLEAR) instantiates a fresh DRBG state with magic = DRBG_MAGIC
    let startup_clear = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // TPM2_Startup
        "0000" // TPM_SU_CLEAR
    );
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_clear[..], &mut resp[..]);

    assert_eq!(global_state.drbg_state.magic, tpm2_impl::DRBG_MAGIC);
    assert_eq!(global_state.drbg_state.reseed_counter, 1);
    let seed_after_boot = global_state.drbg_state.seed;

    // 2. Orderly Shutdown (SU_STATE) persists the DRBG state to NV storage (offset 36..112)
    let shutdown_state = hex!(
        "8001" // tag
        "0000000c" // size
        "00000145" // TPM2_Shutdown
        "0001" // TPM_SU_STATE
    );
    tpm.execute_command_separate(&mut global_state, &shutdown_state[..], &mut resp[..]);

    let mut nv_drbg_buf = [0u8; 76];
    tpm.platform.storage.read_nv(36, &mut nv_drbg_buf).unwrap();
    let persisted_drbg = tpm2_impl::DrbgState::from_bytes(&nv_drbg_buf);
    assert_eq!(persisted_drbg.magic, tpm2_impl::DRBG_MAGIC);
    assert_eq!(persisted_drbg.seed, seed_after_boot);

    // 3. Orderly Startup (SU_STATE) restores the DRBG state from NV and reseeds it (XORing fresh entropy)
    // Simulate _TPM_Init before issuing TPM2_Startup
    global_state.initialized = false;
    let startup_state = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // TPM2_Startup
        "0001" // TPM_SU_STATE
    );
    tpm.execute_command_separate(&mut global_state, &startup_state[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    assert_eq!(global_state.drbg_state.magic, tpm2_impl::DRBG_MAGIC);
    assert_eq!(global_state.drbg_state.reseed_counter, 1);
    assert_ne!(
        global_state.drbg_state.seed, seed_after_boot,
        "Orderly startup must reseed the saved DRBG seed with fresh entropy"
    );
}

#[test]
fn test_pcr_set_auth_value_and_extend_authorization() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.g_nv_ok = true;

    // Startup(CLEAR)
    let startup_clear = hex!(
        "8001" "0000000c" "00000144" "0000"
    );
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_clear[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    // 1. Attempt TPM2_PCR_SetAuthValue on PCR 0 (not in auth group 20-22) -> should fail with TPM_RC_VALUE
    let set_auth_pcr0 = hex!(
        "8002"          // TPM_ST_SESSIONS
        "00000021"      // size (33 bytes)
        "00000183"      // TPM2_PCR_SetAuthValue
        "00000000"      // pcrHandle: PCR 0
        "00000009"      // authSize: 9 bytes
        "40000009"      // TPM_RS_PW
        "0000"          // nonce: empty
        "01"            // attributes: continueSession
        "0000"          // hmac: empty
        "000411223344"  // auth: 4 bytes [0x11, 0x22, 0x33, 0x44]
    );
    tpm.execute_command_separate(&mut global_state, &set_auth_pcr0[..], &mut resp[..]);
    let rc_pcr0 = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_ne!(rc_pcr0, 0, "PCR 0 is not in an auth group and should fail");

    // 2. Execute TPM2_PCR_SetAuthValue on PCR 20 (in auth group 20-22) -> should succeed
    let set_auth_pcr20 = hex!(
        "8002"          // TPM_ST_SESSIONS
        "00000021"      // size (33 bytes)
        "00000183"      // TPM2_PCR_SetAuthValue
        "00000014"      // pcrHandle: PCR 20 (0x14)
        "00000009"      // authSize: 9 bytes
        "40000009"      // TPM_RS_PW
        "0000"          // nonce: empty
        "01"            // attributes: continueSession
        "0000"          // hmac: empty
        "000411223344"  // auth: 4 bytes [0x11, 0x22, 0x33, 0x44]
    );
    tpm.execute_command_separate(&mut global_state, &set_auth_pcr20[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    assert_eq!(
        global_state.pcr_auth_value.get_buffer(),
        &[0x11, 0x22, 0x33, 0x44]
    );

    // 3. Attempt TPM2_PCR_Extend on PCR 20 without session -> should fail with TPM_RC_AUTH_MISSING
    global_state.locality = 2; // PCR 20 requires locality 1, 2, or 3 to extend
    let extend_no_session = hex!(
        "8001"          // TPM_ST_NO_SESSIONS
        "00000028"      // size (40 bytes)
        "00000182"      // TPM2_PCR_Extend
        "00000014"      // pcrHandle: PCR 20
        "00000001"      // count: 1 digest
        "0004"          // SHA1
        "0102030405060708090a0b0c0d0e0f1011121314"
    );
    tpm.execute_command_separate(&mut global_state, &extend_no_session[..], &mut resp[..]);
    let rc_no_sess = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(
        rc_no_sess, 0x00000125,
        "Expected TPM_RC_AUTH_MISSING when extending PCR 20 without session"
    );

    // 4. Attempt TPM2_PCR_Extend on PCR 20 with wrong password -> should fail with TPM_RC_BAD_AUTH
    let extend_bad_auth = hex!(
        "8002"          // TPM_ST_SESSIONS
        "00000039"      // size (57 bytes)
        "00000182"      // TPM2_PCR_Extend
        "00000014"      // pcrHandle: PCR 20
        "0000000d"      // authSize: 13 bytes
        "40000009"      // TPM_RS_PW
        "0000"          // nonce: empty
        "01"            // attributes: continueSession
        "000499999999"  // hmac: wrong password
        "00000001"      // count: 1 digest
        "0004"          // SHA1
        "0102030405060708090a0b0c0d0e0f1011121314"
    );
    tpm.execute_command_separate(&mut global_state, &extend_bad_auth[..], &mut resp[..]);
    let rc_bad_auth = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(
        rc_bad_auth, 0x000009A2,
        "Expected TPM_RC_BAD_AUTH (session 1) for wrong password"
    );

    // 5. Execute TPM2_PCR_Extend on PCR 20 with correct password -> should succeed
    let extend_ok = hex!(
        "8002"          // TPM_ST_SESSIONS
        "00000039"      // size (57 bytes)
        "00000182"      // TPM2_PCR_Extend
        "00000014"      // pcrHandle: PCR 20
        "0000000d"      // authSize: 13 bytes
        "40000009"      // TPM_RS_PW
        "0000"          // nonce: empty
        "01"            // attributes: continueSession
        "000411223344"  // hmac: correct password [0x11, 0x22, 0x33, 0x44]
        "00000001"      // count: 1 digest
        "0004"          // SHA1
        "0102030405060708090a0b0c0d0e0f1011121314"
    );
    tpm.execute_command_separate(&mut global_state, &extend_ok[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
}

#[test]
fn test_pcr_set_auth_policy_and_change_pps() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.g_nv_ok = true;

    // Startup(CLEAR)
    let startup_clear = hex!(
        "8001" "0000000c" "00000144" "0000"
    );
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_clear[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    // 1. Attempt TPM2_PCR_SetAuthPolicy with mismatched digest size -> should fail with TPM_RC_SIZE (P1)
    let set_policy_bad_size = hex!(
        "8002"          // TPM_ST_SESSIONS
        "00000027"      // size (39 bytes)
        "0000012c"      // TPM2_PCR_SetAuthPolicy
        "4000000c"      // authHandle: TPM_RH_PLATFORM
        "00000009"      // authSize: 9 bytes
        "40000009"      // TPM_RS_PW
        "0000"          // nonce: empty
        "01"            // attributes: continueSession
        "0000"          // hmac: empty
        "000411223344"  // authPolicy: 4 bytes (invalid for SHA256)
        "000b"          // hashAlg: SHA256 (requires 32 bytes)
        "00000014"      // pcrNum: PCR 20
    );
    tpm.execute_command_separate(&mut global_state, &set_policy_bad_size[..], &mut resp[..]);
    let rc_size = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(
        rc_size, 0x000001D5,
        "Expected TPM_RC_SIZE + P1 for invalid policy digest size"
    );

    // 2. Attempt TPM2_PCR_SetAuthPolicy on PCR 0 (not in policy group 20-22) -> should fail with TPM_RC_VALUE (P3)
    let set_policy_pcr0 = hex!(
        "8002"          // TPM_ST_SESSIONS
        "00000043"      // size (67 bytes)
        "0000012c"      // TPM2_PCR_SetAuthPolicy
        "4000000c"      // authHandle: TPM_RH_PLATFORM
        "00000009"      // authSize: 9 bytes
        "40000009"      // TPM_RS_PW
        "0000"          // nonce: empty
        "01"            // attributes: continueSession
        "0000"          // hmac: empty
        "0020"          // authPolicy size: 32 bytes
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "000b"          // hashAlg: SHA256
        "00000000"      // pcrNum: PCR 0
    );
    tpm.execute_command_separate(&mut global_state, &set_policy_pcr0[..], &mut resp[..]);
    let rc_pcr0 = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(rc_pcr0, 0x000003C4, "Expected TPM_RC_VALUE + P3 for PCR 0");

    // 3. Execute valid TPM2_PCR_SetAuthPolicy on PCR 20 -> should succeed
    let set_policy_ok = hex!(
        "8002"          // TPM_ST_SESSIONS
        "00000043"      // size (67 bytes)
        "0000012c"      // TPM2_PCR_SetAuthPolicy
        "4000000c"      // authHandle: TPM_RH_PLATFORM
        "00000009"      // authSize: 9 bytes
        "40000009"      // TPM_RS_PW
        "0000"          // nonce: empty
        "01"            // attributes: continueSession
        "0000"          // hmac: empty
        "0020"          // authPolicy size: 32 bytes
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "000b"          // hashAlg: SHA256
        "00000014"      // pcrNum: PCR 20
    );
    tpm.execute_command_separate(&mut global_state, &set_policy_ok[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    assert_eq!(global_state.pcr_policy_alg, Some(tpm2::TpmiAlgHash::Sha256));
    assert_eq!(global_state.pcr_policy.get_buffer(), &[0xBB; 32]);

    // 4. Execute TPM2_ChangePPS -> should clear pcr_policy_alg and pcr_policy
    let change_pps = hex!(
        "8002"          // TPM_ST_SESSIONS
        "0000001b"      // size (27 bytes)
        "00000125"      // TPM2_ChangePPS
        "4000000c"      // authHandle: TPM_RH_PLATFORM
        "00000009"      // authSize: 9 bytes
        "40000009"      // TPM_RS_PW
        "0000"          // nonce: empty
        "01"            // attributes: continueSession
        "0000"          // hmac: empty
    );
    tpm.execute_command_separate(&mut global_state, &change_pps[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    assert_eq!(global_state.pcr_policy_alg, None);
    assert_eq!(global_state.pcr_policy.get_size(), 0);
}

#[test]
fn test_platform_construction_with_generic_rng() {
    use tpm2_impl::GlobalState;
    use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
    use tpm2_impl::timer::SoftwareTimer;

    let mut crypto = FakeCrypto;
    let mut storage = RamStorageMock::<128>::new();
    let mut timer = SoftwareTimer { tick: 0 };
    let rng = FakeRng::new();
    let _platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let global_state = GlobalState::default();

    assert_eq!(global_state.seeds, [0u8; 32]);
}
