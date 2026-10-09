use tpm2::errors::TpmRc;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer, make_test_session_state};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

#[test]
fn test_start_auth_session_dispatch() {
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

    // Send StartAuthSession command (0x00000176)
    // tag: 8001
    // size: 0000001B (27)
    // cc: 00000176
    // tpm_key: 40000007 (RHNull)
    // bind: 40000007 (RHNull)
    // nonce_caller: 0000 (size 0)
    // encrypted_salt: 0000 (size 0)
    // session_type: 01 (Policy)
    // symmetric: 0010 (Null)
    // auth_hash: 000b (SHA256)
    let request = hex!(
        "8001"
        "0000002b"
        "00000176"
        "40000007"
        "40000007"
        "00100102030405060708090a0b0c0d0e0f10"
        "0000"
        "01"
        "0010"
        "000b"
    );
    let mut response = [0u8; 256];
    // Executing the command should now succeed and return the session handle and nonceTPM
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 32);
    assert_eq!(&response[0..2], &hex!("8001"));
    assert_eq!(&response[2..6], &32u32.to_be_bytes());
    assert_eq!(&response[6..10], &0u32.to_be_bytes());
    assert_eq!(&response[10..14], &0x03000000u32.to_be_bytes());
    assert_eq!(&response[14..16], &16u16.to_be_bytes());
    let expected_nonce_bytes = [
        // Startup draws 256 FakeRng bytes (incl. the 64-byte commit nonce at TPM Reset), so
        // the u8 counter has wrapped back to 1.
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];
    assert_eq!(&response[16..32], &expected_nonce_bytes);
}

#[test]
fn test_start_auth_session_public_only_key_fails() {
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

    // Populate a public-only decrypt RSA key directly in transient_objects
    use tpm2::{
        PublicParmsAndId, Tpm2bAuth, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash,
        TpmiRsaKeyBits, TpmsRsaParms, TpmtPublic,
    };
    use tpm2_impl::handler::TransientObject;

    let key_handle = 0x80000001;
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0u8; 1536],
        private_len: 0, // 0 means public only
        qualified_name: Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Send StartAuthSession command using key_handle (0x80000001) as tpmKey
    // and a non-empty encryptedSalt (e.g. 16 bytes).
    let request = hex!(
        "8001"
        "0000003b"
        "00000176"
        "80000001" // tpmKey
        "40000007" // bind (RHNull)
        "00100102030405060708090a0b0c0d0e0f10" // nonceCaller
        "00101112131415161718191a1b1c1d1e1f20" // encryptedSalt (non-empty)
        "01" // sessionType
        "0010" // symmetric
        "000b" // authHash
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    // Spec expects TPM_RC_HANDLE (0x18B) for public-only key.
    assert_eq!(
        error_code, 0x18B,
        "Expected TPM_RC_HANDLE (0x18B), got 0x{:03X}",
        error_code
    );
}

#[test]
fn test_start_auth_session_nonce_caller_too_small_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first
    let startup_request = hex!(
        "8001"
        "0000000c"
        "00000144"
        "0000"
    );
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    // Send StartAuthSession with nonceCaller of size 15 (too small, minimum is 16)
    // tag: 8001
    // size: 0000002a (42)
    // cc: 00000176
    // tpmKey: 40000007 (RHNull)
    // bind: 40000007 (RHNull)
    // nonceCaller: 000f (size 15) + 15 bytes
    // encryptedSalt: 0000 (empty)
    // sessionType: 01 (Policy)
    // symmetric: 0010 (Null)
    // authHash: 000b (SHA256)
    let request = hex!(
        "8001"
        "0000002a"
        "00000176"
        "40000007"
        "40000007"
        "000f0102030405060708090a0b0c0d0e0f"
        "0000"
        "01"
        "0010"
        "000b"
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    // Expected TPM_RC_SIZE (0x095) on parameter 1, which maps to 0x1D5
    assert_eq!(
        error_code, 0x1D5,
        "Expected TPM_RC_SIZE (0x1D5) for too small nonce, got 0x{:03X}",
        error_code
    );
}

#[test]
fn test_start_auth_session_session_type_invalid_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first
    let startup_request = hex!(
        "8001"
        "0000000c"
        "00000144"
        "0000"
    );
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    // Send StartAuthSession with invalid sessionType (0xFF)
    // tag: 8001
    // size: 0000002b (43)
    // cc: 00000176
    // tpmKey: 40000007
    // bind: 40000007
    // nonceCaller: 0010 + 16 bytes
    // encryptedSalt: 0000
    // sessionType: FF (invalid)
    // symmetric: 0010
    // authHash: 000b
    let request = hex!(
        "8001"
        "0000002b"
        "00000176"
        "40000007"
        "40000007"
        "00100102030405060708090a0b0c0d0e0f10"
        "0000"
        "FF"
        "0010"
        "000b"
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    // Expected TPM_RC_VALUE + P3 (0x3C4) for unmarshalling failure of sessionType (TPMI_SH_AUTH_SESSION / TPM_SE)
    assert_eq!(
        error_code, 0x3C4,
        "Expected TPM_RC_VALUE + P3 (0x3C4) for invalid session type, got 0x{:03X}",
        error_code
    );
}

#[test]
fn test_start_auth_session_symmetric_mode_invalid_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first
    let startup_request = hex!(
        "8001"
        "0000000c"
        "00000144"
        "0000"
    );
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    // Send StartAuthSession with AES-128 and mode CTR (0x0040) instead of CFB (0x0043)
    // tag: 8001
    // size: 0000002f (47)
    // cc: 00000176
    // tpmKey: 40000007
    // bind: 40000007
    // nonceCaller: 0010 + 16 bytes
    // encryptedSalt: 0000
    // sessionType: 01
    // symmetric: algorithm AES (0006), keyBits AES-128 (0080), mode CTR (0040)
    // authHash: 000b
    let request = hex!(
        "8001"
        "0000002f"
        "00000176"
        "40000007"
        "40000007"
        "00100102030405060708090a0b0c0d0e0f10"
        "0000"
        "01"
        "000600800040" // symmetric (AES-128-CTR)
        "000b"
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    // Spec expects TPM_RC_MODE (0x4C9) on parameter 4.
    assert_eq!(
        error_code, 0x4C9,
        "Expected TPM_RC_MODE (0x4C9), got 0x{:03X}",
        error_code
    );
}

#[test]
fn test_global_state_session_lifecycle() {
    use tpm2::{Handle, TpmSe};
    use tpm2::{Tpm2bNonce, TpmiAlgHash};
    use tpm2_impl::GlobalState;

    let mut state = GlobalState::default();

    // Verify empty state
    assert!(state.session(1).is_none());

    let session1 = make_test_session_state(
        0x02000001,
        TpmSe::HMAC,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[1, 2, 3],
        None,
        Handle::RH_NULL,
    );

    // Add session 1
    assert!(state.add_session(session1).is_ok());
    let got_session = state.session(0x02000001).unwrap();
    assert_eq!(
        &got_session.session_key[..got_session.session_key_len],
        &[1, 2, 3]
    );
    // Verify different prefixes DO NOT match during lookup
    assert!(state.session(0x03000001).is_none());
    assert!(state.session(0x20000001).is_none());

    // Fill up slots (up to MAX_LOADED_SESSIONS)
    for i in 2..=tpm2_impl::MAX_LOADED_SESSIONS as u32 {
        let handle = 0x02000000 | i;
        let session = make_test_session_state(
            handle,
            TpmSe::HMAC,
            TpmiAlgHash::Sha256,
            Tpm2bNonce::default(),
            Tpm2bNonce::default(),
            &[i as u8],
            None,
            Handle::RH_NULL,
        );
        assert!(state.add_session(session).is_ok());
    }

    // Try adding an additional session when slots are full
    let session65 = make_test_session_state(
        0x0200003F,
        TpmSe::HMAC,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[65],
        None,
        Handle::RH_NULL,
    );
    assert_eq!(
        state.add_session(session65).unwrap_err(),
        TpmRc::SESSION_MEMORY
    );

    // Remove a session using different prefix (0x03) should fail (return None)
    assert!(state.remove_session(0x03000002).is_none());
    // Verify it remains present under correct handle
    assert!(state.session(0x02000002).is_some());
    // Remove using correct handle should succeed
    let removed = state.remove_session(0x02000002).unwrap();
    assert_eq!(&removed.session_key[..removed.session_key_len], &[2]);
    assert!(state.session(0x02000002).is_none());

    // Flush a session using different prefix (0x20) should fail
    assert!(state.flush_session(0x20000003).is_err());
    assert!(state.session(0x02000003).is_some());
    // Flush using correct handle should succeed
    assert!(state.flush_session(0x02000003).is_ok());
    assert!(state.session(0x02000003).is_none());

    // Flush non-existent session
    assert_eq!(
        state.flush_session(0x02000003).unwrap_err(),
        TpmRc::HANDLE.to_rc()
    );
}

#[test]
fn test_session_handle_prefixes_adversarial() {
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

    // Test lookup with mismatched prefixes directly on GlobalState
    use tpm2::{Handle, TpmSe};
    use tpm2::{Tpm2bNonce, TpmiAlgHash};

    let base_handle = 0x02000005;
    let session = make_test_session_state(
        base_handle,
        TpmSe::HMAC,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[1, 2, 3],
        None,
        Handle::RH_NULL,
    );
    global_state.add_session(session).unwrap();

    // Verify lookup matches the exact prefix and does not ignore it
    for prefix in [0x00u32, 0x03, 0x20, 0x40, 0x80, 0xFF] {
        let handle = (prefix << 24) | 0x000005;
        assert!(global_state.session(handle).is_none());
    }
    assert!(global_state.session(0x02000005).is_some());

    // Now test flushing through FlushContext command with different prefixes.
    // Since we need to populate a session each time (because flushing deletes it),
    // we'll loop over valid prefixes, add the session with (prefix << 24) | 5, and flush it.
    for prefix in [0x02u32, 0x03] {
        // Clear active sessions to start fresh
        global_state.active_sessions = core::array::from_fn(|_| None);

        let session = make_test_session_state(
            (prefix << 24) | 0x000005,
            TpmSe::HMAC,
            TpmiAlgHash::Sha256,
            Tpm2bNonce::default(),
            Tpm2bNonce::default(),
            &[1, 2, 3],
            None,
            Handle::RH_NULL,
        );
        global_state.add_session(session).unwrap();

        let flush_handle = (prefix << 24) | 0x000005;
        let mut flush_request = hex!(
            "8001"
            "0000000e"
            "00000165"
            "00000000" // placeholder for handle
        );
        // Put the handle in
        flush_request[10..14].copy_from_slice(&flush_handle.to_be_bytes());

        let mut flush_response = [0u8; 256];
        let resp_size = tpm.execute_command_separate(
            &mut global_state,
            &flush_request[..],
            &mut flush_response[..],
        );
        assert_eq!(
            resp_size, 10,
            "Response size was not 10 for prefix 0x{:02X}",
            prefix
        );
        let resp_code = u32::from_be_bytes([
            flush_response[6],
            flush_response[7],
            flush_response[8],
            flush_response[9],
        ]);

        assert_eq!(
            resp_code, 0,
            "Flush failed for handle 0x{:08X} with response code 0x{:08X}",
            flush_handle, resp_code
        );

        // Verify session state in global state
        assert!(
            global_state.session(flush_handle).is_none(),
            "Session was not flushed for handle 0x{:08X}",
            flush_handle
        );
    }

    // Loop over invalid prefixes, verify they fail with TPM_RC_HANDLE and session is NOT removed
    for prefix in [0x00u32, 0x03, 0x20, 0x40, 0x81, 0xFF] {
        // Clear active sessions to start fresh
        global_state.active_sessions = core::array::from_fn(|_| None);

        let session = make_test_session_state(
            base_handle,
            TpmSe::HMAC,
            TpmiAlgHash::Sha256,
            Tpm2bNonce::default(),
            Tpm2bNonce::default(),
            &[1, 2, 3],
            None,
            Handle::RH_NULL,
        );
        global_state.add_session(session).unwrap();

        let flush_handle = (prefix << 24) | 0x000005;
        let mut flush_request = hex!(
            "8001"
            "0000000e"
            "00000165"
            "00000000" // placeholder for handle
        );
        // Put the handle in
        flush_request[10..14].copy_from_slice(&flush_handle.to_be_bytes());

        let mut flush_response = [0u8; 256];
        let resp_size = tpm.execute_command_separate(
            &mut global_state,
            &flush_request[..],
            &mut flush_response[..],
        );
        assert_eq!(
            resp_size, 10,
            "Response size was not 10 for prefix 0x{:02X}",
            prefix
        );
        let resp_code = u32::from_be_bytes([
            flush_response[6],
            flush_response[7],
            flush_response[8],
            flush_response[9],
        ]);

        if prefix == 0x03 {
            // C: FlushContext only checks SessionIsLoaded(), which masks the handle with
            // HR_HANDLE_MASK and ignores the HMAC/policy type (Session.c:208,
            // FlushContext.c:29), so 0x03000005 flushes the HMAC session in slot 5.
            assert_eq!(
                resp_code, 0,
                "Flush of 0x{:08X} should succeed like C, but got 0x{:08X}",
                flush_handle, resp_code
            );
            assert!(global_state.session(base_handle).is_none());
            continue;
        }
        let expected_code = 0x000001C4; // TPM_RC_VALUE with Position::parameter(1)
        assert_eq!(
            resp_code, expected_code,
            "Flush should have failed for handle 0x{:08X} with expected error, but got 0x{:08X}",
            flush_handle, resp_code
        );

        // Verify session remains active in global state
        assert!(
            global_state.session(base_handle).is_some(),
            "Session was unexpectedly flushed when using handle 0x{:08X}",
            flush_handle
        );
    }

    // Verify prefix 0x80 is treated as a transient handle and fails to flush
    // (since no transient object is loaded under that handle)
    {
        // Clear active sessions to start fresh
        global_state.active_sessions = core::array::from_fn(|_| None);

        let session = make_test_session_state(
            base_handle,
            TpmSe::HMAC,
            TpmiAlgHash::Sha256,
            Tpm2bNonce::default(),
            Tpm2bNonce::default(),
            &[1, 2, 3],
            None,
            Handle::RH_NULL,
        );
        global_state.add_session(session).unwrap();

        let flush_handle = (0x80u32 << 24) | 0x000005;
        let mut flush_request = hex!(
            "8001"
            "0000000e"
            "00000165"
            "00000000" // placeholder for handle
        );
        // Put the handle in
        flush_request[10..14].copy_from_slice(&flush_handle.to_be_bytes());

        let mut flush_response = [0u8; 256];
        let resp_size = tpm.execute_command_separate(
            &mut global_state,
            &flush_request[..],
            &mut flush_response[..],
        );
        assert_eq!(resp_size, 10, "Response size was not 10 for prefix 0x80");
        let resp_code = u32::from_be_bytes([
            flush_response[6],
            flush_response[7],
            flush_response[8],
            flush_response[9],
        ]);
        // C: TPM_RCS_HANDLE + RC_FlushContext_flushHandle (0x1CB), FlushContext.c:22.
        assert_eq!(
            resp_code, 0x000001CB,
            "Flush should have failed for handle 0x{:08X} with HANDLE+P1 (0x1CB), but got 0x{:08X}",
            flush_handle, resp_code
        );

        // Verify session remains active in global state (since 0x80 was treated as transient object and failed, without touching the session)
        assert!(
            global_state.session(base_handle).is_some(),
            "Session was unexpectedly flushed when using handle 0x{:08X}",
            flush_handle
        );
    }
}

#[test]
fn test_session_storage_limits_and_leaks() {
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
    use tpm2::{Handle, TpmSe};
    use tpm2::{Tpm2bNonce, TpmiAlgHash};

    // 1. Try adding sessions up to the limit (4 active sessions). Ensure the 5th session addition returns Err(TpmRc::SESSION_MEMORY).
    let make_session = |handle: u32, key_val: u8| {
        make_test_session_state(
            handle,
            TpmSe::HMAC,
            TpmiAlgHash::Sha256,
            Tpm2bNonce::default(),
            Tpm2bNonce::default(),
            &[key_val],
            None,
            Handle::RH_NULL,
        )
    };

    for i in 0..tpm2_impl::MAX_LOADED_SESSIONS as u32 {
        global_state
            .add_session(make_session(0x02000000 + i, (i % 255) as u8))
            .unwrap();
    }
    let session65 = make_session(0x0200003F, 65);

    // Adding an additional session should return Err(TpmRc::SESSION_MEMORY)
    assert_eq!(
        global_state.add_session(session65.clone()).unwrap_err(),
        TpmRc::SESSION_MEMORY
    );

    // 2. Evict some sessions, and verify that the slots are correctly reused for new sessions.
    // Let's flush Session 2 via FlushContext command (high-level)
    let flush_session2_request = hex!(
        "8001"
        "0000000e"
        "00000165"
        "02000002"
    );
    let mut flush_response = [0u8; 256];
    let resp_size = tpm.execute_command_separate(
        &mut global_state,
        &flush_session2_request[..],
        &mut flush_response[..],
    );
    assert_eq!(resp_size, 10);
    assert_eq!(&flush_response[6..10], &0u32.to_be_bytes()); // Success

    // Verify Session 2 is gone
    assert!(global_state.session(0x02000002).is_none());

    // Try adding Session 65 again with freed handle 0x02000002. It should succeed now.
    let session65 = make_session(0x02000002, 65);
    global_state.add_session(session65).unwrap();
    assert!(global_state.session(0x02000002).is_some());

    // Adding Session 66 now should fail since we are back to full capacity.
    let session66 = make_session(0x0200003F, 66);
    assert_eq!(
        global_state.add_session(session66).unwrap_err(),
        TpmRc::SESSION_MEMORY
    );

    // 3. Verify there are no resource leaks (slots are correctly cleared and reallocated).
    // Flush remaining sessions
    let handles_to_flush: Vec<u32> = global_state
        .active_sessions
        .iter()
        .filter_map(|s| s.as_ref().map(|x| x.session_handle))
        .collect();
    for handle in handles_to_flush {
        let mut request = hex!(
            "8001"
            "0000000e"
            "00000165"
            "00000000"
        );
        request[10..14].copy_from_slice(&handle.to_be_bytes());
        let mut response = [0u8; 256];
        let resp_size =
            tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
        assert_eq!(resp_size, 10);
        assert_eq!(&response[6..10], &0u32.to_be_bytes()); // Success
    }

    // Verify all active session slots in global state are None
    for slot in &global_state.active_sessions {
        assert!(slot.is_none());
    }

    // Reallocate sessions again to ensure slots are fully re-usable without issues
    for i in 0..tpm2_impl::MAX_LOADED_SESSIONS as u32 {
        global_state
            .add_session(make_session(0x02000000 + i, (i % 255) as u8))
            .unwrap();
    }

    // Verify slots are full and extra one fails
    let session_extra = make_session(0x0200003F, 11);
    assert_eq!(
        global_state.add_session(session_extra).unwrap_err(),
        TpmRc::SESSION_MEMORY
    );
}

#[test]
fn test_session_handle_variations_stress() {
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

    use tpm2::{Handle, TpmSe};
    use tpm2::{Tpm2bNonce, TpmiAlgHash};

    let base_handle = 0x02000001; // HMAC session handle

    // Only valid session prefixes should succeed in flushing the session.
    let success_prefixes = [0x02u32, 0x03];

    for &prefix in &success_prefixes {
        // Clear active sessions to start fresh
        global_state.active_sessions = core::array::from_fn(|_| None);

        let session = make_test_session_state(
            (prefix << 24) | 0x000001,
            TpmSe::HMAC,
            TpmiAlgHash::Sha256,
            Tpm2bNonce::default(),
            Tpm2bNonce::default(),
            &[1, 2, 3],
            None,
            Handle::RH_NULL,
        );
        global_state.add_session(session).unwrap();

        let flush_handle = (prefix << 24) | 0x000001;
        let mut flush_request = hex!(
            "8001"
            "0000000e"
            "00000165"
            "00000000" // placeholder for handle
        );
        flush_request[10..14].copy_from_slice(&flush_handle.to_be_bytes());

        let mut flush_response = [0u8; 256];
        let resp_size = tpm.execute_command_separate(
            &mut global_state,
            &flush_request[..],
            &mut flush_response[..],
        );
        assert_eq!(resp_size, 10);
        let resp_code = u32::from_be_bytes([
            flush_response[6],
            flush_response[7],
            flush_response[8],
            flush_response[9],
        ]);

        assert_eq!(
            resp_code, 0,
            "Expected success (0) when flushing session with handle 0x{:08X}, but got 0x{:08X}",
            flush_handle, resp_code
        );

        // Verify session is flushed (no longer in global state)
        assert!(
            global_state.session(flush_handle).is_none(),
            "Session was not flushed when using handle 0x{:08X}",
            flush_handle
        );
    }

    // Verify that attempting to flush with prefix 0x80 fails and does NOT flush the session.
    {
        global_state.active_sessions = core::array::from_fn(|_| None);

        let session = make_test_session_state(
            base_handle,
            TpmSe::HMAC,
            TpmiAlgHash::Sha256,
            Tpm2bNonce::default(),
            Tpm2bNonce::default(),
            &[1, 2, 3],
            None,
            Handle::RH_NULL,
        );
        global_state.add_session(session).unwrap();

        let flush_handle: u32 = 0x80000001;
        let mut flush_request = hex!(
            "8001"
            "0000000e"
            "00000165"
            "00000000" // placeholder for handle
        );
        flush_request[10..14].copy_from_slice(&flush_handle.to_be_bytes());

        let mut flush_response = [0u8; 256];
        let resp_size = tpm.execute_command_separate(
            &mut global_state,
            &flush_request[..],
            &mut flush_response[..],
        );
        assert_eq!(resp_size, 10);
        let resp_code = u32::from_be_bytes([
            flush_response[6],
            flush_response[7],
            flush_response[8],
            flush_response[9],
        ]);

        assert_eq!(
            resp_code,
            0x000001CB, // C: TPM_RCS_HANDLE + RC_FlushContext_flushHandle (0x1CB), FlushContext.c:29.
            "Expected HANDLE+P1 (0x1CB) when flushing session with handle 0x{:08X}, but got 0x{:08X}",
            flush_handle,
            resp_code
        );

        // Verify session is NOT flushed (still in global state)
        assert!(
            global_state.session(base_handle).is_some(),
            "Session was unexpectedly flushed when using handle 0x{:08X}",
            flush_handle
        );
    }
}

#[test]
fn test_start_auth_session_xor_symmetric_success() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup CLEAR
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

    // Start an HMAC auth session with XOR symmetric parameter (TPM_ALG_XOR=0x000a, keyBits/hash=0x000b)
    let request = hex!(
        "8001" // tag
        "0000002d" // size: 45 bytes
        "00000176" // TPM_CC_StartAuthSession
        "40000007" // tpmKey: TPM_RH_NULL
        "40000007" // bind: TPM_RH_NULL
        "00100102030405060708090a0b0c0d0e0f10" // nonceCaller: 16 bytes
        "0000" // encryptedSalt: size 0
        "00" // sessionType: TPM_SE_HMAC
        "000a" // symmetric: TPM_ALG_XOR
        "000b" // keyBits: TPM_ALG_SHA256
        "000b" // authHash: TPM_ALG_SHA256
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 32);
    assert_eq!(&response[0..2], &hex!("8001"));
    assert_eq!(&response[2..6], &32u32.to_be_bytes());
    assert_eq!(&response[6..10], &0u32.to_be_bytes()); // TPM_RC_SUCCESS
    assert_eq!(&response[10..14], &0x02000000u32.to_be_bytes()); // HMAC session handle
    assert_eq!(&response[14..16], &16u16.to_be_bytes()); // nonceTPM size
}

#[test]
fn test_start_auth_session_xor_symmetric_null_hash_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup CLEAR
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

    // Start an HMAC auth session with XOR symmetric parameter but hash=TPM_ALG_NULL (0x0010)
    let request = hex!(
        "8001" // tag
        "0000002d" // size: 45 bytes
        "00000176" // TPM_CC_StartAuthSession
        "40000007" // tpmKey: TPM_RH_NULL
        "40000007" // bind: TPM_RH_NULL
        "00100102030405060708090a0b0c0d0e0f10" // nonceCaller: 16 bytes
        "0000" // encryptedSalt: size 0
        "00" // sessionType: TPM_SE_HMAC
        "000a" // symmetric: TPM_ALG_XOR
        "0010" // keyBits: TPM_ALG_NULL (invalid for XOR)
        "000b" // authHash: TPM_ALG_SHA256
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    assert_eq!(&response[0..2], &hex!("8001"));
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        tpm2::errors::TpmRc::HASH
            .with(tpm2::errors::Position::parameter(4))
            .get(),
        "Expected TPM_RC_HASH (0x04c3) for StartAuthSession with XOR symmetric having NULL hash"
    );
}
