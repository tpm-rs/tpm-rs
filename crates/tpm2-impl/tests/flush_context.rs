use tpm2::Unmarshal;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer, make_test_session_state};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

#[test]
fn test_flush_context_session() {
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

    // Populate a session directly in GlobalState
    use tpm2::{Handle, TpmSe};
    use tpm2::{Tpm2bNonce, TpmiAlgHash};

    let session_handle = 0x02000005; // HMAC session handle
    let session = make_test_session_state(
        session_handle,
        TpmSe::HMAC,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[1, 2, 3],
        None,
        Handle::RH_NULL,
    );
    global_state.add_session(session).unwrap();

    // Verify it is loaded
    assert!(global_state.session(session_handle).is_some());

    // Flush context command request
    // tag: 8001
    // size: 0000000e (14)
    // cc: 00000165 (FlushContext)
    // flushHandle: 02000005
    let flush_request = hex!(
        "8001"
        "0000000e"
        "00000165"
        "02000005"
    );
    let mut flush_response = [0u8; 256];
    let resp_size = tpm.execute_command_separate(
        &mut global_state,
        &flush_request[..],
        &mut flush_response[..],
    );
    assert_eq!(resp_size, 10);
    // Success response code is 0x00000000
    assert_eq!(&flush_response[6..10], &0u32.to_be_bytes());

    // Verify session is no longer in global state
    assert!(global_state.session(session_handle).is_none());

    // Try flushing it again, should return Handle error (0x08B)
    let mut flush_response2 = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &flush_request[..],
        &mut flush_response2[..],
    );
    assert_eq!(&flush_response2[6..10], &0x8Bu32.to_be_bytes());

    // Populate another session (policy session)
    let session_handle_2 = 0x03000006; // Policy session handle
    let session_2 = make_test_session_state(
        session_handle_2,
        TpmSe::Policy,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[4, 5, 6],
        None,
        Handle::RH_NULL,
    );
    global_state.add_session(session_2).unwrap();

    // Verify it is loaded
    assert!(global_state.session(session_handle_2).is_some());

    // Flush context command request using policy session prefix 0x03
    // tag: 8001
    // size: 0000000e (14)
    // cc: 00000165 (FlushContext)
    // flushHandle: 03000006
    let flush_request_2 = hex!(
        "8001"
        "0000000e"
        "00000165"
        "03000006"
    );
    let mut flush_response_2 = [0u8; 256];
    let resp_size_2 = tpm.execute_command_separate(
        &mut global_state,
        &flush_request_2[..],
        &mut flush_response_2[..],
    );
    assert_eq!(resp_size_2, 10);
    assert_eq!(&flush_response_2[6..10], &0u32.to_be_bytes());

    // Verify policy session is no longer in global state
    assert!(global_state.session(session_handle_2).is_none());
}

#[test]
fn test_flush_context_transient_vs_session() {
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
    use tpm2_impl::handler::TransientObject;

    // 1. Populate session with handle 0x02000005
    let session_handle = 0x02000005;
    let session = make_test_session_state(
        session_handle,
        TpmSe::HMAC,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[1, 2, 3],
        None,
        Handle::RH_NULL,
    );
    global_state.add_session(session).unwrap();

    // 2. Populate transient object with handle 0x80000005 (same lower 24-bits)
    let transient_handle = 0x80000005;
    let mut tpmt_public_buf = [0u8; 1024];
    tpmt_public_buf[0] = 0x00;
    tpmt_public_buf[1] = 0x08;
    tpmt_public_buf[2] = 0x00;
    tpmt_public_buf[3] = 0x0B;
    tpmt_public_buf[10] = 0x00;
    tpmt_public_buf[11] = 0x10;

    let public_val = tpm2::TpmtPublic::unmarshal(&mut (&tpmt_public_buf[..])).unwrap();

    let obj = TransientObject {
        handle: transient_handle,
        seed: [0u8; 32],
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: (public_val).into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Verify both are present
    assert!(global_state.session(session_handle).is_some());
    assert!(global_state.transient_objects[0].is_some());

    // 3. Flush the transient object via FlushContext (using handle 0x80000005)
    let flush_transient_request = hex!(
        "8001"
        "0000000e"
        "00000165"
        "80000005"
    );
    let mut response1 = [0u8; 256];
    let resp_size1 = tpm.execute_command_separate(
        &mut global_state,
        &flush_transient_request[..],
        &mut response1[..],
    );
    assert_eq!(resp_size1, 10);
    assert_eq!(&response1[6..10], &0u32.to_be_bytes()); // Success

    // Verify transient object is gone
    assert!(global_state.transient_objects[0].is_none());
    // Verify session is STILL present (not flushed!)
    assert!(global_state.session(session_handle).is_some());

    // 4. Flush the session via FlushContext (using handle 0x02000005)
    let flush_session_request = hex!(
        "8001"
        "0000000e"
        "00000165"
        "02000005"
    );
    let mut response2 = [0u8; 256];
    let resp_size2 = tpm.execute_command_separate(
        &mut global_state,
        &flush_session_request[..],
        &mut response2[..],
    );
    assert_eq!(resp_size2, 10);
    assert_eq!(&response2[6..10], &0u32.to_be_bytes()); // Success

    // Verify session is gone
    assert!(global_state.session(session_handle).is_none());
}

#[test]
fn test_flush_context_exhaustive_prefixes() {
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
    use tpm2_impl::handler::TransientObject;

    // We will test every prefix value from 0 to 255.
    for prefix in 0..=255u8 {
        // Clear active sessions and transient objects
        global_state.active_sessions = core::array::from_fn(|_| None);
        global_state.transient_objects = core::array::from_fn(|_| None);

        // 1. Add session with handle matching prefix if valid session prefix, else default
        let session_handle = if prefix == 0x03 {
            0x03000007
        } else {
            0x02000007
        };
        let session = make_test_session_state(
            session_handle,
            TpmSe::HMAC,
            TpmiAlgHash::Sha256,
            Tpm2bNonce::default(),
            Tpm2bNonce::default(),
            &[1, 2, 3],
            None,
            Handle::RH_NULL,
        );
        global_state.add_session(session).unwrap();

        // 2. Add transient object with handle 0x80000007
        let transient_handle = 0x80000007;
        let mut tpmt_public_buf = [0u8; 1024];
        tpmt_public_buf[0] = 0x00;
        tpmt_public_buf[1] = 0x08;
        tpmt_public_buf[2] = 0x00;
        tpmt_public_buf[3] = 0x0B;
        tpmt_public_buf[10] = 0x00;
        tpmt_public_buf[11] = 0x10;
        let public_val = tpm2::TpmtPublic::unmarshal(&mut (&tpmt_public_buf[..])).unwrap();

        let obj = TransientObject {
            handle: transient_handle,
            seed: [0u8; 32],
            name: (tpm2::Tpm2bName::default()).into(),
            auth: (tpm2::Tpm2bAuth::default()).into(),
            public: (public_val).into(),
            private: [0u8; 1536],
            private_len: 0,
            qualified_name: (tpm2::Tpm2bName::default()).into(),
            hierarchy: 0x40000001,
            st_clear: false,
        };
        global_state.transient_objects[0] = Some(obj);

        // Verify both are present
        assert!(global_state.session(session_handle).is_some());
        assert!(global_state.transient_objects[0].is_some());

        // 3. Flush context using handle with the current prefix
        let flush_handle = ((prefix as u32) << 24) | 0x000007;
        let mut flush_request = hex!(
            "8001"
            "0000000e"
            "00000165"
            "00000000" // placeholder
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

        if prefix == 0x02 || prefix == 0x03 {
            // It should successfully flush the session, but NOT the transient object
            assert_eq!(
                resp_code, 0,
                "Prefix 0x{:02X} should succeed in flushing session, got 0x{:08X}",
                prefix, resp_code
            );
            assert!(
                global_state.session(session_handle).is_none(),
                "Session should be flushed for prefix 0x{:02X}",
                prefix
            );
            assert!(
                global_state.transient_objects[0].is_some(),
                "Transient object should NOT be flushed for session prefix 0x{:02X}",
                prefix
            );
        } else if prefix == 0x80 {
            // It should successfully flush the transient object, but NOT the session
            assert_eq!(
                resp_code, 0,
                "Prefix 0x80 should succeed in flushing transient object, got 0x{:08X}",
                resp_code
            );
            assert!(
                global_state.transient_objects[0].is_none(),
                "Transient object should be flushed for prefix 0x80"
            );
            assert!(
                global_state.session(session_handle).is_some(),
                "Session should NOT be flushed for prefix 0x80"
            );
        } else {
            // Any other prefix must fail and flush NEITHER
            let expected_code = 0x000001C4; // TPM_RC_VALUE with Position::parameter(1)
            assert_eq!(
                resp_code, expected_code,
                "Prefix 0x{:02X} should fail with 0x{:08X}, got 0x{:08X}",
                prefix, expected_code, resp_code
            );
            assert!(
                global_state.session(session_handle).is_some(),
                "Session was unexpectedly flushed for prefix 0x{:02X}",
                prefix
            );
            assert!(
                global_state.transient_objects[0].is_some(),
                "Transient object was unexpectedly flushed for prefix 0x{:02X}",
                prefix
            );
        }
    }
}

#[test]
fn test_flush_context_multi_session_isolation() {
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

    // Start 3 concurrent sessions (S_1, S_2, S_3)
    let s1_handle = 0x02000001; // HMAC session
    let s1 = make_test_session_state(
        s1_handle,
        TpmSe::HMAC,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[1, 2, 3],
        None,
        Handle::RH_NULL,
    );
    global_state.add_session(s1).unwrap();

    let s2_handle = 0x02000002; // HMAC session
    let s2 = make_test_session_state(
        s2_handle,
        TpmSe::HMAC,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[4, 5, 6],
        None,
        Handle::RH_NULL,
    );
    global_state.add_session(s2).unwrap();

    let s3_handle = 0x03000003; // Policy session
    let s3 = make_test_session_state(
        s3_handle,
        TpmSe::Policy,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[7, 8, 9],
        None,
        Handle::RH_NULL,
    );
    global_state.add_session(s3).unwrap();

    // Verify all 3 sessions are active in global state
    assert!(global_state.session(s1_handle).is_some());
    assert!(global_state.session(s2_handle).is_some());
    assert!(global_state.session(s3_handle).is_some());

    // Call FlushContext(S_2)
    // tag: 8001, size: 0000000e (14), cc: 00000165 (FlushContext), flushHandle: 02000002
    let flush_s2_req = hex!(
        "8001"
        "0000000e"
        "00000165"
        "02000002"
    );
    let mut flush_resp = [0u8; 256];
    let resp_size =
        tpm.execute_command_separate(&mut global_state, &flush_s2_req[..], &mut flush_resp[..]);
    assert_eq!(resp_size, 10);
    // Verify TPM_RC_SUCCESS
    assert_eq!(&flush_resp[6..10], &0u32.to_be_bytes());

    // Verify S_2 is no longer in global state
    assert!(global_state.session(s2_handle).is_none());

    // Assert S_2 returns TPM_RC_HANDLE when used (try flushing it again via FlushContext)
    let mut flush_resp_again = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &flush_s2_req[..],
        &mut flush_resp_again[..],
    );
    let rc_s2 = u32::from_be_bytes([
        flush_resp_again[6],
        flush_resp_again[7],
        flush_resp_again[8],
        flush_resp_again[9],
    ]);
    assert_eq!(rc_s2, 0x08B); // TPM_RC_HANDLE

    // Verify S_1 and S_3 remain active and usable in subsequent commands
    assert!(global_state.session(s1_handle).is_some());
    assert!(global_state.session(s3_handle).is_some());

    // Execute PolicyGetDigest on S_3 to verify it remains usable and returns TPM_RC_SUCCESS
    let get_digest_req = hex!(
        "8001"
        "0000000e"
        "00000189"
        "03000003"
    );
    let mut get_digest_resp = [0u8; 256];
    let gd_size = tpm.execute_command_separate(
        &mut global_state,
        &get_digest_req[..],
        &mut get_digest_resp[..],
    );
    assert!(gd_size >= 10);
    assert_eq!(&get_digest_resp[6..10], &0u32.to_be_bytes());
}

#[test]
fn test_policy_session_handle_persistence() {
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

    // Start active policy session
    let pol_handle = 0x03000005;
    let pol_session = make_test_session_state(
        pol_handle,
        TpmSe::Policy,
        TpmiAlgHash::Sha256,
        Tpm2bNonce::default(),
        Tpm2bNonce::default(),
        &[1, 2, 3],
        None,
        Handle::RH_NULL,
    );
    global_state.add_session(pol_session).unwrap();

    assert!(global_state.session(pol_handle).is_some());

    // Step 1: PolicyCommandCode (0x016c) on pol_handle
    let pol_cc_req = hex!(
        "8001"
        "00000012"
        "0000016c"
        "03000005"
        "00000181"
    );
    let mut resp = [0u8; 256];
    let sz = tpm.execute_command_separate(&mut global_state, &pol_cc_req[..], &mut resp[..]);
    assert_eq!(sz, 10);
    assert_eq!(&resp[6..10], &0u32.to_be_bytes());
    assert!(global_state.session(pol_handle).is_some());

    // Step 2: PolicyGetDigest (0x018a) on pol_handle
    let gd_req = hex!(
        "8001"
        "0000000e"
        "00000189"
        "03000005"
    );
    let sz_gd = tpm.execute_command_separate(&mut global_state, &gd_req[..], &mut resp[..]);
    assert!(sz_gd >= 10);
    assert_eq!(&resp[6..10], &0u32.to_be_bytes());
    assert!(global_state.session(pol_handle).is_some());

    // Step 3: PolicyRestart (0x013f) on pol_handle
    let restart_req = hex!(
        "8001"
        "0000000e"
        "00000180"
        "03000005"
    );
    let sz_rst = tpm.execute_command_separate(&mut global_state, &restart_req[..], &mut resp[..]);
    assert_eq!(sz_rst, 10);
    assert_eq!(&resp[6..10], &0u32.to_be_bytes());
    assert!(global_state.session(pol_handle).is_some());

    // Verify session state was reset to initial state by PolicyRestart
    let session = global_state.session(pol_handle).unwrap();
    assert_eq!(session.policy_digest, [0u8; 64]);
    assert_eq!(session.command_code, 0);
}

#[test]
fn test_flush_context_parameter_framing_and_attributes() {
    use tpm2::{TpmCc, errors::Position, errors::TpmRc};
    use tpm2_impl::{command_handles_count, get_command_attribute};

    // Verify cHandles = 0 in engine handle count and TPMA_CC attribute table
    assert_eq!(command_handles_count(TpmCc::FlushContext), 0);
    let attr = get_command_attribute(TpmCc::FlushContext);
    let c_handles = (attr.0 >> 25) & 0x7;
    assert_eq!(
        c_handles, 0,
        "TPMA_CC for FlushContext must have cHandles = 0"
    );

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    let startup_request = hex!("8001" "0000000c" "00000144" "0000");
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut resp[..]);

    // Query GetCapability(TPM_CAP_COMMANDS = 0x00000002, property = 0x00000165, count = 1)
    let get_cap_req = hex!(
        "8001"     // tag: NO_SESSIONS
        "00000016" // size: 22
        "0000017a" // cc: GetCapability
        "00000002" // capability: TPM_CAP_COMMANDS
        "00000165" // property: TPM_CC_FlushContext
        "00000001" // propertyCount: 1
    );
    let cap_sz = tpm.execute_command_separate(&mut global_state, &get_cap_req[..], &mut resp[..]);
    assert!(cap_sz >= 23);
    assert_eq!(&resp[6..10], &0u32.to_be_bytes());
    // Response payload: moreData (1 byte) + capability (4 bytes) + count (4 bytes) + tpmaCc (4 bytes)
    let wire_tpma_cc = u32::from_be_bytes(resp[19..23].try_into().unwrap());
    assert_eq!(wire_tpma_cc, 0x0000_0165);

    // Invalid flushHandle (persistent object 0x81000001) must return TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 (0x1C4)
    let flush_invalid = hex!("8001" "0000000e" "00000165" "81000001");
    tpm.execute_command_separate(&mut global_state, &flush_invalid[..], &mut resp[..]);
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "FlushContext invalid handle must produce parameter 1 error modifier (0x1C4), not handle 1 (0x184)"
    );
}
