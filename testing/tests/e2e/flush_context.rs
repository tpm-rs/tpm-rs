//! TPM2_FlushContext: handle type validation and flushing sessions/objects without disturbing
//! others.

use crate::_common::{
    CC_FLUSH_CONTEXT, LOADED_SESSION_FIRST, PW_SESSION_CONTINUE, ST_SESSIONS, TRANSIENT_FIRST,
    build_raw_cmd, create_transient_object, flush_raw, flush_rc, flush_session_raw, hex_checked,
    is_loaded, loaded_handles, loaded_sessions, mssim_rc_of, raw, raw_rc, rc_of, rc_p,
    session_handles, session_loaded, start_hmac_session_raw, start_session_raw,
    start_session_raw_attrs, start_session_u32,
};
use testing::tpm::Tpm;
use tpm2::TpmSe;
use tpm2::errors::{Position, TpmRc};

/// FlushContext is checked for every handle type prefix 0x00..0xFF against loaded sessions and objects.
#[test]
fn every_handle_type_prefix() {
    let mut sim = Tpm::new();

    // We will test every prefix value from 0 to 255.
    for prefix in 0..=255u8 {
        // Start from no loaded sessions and transient objects
        for first in [LOADED_SESSION_FIRST, TRANSIENT_FIRST] {
            for handle in loaded_handles(&mut sim, first) {
                assert_eq!(rc_of(&flush_raw(&mut sim, handle)), 0);
            }
        }

        // 1. Start a session (a policy session for prefix 0x03, else an HMAC session)
        let session_handle = if prefix == 0x03 {
            start_session_u32(&mut sim, TpmSe::Policy)
        } else {
            start_session_u32(&mut sim, TpmSe::HMAC)
        };

        // 2. Create a transient object with the same lower 24 bits
        let transient_handle = create_transient_object(&mut sim);
        let low = transient_handle & 0x00FF_FFFF;
        assert_eq!(
            session_handle & 0x00FF_FFFF,
            low,
            "precondition: session and transient object share the lower 24 handle bits"
        );

        // Verify both are present
        assert!(is_loaded(&mut sim, session_handle));
        assert!(is_loaded(&mut sim, transient_handle));

        // 3. Flush context using handle with the current prefix
        let flush_handle = ((prefix as u32) << 24) | low;
        let rsp = flush_raw(&mut sim, flush_handle);
        assert_eq!(rsp.len(), 10);
        let resp_code = rc_of(&rsp);

        if prefix == 0x02 || prefix == 0x03 {
            // It should successfully flush the session, but NOT the transient object
            assert_eq!(
                resp_code, 0,
                "Prefix 0x{:02X} should succeed in flushing session, got 0x{:08X}",
                prefix, resp_code
            );
            assert!(
                !is_loaded(&mut sim, session_handle),
                "Session should be flushed for prefix 0x{:02X}",
                prefix
            );
            assert!(
                is_loaded(&mut sim, transient_handle),
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
                !is_loaded(&mut sim, transient_handle),
                "Transient object should be flushed for prefix 0x80"
            );
            assert!(
                is_loaded(&mut sim, session_handle),
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
                is_loaded(&mut sim, session_handle),
                "Session was unexpectedly flushed for prefix 0x{:02X}",
                prefix
            );
            assert!(
                is_loaded(&mut sim, transient_handle),
                "Transient object was unexpectedly flushed for prefix 0x{:02X}",
                prefix
            );
        }
    }
}

/// Flushing one of three sessions leaves the others loaded; the flushed handle then fails with TPM_RC_HANDLE.
#[test]
fn flush_one_of_several_sessions() {
    let mut sim = Tpm::new();

    // Start 3 concurrent sessions (S_1, S_2, S_3)
    let s1_handle = start_session_u32(&mut sim, TpmSe::HMAC);
    let s2_handle = start_session_u32(&mut sim, TpmSe::HMAC);
    let s3_handle = start_session_u32(&mut sim, TpmSe::Policy);

    // Verify all 3 sessions are active
    assert!(is_loaded(&mut sim, s1_handle));
    assert!(is_loaded(&mut sim, s2_handle));
    assert!(is_loaded(&mut sim, s3_handle));

    // Call FlushContext(S_2)
    let rsp = flush_raw(&mut sim, s2_handle);
    assert_eq!(rsp.len(), 10);
    // Verify TPM_RC_SUCCESS
    assert_eq!(rc_of(&rsp), 0);

    // Verify S_2 is no longer loaded
    assert!(!is_loaded(&mut sim, s2_handle));

    // Assert S_2 returns TPM_RC_HANDLE when used (try flushing it again via FlushContext)
    // C: TPM_RCS_HANDLE + RC_FlushContext_flushHandle (0x1CB), FlushContext.c:29.
    assert_eq!(rc_of(&flush_raw(&mut sim, s2_handle)), 0x1CB);

    // Verify S_1 and S_3 remain active and usable in subsequent commands
    assert!(is_loaded(&mut sim, s1_handle));
    assert!(is_loaded(&mut sim, s3_handle));

    // Execute PolicyGetDigest on S_3 to verify it remains usable and returns TPM_RC_SUCCESS
    let mut get_digest_req = Vec::new();
    get_digest_req.extend_from_slice(&0x8001u16.to_be_bytes());
    get_digest_req.extend_from_slice(&14u32.to_be_bytes());
    get_digest_req.extend_from_slice(&0x0000_0189u32.to_be_bytes());
    get_digest_req.extend_from_slice(&s3_handle.to_be_bytes());
    let rsp = raw(&mut sim, &get_digest_req);
    assert!(rsp.len() >= 10);
    assert_eq!(rc_of(&rsp), 0);
}

/// `TPM2_FlushContext` only accepts session handles with the HMAC (0x02) or policy (0x03)
/// prefix; other prefixes fail and leave the session loaded.
#[test]
fn flush_rejects_invalid_session_prefixes() {
    let mut sim = Tpm::new();

    // Flushing through FlushContext with the matching prefix succeeds: an HMAC session with
    // 0x02, a policy session with 0x03.
    for (session_type, prefix) in [(0x00u8, 0x02u32), (0x01, 0x03)] {
        let handle = start_session_raw_attrs(&mut sim, session_type);
        assert_eq!(handle >> 24, prefix);
        assert!(session_loaded(&mut sim, handle));
        let (resp_size, resp_code) = flush_session_raw(&mut sim, handle);
        assert_eq!(
            resp_size, 10,
            "Response size was not 10 for prefix 0x{:02X}",
            prefix
        );
        assert_eq!(
            resp_code, 0,
            "Flush failed for handle 0x{:08X} with response code 0x{:08X}",
            handle, resp_code
        );
        assert!(
            loaded_sessions(&mut sim).is_empty(),
            "Session was not flushed for handle 0x{:08X}",
            handle
        );
    }

    // Loop over invalid prefixes, verify they fail with TPM_RC_VALUE and session is NOT
    // removed
    for prefix in [0x00u32, 0x03, 0x20, 0x40, 0x81, 0xFF] {
        let base_handle = start_hmac_session_raw(&mut sim);
        let flush_handle = (prefix << 24) | (base_handle & 0x00FF_FFFF);
        let (resp_size, resp_code) = flush_session_raw(&mut sim, flush_handle);
        assert_eq!(
            resp_size, 10,
            "Response size was not 10 for prefix 0x{:02X}",
            prefix
        );

        if prefix == 0x03 {
            // C: FlushContext only checks SessionIsLoaded(), which masks the handle with
            // HR_HANDLE_MASK and ignores the HMAC/policy type (Session.c:208,
            // FlushContext.c:29), so 0x03xxxxxx flushes the HMAC session in the same slot.
            assert_eq!(
                resp_code, 0,
                "Flush of 0x{:08X} should succeed like C, but got 0x{:08X}",
                flush_handle, resp_code
            );
            assert!(!session_loaded(&mut sim, base_handle));
            continue;
        }
        let expected_code = 0x000001C4; // TPM_RC_VALUE with Position::parameter(1)
        assert_eq!(
            resp_code, expected_code,
            "Flush should have failed for handle 0x{:08X} with expected error, but got 0x{:08X}",
            flush_handle, resp_code
        );

        // Verify session remains active
        assert!(
            session_loaded(&mut sim, base_handle),
            "Session was unexpectedly flushed when using handle 0x{:08X}",
            flush_handle
        );
        assert_eq!(flush_session_raw(&mut sim, base_handle).1, 0);
    }

    // Verify prefix 0x80 is treated as a transient handle and fails to flush
    // (since no transient object is loaded under that handle)
    {
        let base_handle = start_hmac_session_raw(&mut sim);
        let flush_handle = (0x80u32 << 24) | (base_handle & 0x00FF_FFFF);
        let (resp_size, resp_code) = flush_session_raw(&mut sim, flush_handle);
        assert_eq!(resp_size, 10, "Response size was not 10 for prefix 0x80");
        // C: TPM_RCS_HANDLE + RC_FlushContext_flushHandle (0x1CB), FlushContext.c:22.
        assert_eq!(
            resp_code, 0x000001CB,
            "Flush should have failed for handle 0x{:08X} with HANDLE+P1 (0x1CB), but got 0x{:08X}",
            flush_handle, resp_code
        );

        // Verify session remains active (since 0x80 was treated as transient object and
        // failed, without touching the session)
        assert!(
            session_loaded(&mut sim, base_handle),
            "Session was unexpectedly flushed when using handle 0x{:08X}",
            flush_handle
        );
    }
}

/// Only valid session prefixes flush a session; prefix 0x80 fails and does not flush.
#[test]
fn flush_with_mismatched_prefix_keeps_session() {
    let mut sim = Tpm::new();

    // Only valid session prefixes should succeed in flushing the session.
    for (session_type, prefix) in [(0x00u8, 0x02u32), (0x01, 0x03)] {
        let flush_handle = start_session_raw_attrs(&mut sim, session_type);
        assert_eq!(flush_handle >> 24, prefix);
        assert!(session_loaded(&mut sim, flush_handle));

        let (resp_size, resp_code) = flush_session_raw(&mut sim, flush_handle);
        assert_eq!(resp_size, 10);
        assert_eq!(
            resp_code, 0,
            "Expected success (0) when flushing session with handle 0x{:08X}, but got 0x{:08X}",
            flush_handle, resp_code
        );

        // Verify session is flushed
        assert!(
            loaded_sessions(&mut sim).is_empty(),
            "Session was not flushed when using handle 0x{:08X}",
            flush_handle
        );
    }

    // Verify that attempting to flush with prefix 0x80 fails and does NOT flush the session.
    {
        let base_handle = start_hmac_session_raw(&mut sim);
        let flush_handle: u32 = 0x8000_0000 | (base_handle & 0x00FF_FFFF);

        let (resp_size, resp_code) = flush_session_raw(&mut sim, flush_handle);
        assert_eq!(resp_size, 10);
        assert_eq!(
            resp_code,
            0x000001CB, // C: TPM_RCS_HANDLE + RC_FlushContext_flushHandle (0x1CB), FlushContext.c:29.
            "Expected HANDLE+P1 (0x1CB) when flushing session with handle 0x{:08X}, but got 0x{:08X}",
            flush_handle,
            resp_code
        );

        // Verify session is NOT flushed
        assert!(
            session_loaded(&mut sim, base_handle),
            "Session was unexpectedly flushed when using handle 0x{:08X}",
            flush_handle
        );
    }
}

/// TPMA_CC of FlushContext has cHandles = 0, and a persistent flushHandle fails with TPM_RC_VALUE + P1.
#[test]
fn handle_is_parameter_and_persistent_rejected() {
    let mut sim = Tpm::new();

    // Query GetCapability(TPM_CAP_COMMANDS = 0x00000002, property = 0x00000165, count = 1)
    let mut get_cap_req = Vec::new();
    get_cap_req.extend_from_slice(&0x8001u16.to_be_bytes()); // tag: NO_SESSIONS
    get_cap_req.extend_from_slice(&22u32.to_be_bytes()); // size: 22
    get_cap_req.extend_from_slice(&0x0000_017au32.to_be_bytes()); // cc: GetCapability
    get_cap_req.extend_from_slice(&0x0000_0002u32.to_be_bytes()); // capability: TPM_CAP_COMMANDS
    get_cap_req.extend_from_slice(&0x0000_0165u32.to_be_bytes()); // property: TPM_CC_FlushContext
    get_cap_req.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // propertyCount: 1
    let rsp = raw(&mut sim, &get_cap_req);
    assert!(rsp.len() >= 23);
    assert_eq!(rc_of(&rsp), 0);
    // Response payload: moreData (1 byte) + capability (4 bytes) + count (4 bytes) + tpmaCc (4 bytes)
    // TPMA_CC for FlushContext must have cHandles (bits 25..27) = 0.
    let wire_tpma_cc = u32::from_be_bytes(rsp[19..23].try_into().unwrap());
    assert_eq!(wire_tpma_cc, 0x0000_0165);
    assert_eq!(
        (wire_tpma_cc >> 25) & 0x7,
        0,
        "TPMA_CC for FlushContext must have cHandles = 0"
    );

    // Invalid flushHandle (persistent object 0x81000001) must return TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 (0x1C4)
    let rc = rc_of(&flush_raw(&mut sim, 0x8100_0001));
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "FlushContext invalid handle must produce parameter 1 error modifier (0x1C4), not handle 1 (0x184)"
    );
}

/// Flushing an HMAC session unloads it; flushing it again fails with TPM_RC_HANDLE + P1.
#[test]
fn hmac_session_flush_and_reflush() {
    let mut sim = Tpm::new();

    // Start an HMAC session and verify it is loaded
    let session_handle = start_session_u32(&mut sim, TpmSe::HMAC);
    assert_eq!(session_handle >> 24, 0x02);
    assert!(is_loaded(&mut sim, session_handle));

    // Flush it
    let rsp = flush_raw(&mut sim, session_handle);
    assert_eq!(rsp.len(), 10);
    // Success response code is 0x00000000
    assert_eq!(rc_of(&rsp), 0);

    // Verify the session is no longer loaded
    assert!(!is_loaded(&mut sim, session_handle));

    // Try flushing it again, should return Handle error
    // C: TPM_RCS_HANDLE + RC_FlushContext_flushHandle (0x1CB), FlushContext.c:29.
    assert_eq!(rc_of(&flush_raw(&mut sim, session_handle)), 0x1CB);

    // Start another session (policy session) and verify it is loaded
    let session_handle_2 = start_session_u32(&mut sim, TpmSe::Policy);
    assert_eq!(session_handle_2 >> 24, 0x03);
    assert!(is_loaded(&mut sim, session_handle_2));

    // Flush context using the policy session prefix 0x03
    let rsp = flush_raw(&mut sim, session_handle_2);
    assert_eq!(rsp.len(), 10);
    assert_eq!(rc_of(&rsp), 0);

    // Verify policy session is no longer loaded
    assert!(!is_loaded(&mut sim, session_handle_2));
}

/// Flushing a transient object leaves a session with the same lower 24 handle bits loaded.
#[test]
fn transient_does_not_flush_session_with_same_index() {
    let mut sim = Tpm::new();

    // 1. Start an HMAC session
    let session_handle = start_session_u32(&mut sim, TpmSe::HMAC);

    // 2. Create a transient object with the same lower 24 bits
    let transient_handle = create_transient_object(&mut sim);
    assert_eq!(
        session_handle & 0x00FF_FFFF,
        transient_handle & 0x00FF_FFFF,
        "precondition: session and transient object share the lower 24 handle bits"
    );

    // Verify both are present
    assert!(is_loaded(&mut sim, session_handle));
    assert!(is_loaded(&mut sim, transient_handle));

    // 3. Flush the transient object via FlushContext
    let rsp = flush_raw(&mut sim, transient_handle);
    assert_eq!(rsp.len(), 10);
    assert_eq!(rc_of(&rsp), 0); // Success

    // Verify transient object is gone
    assert!(!is_loaded(&mut sim, transient_handle));
    // Verify session is STILL present (not flushed!)
    assert!(is_loaded(&mut sim, session_handle));

    // 4. Flush the session via FlushContext
    let rsp = flush_raw(&mut sim, session_handle);
    assert_eq!(rsp.len(), 10);
    assert_eq!(rc_of(&rsp), 0); // Success

    // Verify session is gone
    assert!(!is_loaded(&mut sim, session_handle));
}

/// `TPM2_FlushContext`: positioned `TPM_RC_HANDLE`, session type byte ignored, no sessions.
#[test]
fn unloaded_transient_and_session_type_byte() {
    let mut sim = Tpm::new();
    assert_eq!(flush_rc(&mut sim, 0x8000_0001), rc_p(TpmRc::HANDLE, 1));
    assert_eq!(flush_rc(&mut sim, 0x0300_0001), rc_p(TpmRc::HANDLE, 1));

    let h = start_session_raw(&mut sim, 0);
    assert_eq!(flush_rc(&mut sim, 0x0300_0000 | (h & 0x00FF_FFFF)), 0);
    assert!(session_handles(&mut sim, false).is_empty());

    let cmd = build_raw_cmd(
        ST_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        Some(&PW_SESSION_CONTINUE),
        &0x8000_0000u32.to_be_bytes(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());
}

/// Verifies that TPM2_FlushContext behaves properly during handle validation in the engine header stage,
/// returning TpmRc::HANDLE (0x8B) for unloaded transient handles per Part 3 specification.
#[test]
fn unloaded_transient_handle_error() {
    let mut sim = Tpm::new();

    let flush_request = hex_checked(concat!(
        "8001",     // tag: NO_SESSIONS
        "0000000e", // size: 14 bytes
        "00000165", // command code: TPM_CC_FlushContext (0x0165)
        "80000002", // flushHandle: transient handle not present in RAM
    ));
    let rc = raw_rc(&mut sim, &flush_request);
    // flushHandle is a parameter: C `TPM2_FlushContext()` returns
    // TPM_RCS_HANDLE + RC_FlushContext_flushHandle (TPM_RC_HANDLE + RC_P1).
    assert_eq!(
        rc,
        TpmRc::HANDLE.with(Position::parameter(1)).get(),
        "Flushing an unloaded transient handle should return TPM_RC_HANDLE + RC_P1"
    );
}

/// FlushContext of a transient handle above TRANSIENT_LAST or a session handle above
/// `*_SESSION_LAST` fails with TPM_RC_VALUE + P1: such values are not `TPMI_DH_CONTEXT` values
/// (Part 2, Handle Value Constants), so the unmarshaling error comes before the
/// `TPM_RC_HANDLE` check for unloaded entities.
#[test]
fn out_of_range_handle_rejected_as_value() {
    let mut sim = Tpm::new();
    // TRANSIENT_LAST is TRANSIENT_FIRST + MAX_LOADED_OBJECTS - 1 = 0x8000000F.
    assert_eq!(flush_rc(&mut sim, 0x8000_000F), rc_p(TpmRc::HANDLE, 1));
    assert_eq!(flush_rc(&mut sim, 0x8000_0010), rc_p(TpmRc::VALUE, 1));
    assert_eq!(flush_rc(&mut sim, 0x8000_00FF), rc_p(TpmRc::VALUE, 1));
    // *_SESSION_LAST is *_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1 = 0x0X00003F.
    assert_eq!(flush_rc(&mut sim, 0x0200_003F), rc_p(TpmRc::HANDLE, 1));
    assert_eq!(flush_rc(&mut sim, 0x0200_0040), rc_p(TpmRc::VALUE, 1));
    assert_eq!(flush_rc(&mut sim, 0x0300_0040), rc_p(TpmRc::VALUE, 1));
}
