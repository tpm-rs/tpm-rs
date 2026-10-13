//! Session slot capacity: exhaustion, recovery after flush and failed starts not leaking slots.

use crate::_common::{
    create_signing_key_empty_unique, create_signing_key_with_unique, execute_with_corrupted_bytes,
    execute_with_password_sessions, flush_context, flush_session_raw, hex, loaded_sessions,
    max_loaded_sessions, rc_of, send, session_loaded, start_auth_session, start_hmac_session_raw,
};
use testing::tpm::Tpm;
use tpm2::commands::{PolicyDuplicationSelect, StartAuthSession};
use tpm2::errors::TpmRc;
use tpm2::{Handle, Tpm2bEncryptedSecret, Tpm2bNonce, TpmSe, TpmiAlgHash};

/// Flushing a trial session twice fails the second time without corrupting session slots.
#[test]
fn double_flush_is_harmless() {
    let mut sim = Tpm::new();

    // 1. Start a trial session.
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
    let session_handle = start_rsp.session_handle;

    // 2. Flush it once.
    flush_context(&mut sim, session_handle).unwrap();

    // 3. Flush it again (should fail with handle error, but not crash/corrupt the system).
    let res = flush_context(&mut sim, session_handle);
    assert!(res.is_err(), "Expected double flush to fail");

    // 4. Verify we can still start MAX_LOADED_SESSIONS active sessions.
    let mut active_handles = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let start_auth = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
        active_handles.push(start_rsp.session_handle);
    }

    // 5. Clean up.
    for handle in active_handles {
        flush_context(&mut sim, handle).unwrap();
    }
}

/// A trial session whose policy command failed can be flushed and its slot reused.
#[test]
fn failed_policy_command_keeps_slot_flushable() {
    let mut sim = Tpm::new();
    let (_sk, sk_name) = create_signing_key_empty_unique(&mut sim);
    let (_ek, ek_name) = create_signing_key_with_unique(&mut sim, b"ek");

    // 1. Start a trial session.
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
    let session_handle = start_rsp.session_handle;

    // 2. Execute a policy command that fails (e.g., PolicyDuplicationSelect with invalid bool).
    let policy_dup = PolicyDuplicationSelect {
        policy_session: session_handle,
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: false,
    };
    let res = execute_with_corrupted_bytes(&mut sim, &policy_dup, 0, &[], |buf| {
        let last_idx = buf.len() - 1;
        buf[last_idx] = 2; // corrupt to 2 (invalid)
    });
    assert!(
        res.is_err(),
        "Expected PolicyDuplicationSelect to fail with invalid bool"
    );

    // 3. Flush the failed session context.
    flush_context(&mut sim, session_handle).unwrap();

    // 4. Verify we can start 4 new sessions (meaning the slot was released).
    let mut active_handles = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let start_auth = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
        active_handles.push(start_rsp.session_handle);
    }

    // 5. Clean up.
    for handle in active_handles {
        flush_context(&mut sim, handle).unwrap();
    }
    flush_context(&mut sim, _sk).unwrap();
    flush_context(&mut sim, _ek).unwrap();
}

/// StartAuthSession with a non-existent tpmKey fails without occupying a session slot.
#[test]
fn failed_start_auth_session_takes_no_slot() {
    let mut sim = Tpm::new();

    // 1. Attempt to start a session with a non-existent key handle (e.g. 0x80000000).
    // This should fail to create the session.
    let start_auth = StartAuthSession {
        tpm_key: Handle(0x80000000), // Non-existent key handle
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]);
    assert!(
        res.is_err(),
        "Expected StartAuthSession to fail with invalid key handle"
    );

    // 2. Verify that we can still start MAX_LOADED_SESSIONS active sessions (i.e. the failed attempt didn't occupy a slot).
    let mut active_handles = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let start_auth = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
        active_handles.push(start_rsp.session_handle);
    }

    // 3. Clean up.
    for handle in active_handles {
        flush_context(&mut sim, handle).unwrap();
    }
}

/// Exactly the advertised maximum number of loaded sessions can be started.
///
/// F3: Session Storage & Lifecycle Boundaries
#[test]
fn max_loaded_sessions_start() {
    let mut sim = Tpm::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let _ = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
    }
}

/// Session slots are limited; flushed slots are reused and no slots leak.
#[test]
fn session_memory_limit_and_slot_reuse() {
    let mut sim = Tpm::new();
    let max_sessions = max_loaded_sessions(&mut sim);
    assert!(max_sessions > 0);

    // 1. Start sessions up to the limit. Ensure an additional session returns
    // TPM_RC_SESSION_MEMORY.
    let start_request = hex(concat!(
        "8001 0000002b 00000176",
        "40000007 40000007",
        "00100102030405060708090a0b0c0d0e0f10",
        "0000 00 0010 000b",
    ));
    let mut handles = Vec::new();
    for _ in 0..max_sessions {
        handles.push(start_hmac_session_raw(&mut sim));
    }
    assert_eq!(
        rc_of(&send(&mut sim, &start_request)),
        TpmRc::SESSION_MEMORY.get()
    );

    // 2. Evict a session, and verify that the slot is correctly reused for a new session.
    let evicted = handles.remove(1);
    let (resp_size, resp_code) = flush_session_raw(&mut sim, evicted);
    assert_eq!(resp_size, 10);
    assert_eq!(resp_code, 0); // Success
    assert!(!session_loaded(&mut sim, evicted));

    // Starting a session again succeeds now.
    let reused = start_hmac_session_raw(&mut sim);
    assert!(session_loaded(&mut sim, reused));
    handles.push(reused);

    // Starting another session now fails since we are back to full capacity.
    assert_eq!(
        rc_of(&send(&mut sim, &start_request)),
        TpmRc::SESSION_MEMORY.get()
    );

    // 3. Verify there are no resource leaks (slots are correctly cleared and reallocated).
    // Flush remaining sessions
    for handle in loaded_sessions(&mut sim) {
        let (resp_size, resp_code) = flush_session_raw(&mut sim, handle);
        assert_eq!(resp_size, 10);
        assert_eq!(resp_code, 0); // Success
    }

    // Verify no sessions are loaded
    assert!(loaded_sessions(&mut sim).is_empty());

    // Reallocate sessions again to ensure slots are fully re-usable without issues
    for _ in 0..max_sessions {
        start_hmac_session_raw(&mut sim);
    }

    // Verify slots are full and extra one fails
    assert_eq!(
        rc_of(&send(&mut sim, &start_request)),
        TpmRc::SESSION_MEMORY.get()
    );
}

/// After flushing one of three sessions a new one starts, then the rest flush cleanly.
#[test]
fn session_slot_reused_after_flush() {
    let mut sim = Tpm::new();
    let sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let sess3 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    flush_context(&mut sim, sess1.session_handle).unwrap();
    let _sess4 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    flush_context(&mut sim, sess2.session_handle).unwrap();
    flush_context(&mut sim, sess3.session_handle).unwrap();
}

/// Starting more than the max loaded sessions fails with TPM_RC_SESSION_MEMORY; flushing one frees a slot.
#[test]
fn session_slots_exhaust_and_recover_after_flush() {
    let mut sim = Tpm::new();
    let sym_null = None;

    // 1. Start max allowed active sessions in GlobalState
    let mut sessions = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            sym_null,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        sessions.push(session);
    }

    // 2. Try to start another session beyond capacity. It must fail with SessionMemory error (0x903)
    let res = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        sym_null,
        TpmiAlgHash::Sha256,
    );
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err, 0x903); // TPM_RC_SESSION_MEMORY

    // 3. Flush one session (say the first one) to free a slot
    let flushed_handle = sessions[0].session_handle;
    flush_context(&mut sim, flushed_handle).unwrap();

    // 4. Try starting a session again, it must succeed now
    let new_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        sym_null,
        TpmiAlgHash::Sha256,
    );
    assert!(new_sess.is_ok());
    let new_sess = new_sess.unwrap();

    // 5. Clean up remaining sessions
    for session in sessions.iter().take(4).skip(1) {
        flush_context(&mut sim, session.session_handle).unwrap();
    }
    flush_context(&mut sim, new_sess.session_handle).unwrap();
}

/// 20 start/flush rounds of trial sessions do not leak slots; without flushing the session limit is reached with TPM_RC_SESSION_MEMORY.
#[test]
fn trial_sessions_do_not_leak_slots() {
    let mut sim = Tpm::new();
    let (_sk, sk_name) = create_signing_key_empty_unique(&mut sim);
    let (_ek, ek_name) = create_signing_key_with_unique(&mut sim, b"ek");

    // Run 20 iterations. Since MAX_ACTIVE_SESSIONS = 4, if they leaked,
    // we would fail by iteration 5.
    for _ in 0..20 {
        let start_auth = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();

        let policy_dup = PolicyDuplicationSelect {
            policy_session: start_rsp.session_handle,
            object_name: sk_name,
            new_parent_name: ek_name,
            include_object: true,
        };
        sim.execute(policy_dup).unwrap();

        // Flush session at the end of each iteration.
        flush_context(&mut sim, start_rsp.session_handle).unwrap();
    }

    // Now verify that if we DON'T flush, we hit the limit on the 65th attempt.
    let mut active_handles = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let start_auth = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
        active_handles.push(start_rsp.session_handle);
    }

    // The next StartAuthSession beyond capacity should fail with SessionMemory
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]);
    assert!(res.is_err(), "Expected 65th session creation to fail");
    let err = res.unwrap_err();
    assert_eq!(err, TpmRc::SESSION_MEMORY.get());

    // Flush active sessions to clean up properly.
    for handle in active_handles {
        flush_context(&mut sim, handle).unwrap();
    }

    // Flush transient keys as well to verify clean state.
    flush_context(&mut sim, _sk).unwrap();
    flush_context(&mut sim, _ek).unwrap();
}
