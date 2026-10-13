use tpm2::errors::TpmRc;
mod common;

use common::make_test_session_state;

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
