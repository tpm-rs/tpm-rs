//! TPM2_HierarchyChangeAuth: newAuth size limits, authorization with the new value and orderly-
//! state handling.

use crate::_common::{
    CC_HIERARCHY_CHANGE_AUTH, build_pw_cmd, change_auth_command, execute_with_password_sessions,
    mssim_rc_of, power_on_start_up, send_rc, set_hierarchy_auth, su_command,
};
use crate::_common::{NO_STREAM, PlatformConnection};
use tpm2::commands::HierarchyChangeAuth;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bAuth};
use tpm2_simulator::{SimulatorPlatformSignal, create_simulator};

/// TPM2_HierarchyChangeAuth rejects a 65-byte newAuth with TPM_RC_SIZE + P1 and accepts 64 bytes
#[test]
fn hierarchy_change_auth_rejects_auth_over_digest_size() {
    let mut sim = create_simulator!();

    // The max auth size is the digest size of the context integrity hash (Part 1,
    // "Authorization Size Convention"), which must be the strongest implemented hash (Part 1,
    // "Context Integrity Protection"): SHA-512 -> 64 bytes, also the TPM2B_AUTH maximum.
    // A raw 65-byte newAuth (empty ownerAuth still in place) fails while unmarshaling the
    // TPM2B_AUTH parameter: TPM_RC_SIZE + RC_P1.
    let mut params = 65u16.to_be_bytes().to_vec();
    params.extend_from_slice(&[2u8; 65]);
    let cmd = build_pw_cmd(CC_HIERARCHY_CHANGE_AUTH, &[Handle::RH_OWNER.0], 1, &params);
    assert_eq!(
        mssim_rc_of(&mut sim, &cmd),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "65-byte newAuth must fail with TPM_RC_SIZE + P1"
    );

    let valid_auth = vec![1u8; 64];
    let hca_cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(&valid_auth).unwrap(),
    };
    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, 1, &[]);
    assert!(resp.is_ok(), "64 byte auth should be valid");
}

/// HierarchyChangeAuth with 40- and 64-byte newAuth values (responses are printed, not asserted).
#[test]
fn oversized_new_auth() {
    let mut sim = create_simulator!();

    // CONTEXT_INTEGRITY_HASH_SIZE in most TPMs is SHA256 (32 bytes).
    // Let's see if 40 bytes is accepted.
    let oversized_auth = vec![1u8; 40];

    let hca_cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(&oversized_auth).unwrap(),
    };

    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, 1, &[]);
    println!("Resp for 40 bytes auth: {:?}", resp);

    let max_auth = vec![2u8; 64];
    let hca_cmd2 = HierarchyChangeAuth {
        auth_handle: Handle::RH_PLATFORM,
        new_auth: Tpm2bAuth::from_bytes(&max_auth).unwrap(),
    };

    let resp2 = execute_with_password_sessions(&mut sim, &hca_cmd2, 1, &[]);
    println!("Resp for 64 bytes auth: {:?}", resp2);
}

/// HierarchyChangeAuth of the owner auth succeeds (orderly state handling).
#[test]
fn owner_auth_change_succeeds() {
    let mut sim = create_simulator!();

    // Change owner auth
    let hca_cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(&[1, 2, 3]).unwrap(),
    };
    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, 1, &[]);
    assert!(resp.is_ok());

    // Check if orderly state was cleared.
    // In Rust tpm context we can't easily read orderly_state from simulator,
    // but we can check if it behaves differently.
    // Actually we can just read the global_state if we access it, but Simulator encapsulates it.
}

/// Owner auth set by HierarchyChangeAuth survives a power cycle
#[test]
fn owner_auth_persists_across_power_cycle() {
    let mut sim = create_simulator!();

    // Change owner auth
    let new_auth = b"newownerauth";
    let hca_cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(new_auth).unwrap(),
    };
    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, 1, &[]);
    assert!(resp.is_ok());

    // Power cycle
    sim.signal_platform(SimulatorPlatformSignal::PowerOff, NO_STREAM)
        .unwrap();
    power_on_start_up(&mut sim);

    // Check if new owner auth is still valid!
    let hca_cmd2 = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"another").unwrap(),
    };
    let resp2 = execute_with_password_sessions(&mut sim, &hca_cmd2, 1, new_auth);
    assert!(
        resp2.is_ok(),
        "Owner auth was not saved across power cycle! State is LOST!"
    );
}

/// `TPM_ST_NO_SESSIONS` for a command that requires authorization of the owner hierarchy fails
/// with `TPM_RC_AUTH_MISSING`.
#[test]
fn owner_without_sessions_auth_missing() {
    let mut sim = create_simulator!();
    let cmd = change_auth_command(Handle::RH_OWNER, None, &[4, 5, 6]);
    assert_eq!(send_rc(&mut sim, &cmd), TpmRc::AUTH_MISSING.get());
}

/// Changing the platform auth after `Shutdown(STATE)` invalidates the saved state, so a
/// following `Startup(STATE)` fails.
#[test]
fn platform_auth_change_invalidates_saved_state() {
    let mut sim = create_simulator!();
    set_hierarchy_auth(&mut sim, Handle::RH_PLATFORM, &[1, 2, 3]);
    assert_eq!(su_command(&mut sim, 0x145, 0x0001), 0); // Shutdown(STATE)

    let cmd = change_auth_command(Handle::RH_PLATFORM, Some(&[&[1, 2, 3]]), &[4, 5, 6]);
    assert_eq!(send_rc(&mut sim, &cmd), 0);

    // The orderly state is no longer TPM_SU_STATE: Startup(STATE) is rejected.
    sim.signal_platform(SimulatorPlatformSignal::PowerOff, NO_STREAM)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn, NO_STREAM)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn, NO_STREAM)
        .unwrap();
    assert_eq!(
        su_command(&mut sim, 0x144, 0x0001),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
}

/// `TPM_ST_NO_SESSIONS` for a command that requires authorization of the platform hierarchy
/// fails with `TPM_RC_AUTH_MISSING`.
#[test]
fn platform_without_sessions_auth_missing() {
    let mut sim = create_simulator!();
    let cmd = change_auth_command(Handle::RH_PLATFORM, None, &[4, 5, 6]);
    // Spec says TPM_RC_AUTH_MISSING when a session is required but 0x8001 is provided
    assert_eq!(send_rc(&mut sim, &cmd), TpmRc::AUTH_MISSING.get());
}

/// A second password session that does not authorize any handle fails with
/// `TPM_RC_HANDLE + S2`.
#[test]
fn second_password_session_rejected() {
    let mut sim = create_simulator!();
    set_hierarchy_auth(&mut sim, Handle::RH_OWNER, &[1, 2, 3]);

    let cmd = change_auth_command(
        Handle::RH_OWNER,
        Some(&[&[1, 2, 3], &[1, 2, 3]]),
        &[4, 5, 6],
    );
    // The second password session does not authorize any handle (C ParseSessionBuffer):
    // TPM_RC_HANDLE + RC_S2.
    let expected_err = TpmRc::HANDLE.with(Position::session(2));
    assert_eq!(send_rc(&mut sim, &cmd), expected_err.get());
}

/// Trailing zeros of an authValue are not significant: an owner auth set to `[1, 2, 3, 0]` is
/// satisfied by the password `[1, 2, 3]`.
#[test]
fn trailing_zero_auth_bytes_ignored() {
    let mut sim = create_simulator!();
    // Set Owner Auth to [1, 2, 3, 0]
    set_hierarchy_auth(&mut sim, Handle::RH_OWNER, &[1, 2, 3, 0]);

    // Provide the hmac without the trailing zero: [1, 2, 3]
    let cmd = change_auth_command(Handle::RH_OWNER, Some(&[&[1, 2, 3]]), &[4, 5, 6]);
    let rc = send_rc(&mut sim, &cmd);
    assert_eq!(
        rc, 0,
        "Expected authorization to succeed after stripping trailing zeros, got 0x{:08X}",
        rc
    );
}

/// A wrong password for the owner hierarchy fails with `TPM_RC_BAD_AUTH + S1`.
#[test]
fn wrong_owner_password_bad_auth() {
    let mut sim = create_simulator!();
    set_hierarchy_auth(&mut sim, Handle::RH_OWNER, &[1, 2, 3]);

    // Provide WRONG hmac
    let cmd = change_auth_command(Handle::RH_OWNER, Some(&[&[9, 9, 9]]), &[4, 5, 6]);
    let expected_err = TpmRc::BAD_AUTH.with(Position::session(1));
    assert_eq!(send_rc(&mut sim, &cmd), expected_err.get());
}
