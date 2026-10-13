//! TPM2_Shutdown: shutdown types, NV errors and the effect of state changes on a following
//! Startup(STATE).

use crate::_common::{
    SU_CLEAR, SU_STATE, create_storage_primary_with_auth, hex_checked, nv_off, nv_unavailable,
    power_cycle, power_cycle_with, raw_mssim, raw_rc, raw_rc_at, rc_of, shutdown, shutdown_raw,
    start_auth_session, startup, u16_param_command,
};
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmSe, TpmiAlgHash};
use tpm2_simulator::create_simulator;

/// `TPM2_PCR_Extend` of a state-saved PCR after `Shutdown(STATE)` invalidates the saved state,
/// so a following `Startup(STATE)` fails with `TPM_RC_VALUE + P1`.
#[test]
fn pcr_extend_invalidates_saved_state() {
    let mut sim = create_simulator!();
    assert_eq!(shutdown(&mut sim, SU_STATE), 0);

    // Execute PCR_Extend on PCR 0 (state-saved PCR) after Shutdown(STATE)
    let pcr_extend = [
        0x80, 0x02, // TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x41, // size: 65 bytes
        0x00, 0x00, 0x01, 0x82, // TPM_CC_PCR_Extend
        0x00, 0x00, 0x00, 0x00, // pcrHandle: PCR 0
        0x00, 0x00, 0x00, 0x09, // authSize: 9 bytes
        0x40, 0x00, 0x00, 0x09, // TPM_RS_PW
        0x00, 0x00, // nonce size 0
        0x01, // sessionAttributes: continueSession
        0x00, 0x00, // hmac size 0
        0x00, 0x00, 0x00, 0x01, // count: 1 digest
        0x00, 0x0b, // hashAlg: SHA256
        // 32-byte digest
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa,
    ];
    assert_eq!(rc_of(&raw_mssim(&mut sim, &pcr_extend)), 0);

    // Reboot and attempt Startup(STATE) -> must fail with TPM_RC_VALUE
    power_cycle(&mut sim);
    assert_eq!(
        startup(&mut sim, SU_STATE),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
}

/// `TPM2_HierarchyChangeAuth(TPM_RH_PLATFORM)` after `Shutdown(STATE)` invalidates the saved
/// state (orderly state becomes `SU_NONE`, not `SU_CLEAR`), so a following `Startup(STATE)`
/// fails with `TPM_RC_VALUE + P1`.
#[test]
fn platform_auth_change_invalidates_saved_state() {
    let mut sim = create_simulator!();
    assert_eq!(shutdown(&mut sim, SU_STATE), 0);

    // Execute HierarchyChangeAuth on TPM_RH_PLATFORM after Shutdown(STATE)
    let change_auth = [
        0x80, 0x02, // TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x21, // size: 33 bytes
        0x00, 0x00, 0x01, 0x29, // TPM_CC_HierarchyChangeAuth
        0x40, 0x00, 0x00, 0x0c, // authHandle: TPM_RH_PLATFORM
        0x00, 0x00, 0x00, 0x09, // authSize: 9 bytes
        0x40, 0x00, 0x00, 0x09, // TPM_RS_PW
        0x00, 0x00, // nonce size 0
        0x01, // sessionAttributes: continueSession
        0x00, 0x00, // hmac size 0
        0x00, 0x04, // newAuth size: 4 bytes
        0x01, 0x02, 0x03, 0x04, // newAuth
    ];
    assert_eq!(rc_of(&raw_mssim(&mut sim, &change_auth)), 0);

    power_cycle(&mut sim);
    assert_eq!(
        startup(&mut sim, SU_STATE),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
}

/// Regression test for CPCTPM_TC2_0_11_04_02:
/// TPM2_Shutdown with an invalid shutdownType (e.g. 42 = 0x002A)
/// must return TPM_RC_VALUE (Parameter 1, 0x0103).
#[test]
fn shutdown_invalid_type_rejected() {
    let mut sim = create_simulator!();

    let shutdown_req = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "0000000c", // size: 12 bytes
        "00000145", // TPM_CC_Shutdown
        "002a",     // shutdownType = 42 (invalid)
    ));
    let rc = raw_rc(&mut sim, &shutdown_req);
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_VALUE (0x0103) for Shutdown with invalid shutdownType"
    );
}

/// Shutdown: NV_UNAVAILABLE (not NV_UNINITIALIZED), checked after parameter unmarshaling.
#[test]
fn shutdown_reports_nv_unavailable() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(shutdown_raw(&mut sim, SU_CLEAR), nv_unavailable());
}

/// A session context saved before Shutdown(STATE) is still loadable after TPM Resume.
#[test]
fn shutdown_state_preserves_context_counter() {
    let mut sim = create_simulator!();
    // The context counter (STATE_RESET_DATA) survives Shutdown(STATE): a session context saved
    // before the shutdown is still loadable after TPM Resume.
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let saved = sim
        .execute(ContextSave {
            save_handle: session.session_handle,
        })
        .unwrap()
        .context;
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_STATE), 0);
    sim.execute(ContextLoad { context: saved })
        .expect("saved session context lost on TPM Resume");
    nv_off(&mut sim);
    assert_eq!(shutdown_raw(&mut sim, SU_STATE), nv_unavailable());
}

/// Null proof/seed survive Shutdown(STATE) + Startup(STATE): NULL-hierarchy primary is unchanged.
#[test]
fn shutdown_state_preserves_null_seed() {
    let mut sim = create_simulator!();
    // Null proof/seed survive Shutdown(STATE) + Startup(STATE).
    let (_, before) = create_storage_primary_with_auth(&mut sim, Handle::RH_NULL, &[]);
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_STATE), 0);
    let (_, after) = create_storage_primary_with_auth(&mut sim, Handle::RH_NULL, &[]);
    assert_eq!(before, after);
    nv_off(&mut sim);
    assert_eq!(shutdown_raw(&mut sim, SU_CLEAR), nv_unavailable());
}

/// Shutdown reports bad parameters/trailing bytes before the NV error.
#[test]
fn shutdown_trailing_bytes_before_nv_error() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(
        shutdown_raw(&mut sim, 0x0002),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
    // Trailing bytes are reported before the NV error.
    let mut cmd = u16_param_command(0x145, SU_CLEAR);
    cmd.push(0);
    cmd[2..6].copy_from_slice(&13u32.to_be_bytes());
    assert_eq!(raw_rc_at(&mut sim, 0, &cmd), TpmRc::SIZE.get());
    assert_eq!(shutdown_raw(&mut sim, SU_STATE), nv_unavailable());
}
