//! TPM2_Startup: startup types, TPM Reset/Restart/Resume semantics and state restored at startup.

use crate::_common::{NO_STREAM, PlatformConnection};
use crate::_common::{
    NV_RW, SU_CLEAR, SU_STATE, create_storage_primary_with_auth, define_nv, ecc_primary_template,
    execute_with_password_sessions, flush_context, hash_end, hash_start, hierarchy_change_auth,
    hierarchy_control, hmac_primary_template, nv_off, nv_on, nv_read_status, nv_unavailable,
    nv_write_index, power_cycle, power_cycle_with, raw_at_checked, raw_mssim, rc_of, read_clock,
    reset_restart_counts, shutdown, shutdown_raw, start_auth_session, startup, startup_raw,
    u16_param_command, unstarted_simulator,
};
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::{SimulatorPlatformSignal, create_simulator};

/// `TPM2_Startup(CLEAR)` on a fresh TPM is a TPM Reset: resetCount 1, restartCount 0, and the
/// TPM accepts commands afterwards.
#[test]
fn clear_is_tpm_reset() {
    let mut sim = create_simulator!();
    power_cycle(&mut sim);
    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TpmCc::Startup
        0x00, 0x00, // TpmSu::Clear
    ];
    assert_eq!(rc_of(&raw_mssim(&mut sim, &request)), 0);
    // The power cycle without an orderly shutdown is another TPM Reset.
    assert_eq!(reset_restart_counts(&mut sim), (2, 0));
}

/// An invalid `startupType` fails with `TPM_RC_VALUE + P1`.
#[test]
fn invalid_startup_type_returns_value_p1() {
    let mut sim = unstarted_simulator();
    assert_eq!(
        startup(&mut sim, 0x0002),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
}

/// Every `startupType` other than `TPM_SU_CLEAR`/`TPM_SU_STATE` is rejected with
/// `TPM_RC_VALUE + P1`; both valid values succeed after an orderly `Shutdown(STATE)`.
#[test]
fn invalid_startup_types_rejected() {
    let mut sim = create_simulator!();
    assert_eq!(shutdown(&mut sim, SU_STATE), 0);
    power_cycle(&mut sim);
    // A rejected Startup leaves the TPM waiting for Startup, so all invalid values can be
    // probed on the same power cycle.
    for su_val in 2..=u16::MAX {
        assert_eq!(
            startup(&mut sim, su_val),
            TpmRc::VALUE.with(Position::parameter(1)).get(),
            "Failed for invalid su_val {}",
            su_val
        );
    }
    assert_eq!(startup(&mut sim, SU_STATE), 0, "Failed for valid su_val 1");

    assert_eq!(shutdown(&mut sim, SU_STATE), 0);
    power_cycle(&mut sim);
    assert_eq!(startup(&mut sim, SU_CLEAR), 0, "Failed for valid su_val 0");
}

/// `TPM2_Startup` at locality 4 is rejected with `TPM_RC_LOCALITY` even after an H-CRTM
/// sequence (`_TPM_Hash_Start`/`_TPM_Hash_End` before Startup).
#[test]
fn locality_4_rejected_after_hcrtm() {
    let mut sim = unstarted_simulator();
    hash_start(&mut sim);
    hash_end(&mut sim);
    let rc = rc_of(&raw_at_checked(
        &mut sim,
        4,
        &u16_param_command(0x144, SU_CLEAR),
    ));
    // C `TPM2_Startup` checks `locality != 0 && locality != 3` before the H-CRTM override
    // (`Startup.c`), so a Startup at locality 4 is rejected even after an H-CRTM sequence.
    assert_eq!(rc, TpmRc::LOCALITY.get());
}

/// `TPM2_Startup` while NV is unavailable fails with `TPM_RC_NV_UNAVAILABLE`.
#[test]
fn nv_unavailable_rejected() {
    let mut sim = unstarted_simulator();
    sim.signal_platform(SimulatorPlatformSignal::NvOff, NO_STREAM)
        .unwrap();
    // C `TPM2_Startup` uses RETURN_IF_NV_IS_NOT_AVAILABLE -> TPM_RC_NV_UNAVAILABLE.
    assert_eq!(startup(&mut sim, SU_CLEAR), TpmRc::NV_UNAVAILABLE.get());
}

/// After `Startup(CLEAR)` the platform unique value matches ibmswtpm2 `_plat__GetUnique(1, ...)`
/// (observable as the authValue of `TPM_RH_AUTH_00`), and `TPM2_GetCapability(TPM_CAP_HANDLES)`
/// lists `TPM_RH_AUTH_00` among the permanent handles.
#[test]
fn platform_unique_and_auth_00_handle() {
    let mut sim = create_simulator!();

    // Query TPM2_GetCapability(TPM_CAP_HANDLES, property = 0x40000000, count = 32)
    let get_cap = [
        0x80, 0x01, // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x16, // size: 22 bytes
        0x00, 0x00, 0x01, 0x7a, // TPM_CC_GetCapability
        0x00, 0x00, 0x00, 0x01, // capability: TPM_CAP_HANDLES
        0x40, 0x00, 0x00, 0x00, // property: permanent handles (0x40000000)
        0x00, 0x00, 0x00, 0x20, // propertyCount: 32
    ];
    let response = raw_mssim(&mut sim, &get_cap);
    assert_eq!(rc_of(&response), 0);

    // Response structure: header (10) + moreData (1) + capability (4) + count (4) + handles (4 * count)
    assert!(response.len() >= 19);
    let count = u32::from_be_bytes(response[15..19].try_into().unwrap()) as usize;
    let found_rh_auth_00 = (0..count).any(|i| {
        let offset = 19 + i * 4;
        u32::from_be_bytes(response[offset..offset + 4].try_into().unwrap()) == Handle::RH_AUTH_00.0
    });
    assert!(
        found_rh_auth_00,
        "TPM_RH_AUTH_00 (0x40000010) must be present in permanent handles"
    );

    // The platform unique value matches ibmswtpm2 _plat__GetUnique(1, 48, ...): it authorizes
    // TPM_RH_AUTH_00 in TPM2_PolicySecret.
    let unique = b"euqinu laer A .eulav euqinu a yllaer ton si sihT";
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let cmd = PolicySecret {
        auth_handle: Handle::RH_AUTH_00,
        policy_session: session.session_handle,
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, unique)
        .expect("TPM2_PolicySecret with TPM_RH_AUTH_00 must succeed");
}

/// `Startup(STATE)` (TPM Resume) flushes loaded transient objects and sequence objects, but saved
/// session contexts survive (spec Part 1 Sec 12.2.3).
#[test]
fn resume_flushes_transients_keeps_saved_sessions() {
    let mut sim = create_simulator!();

    // A loaded transient object.
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate::default()),
        in_public: Tpm2b(hmac_primary_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let primary = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let object = primary.object_handle;

    // A loaded sequence object.
    let seq = execute_with_password_sessions(
        &mut sim,
        &HashSequenceStart {
            auth: Tpm2bAuth::default(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        0,
        &[],
    )
    .unwrap();
    let sequence = seq.sequence_handle;

    // A saved session context.
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
    let saved = execute_with_password_sessions(
        &mut sim,
        &ContextSave {
            save_handle: session.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    assert_eq!(shutdown(&mut sim, SU_STATE), 0);
    power_cycle(&mut sim);
    assert_eq!(startup(&mut sim, SU_STATE), 0);

    // Transient objects and sequences are flushed on SU_STATE.
    let caps = sim
        .execute(GetCapability {
            capability: TpmCap::Handles,
            property: 0x8000_0000,
            property_count: 64,
        })
        .unwrap();
    let TpmsCapabilityData::Handles(handles) = caps.capability_data else {
        panic!("unexpected capability data");
    };
    let transient: Vec<u32> = handles
        .as_ref()
        .iter()
        .map(|h| h.0)
        .filter(|h| h >> 24 == 0x80)
        .collect();
    assert!(
        transient.is_empty(),
        "transient handles left: {transient:x?}"
    );
    for handle in [object, sequence] {
        let rc = flush_context(&mut sim, handle).unwrap_err();
        assert_eq!(rc, TpmRc::HANDLE.with(Position::parameter(1)).get());
    }

    // Saved sessions survive SU_STATE.
    execute_with_password_sessions(
        &mut sim,
        &ContextLoad {
            context: saved.context,
        },
        0,
        &[],
    )
    .expect("saved session must survive Startup(STATE)");
}

/// Shutdown(CLEAR) + Startup(CLEAR) is a TPM Reset; Shutdown(STATE) + Startup(STATE) resumes
/// and preserves platformAuth and the hierarchy enables.
#[test]
fn resume_restart_reset_semantics() {
    let mut sim = create_simulator!();
    let info = read_clock(&mut sim).clock_info;
    assert_eq!(power_cycle_with(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    let after = read_clock(&mut sim).clock_info;
    assert_eq!(after.reset_count, info.reset_count + 1, "not a TPM Reset");
    assert_eq!(after.restart_count, 0);

    // TPM Resume keeps platformAuth and shEnable.
    hierarchy_change_auth(&mut sim, Handle::RH_PLATFORM, &[], b"plat").unwrap();
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, false).unwrap();
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_STATE), 0);
    let resumed = read_clock(&mut sim).clock_info;
    assert_eq!(resumed.reset_count, after.reset_count);
    assert_eq!(resumed.restart_count, 1);
    // The empty password no longer works for the platform hierarchy...
    assert!(hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, true).is_err());
    // ...the saved one does, and the storage hierarchy is still disabled until re-enabled.
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(ecc_primary_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    assert!(
        execute_with_password_sessions(&mut sim, &cmd, 1, &[]).is_err(),
        "shEnable was re-enabled by TPM Resume"
    );
    execute_with_password_sessions(
        &mut sim,
        &HierarchyControl {
            auth_handle: Handle::RH_PLATFORM,
            enable: Handle::RH_OWNER,
            state: true,
        },
        1,
        b"plat",
    )
    .expect("platformAuth lost on TPM Resume");

    // TPM Restart keeps the null seed; TPM Reset replaces it.
    let (_, null_name) = create_storage_primary_with_auth(&mut sim, Handle::RH_NULL, &[]);
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_CLEAR), 0);
    let restarted = read_clock(&mut sim).clock_info;
    assert_eq!(restarted.restart_count, 2);
    let (_, null_name_restart) = create_storage_primary_with_auth(&mut sim, Handle::RH_NULL, &[]);
    assert_eq!(
        null_name, null_name_restart,
        "null seed changed on TPM Restart"
    );
    assert_eq!(power_cycle_with(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    let (_, null_name_reset) = create_storage_primary_with_auth(&mut sim, Handle::RH_NULL, &[]);
    assert_ne!(null_name, null_name_reset, "null seed kept on TPM Reset");
}

/// A second `TPM2_Startup(CLEAR)` fails with `TPM_RC_INITIALIZE` and does not count as another
/// TPM Reset.
#[test]
fn second_clear_returns_initialize() {
    // `create_simulator!()` already sent the first, successful Startup(CLEAR).
    let mut sim = create_simulator!();
    assert_eq!(startup(&mut sim, SU_CLEAR), TpmRc::INITIALIZE.get());
    assert_eq!(reset_restart_counts(&mut sim).0, 1);
}

/// `Shutdown(CLEAR)` + `Startup(CLEAR)` is a TPM Reset, not a TPM Restart.
#[test]
fn shutdown_clear_then_clear_is_reset() {
    let mut sim = create_simulator!();
    let (reset_before, restart_before) = reset_restart_counts(&mut sim);
    assert_eq!(shutdown(&mut sim, SU_CLEAR), 0);
    power_cycle(&mut sim);
    assert_eq!(startup(&mut sim, SU_CLEAR), 0);
    // Shutdown(CLEAR) + Startup(CLEAR) is a TPM Reset (`Startup.c`), not a TPM Restart.
    assert_eq!(
        reset_restart_counts(&mut sim),
        (reset_before + 1, restart_before)
    );
    assert_eq!(restart_before, 0);
}

/// NvEntityStartup: READLOCKED and WRITE_STCLEAR locks are cleared, CLEAR_STCLEAR indices
/// become unwritten on TPM Reset / Restart, but nothing changes on TPM Resume.
#[test]
fn startup_resets_nv_stclear_locks() {
    let mut sim = create_simulator!();
    let read_locked = 0x0150_0010;
    let write_locked = 0x0150_0011;
    let clear_stclear = 0x0150_0012;
    define_nv(&mut sim, read_locked, NV_RW | TpmaNv::READ_STCLEAR, 8);
    define_nv(&mut sim, write_locked, NV_RW | TpmaNv::WRITE_STCLEAR, 8);
    define_nv(&mut sim, clear_stclear, NV_RW | TpmaNv::CLEAR_STCLEAR, 8);
    for idx in [read_locked, write_locked, clear_stclear] {
        nv_write_index(&mut sim, idx, &[1; 8]).unwrap();
    }
    execute_with_password_sessions(
        &mut sim,
        &NVReadLock {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(read_locked),
        },
        1,
        &[],
    )
    .unwrap();
    execute_with_password_sessions(
        &mut sim,
        &NVWriteLock {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(write_locked),
        },
        1,
        &[],
    )
    .unwrap();
    assert!(nv_read_status(&mut sim, read_locked, 8).is_err());
    assert!(nv_write_index(&mut sim, write_locked, &[2; 8]).is_err());

    // TPM Resume keeps the locks.
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_STATE), 0);
    assert!(nv_read_status(&mut sim, read_locked, 8).is_err());
    assert!(nv_write_index(&mut sim, write_locked, &[2; 8]).is_err());
    nv_read_status(&mut sim, clear_stclear, 8).unwrap();

    // TPM Reset clears them.
    assert_eq!(power_cycle_with(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    nv_read_status(&mut sim, read_locked, 8).expect("READLOCKED survived TPM Reset");
    nv_write_index(&mut sim, write_locked, &[2; 8]).expect("WRITELOCKED survived TPM Reset");
    assert_eq!(
        nv_read_status(&mut sim, clear_stclear, 8),
        Err(TpmRc::NV_UNINITIALIZED.get()),
        "CLEAR_STCLEAR index still written after TPM Reset"
    );
}

/// resetCount/orderlyState are loaded from NV at _TPM_Init.
#[test]
fn startup_state_requires_orderly_state_shutdown() {
    let mut sim = create_simulator!();
    let base = read_clock(&mut sim).clock_info.reset_count;
    for i in 1..=3 {
        assert_eq!(power_cycle_with(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
        assert_eq!(read_clock(&mut sim).clock_info.reset_count, base + i);
    }
    // Startup(STATE) after Shutdown(STATE) is possible after a power cycle.
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_STATE), 0);
    // Startup(STATE) after an unorderly shutdown is rejected.
    assert_eq!(
        power_cycle_with(&mut sim, None, SU_STATE),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
    assert_eq!(startup_raw(&mut sim, 0, SU_CLEAR), 0);
}

/// Startup: startupType is validated (VALUE+P1) before NV availability; NV_UNAVAILABLE when NV
/// is off; LOCALITY when a Resume happens at a different startup locality.
#[test]
fn startup_type_nv_and_locality_checks() {
    let mut sim = create_simulator!();
    sim.signal_platform(SimulatorPlatformSignal::PowerOff, NO_STREAM)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn, NO_STREAM)
        .unwrap();
    nv_off(&mut sim);
    assert_eq!(
        startup_raw(&mut sim, 0, 0x0002),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
    assert_eq!(startup_raw(&mut sim, 0, SU_CLEAR), nv_unavailable());
    nv_on(&mut sim);
    assert_eq!(startup_raw(&mut sim, 3, SU_CLEAR), 0);
    // Shutdown(STATE) after a locality-3 startup; resuming at locality 0 is a LOCALITY error.
    assert_eq!(shutdown_raw(&mut sim, SU_STATE), 0);
    sim.signal_platform(SimulatorPlatformSignal::PowerOff, NO_STREAM)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn, NO_STREAM)
        .unwrap();
    nv_on(&mut sim);
    assert_eq!(startup_raw(&mut sim, 0, SU_STATE), TpmRc::LOCALITY.get());
    assert_eq!(startup_raw(&mut sim, 3, SU_STATE), 0);
}

/// `Startup(STATE)` after a successful `Startup(CLEAR)` fails with `TPM_RC_INITIALIZE`.
#[test]
fn state_after_clear_returns_initialize() {
    let mut sim = unstarted_simulator();
    assert_eq!(startup(&mut sim, SU_CLEAR), 0);
    assert_eq!(startup(&mut sim, SU_STATE), TpmRc::INITIALIZE.get());
}

/// `Shutdown(STATE)` + `Startup(STATE)` is a TPM Resume: resetCount unchanged, restartCount
/// incremented.
#[test]
fn state_after_shutdown_state_is_resume() {
    let mut sim = create_simulator!();
    let (reset_before, restart_before) = reset_restart_counts(&mut sim);
    assert_eq!(shutdown(&mut sim, SU_STATE), 0);
    power_cycle(&mut sim);
    assert_eq!(startup(&mut sim, SU_STATE), 0);
    assert_eq!(
        reset_restart_counts(&mut sim),
        (reset_before, restart_before + 1)
    );
}

/// `Startup(STATE)` without a preceding `Shutdown(STATE)` fails with `TPM_RC_VALUE + P1`.
#[test]
fn state_without_saved_state_rejected() {
    let mut sim = unstarted_simulator();
    assert_eq!(
        startup(&mut sim, SU_STATE),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
}

/// A Startup command with a trailing byte fails with `TPM_RC_SIZE`.
#[test]
fn trailing_byte_returns_size() {
    let mut sim = unstarted_simulator();
    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0d, // size (13 bytes = 10 + 3)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x00, // TpmSu::Clear
        0xFF, // Trailing byte
    ];
    assert_eq!(rc_of(&raw_mssim(&mut sim, &request)), TpmRc::SIZE.get());
}

/// A truncated Startup parameter fails with `TPM_RC_INSUFFICIENT + P1`.
#[test]
fn truncated_parameter_returns_insufficient() {
    let mut sim = unstarted_simulator();
    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0b, // size (11 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, // Too short payload (1 byte)
    ];
    assert_eq!(
        rc_of(&raw_mssim(&mut sim, &request)),
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get()
    );
}
