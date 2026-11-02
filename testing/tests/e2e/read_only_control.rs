//! TPM2_ReadOnlyControl and the Read-Only mode of operation (`tpm2-engine`'s
//! `cc-read-only-control`; TPM 2.0 Part 1, "Read-Only Mode of Operation"): entering and leaving
//! the mode with platform authorization, `TPMA_STARTUP_CLEAR.readOnly`, the commands that are
//! *Not Permitted* (`TPM_RC_READ_ONLY` before any handle or session check), the NV commands
//! that are permitted only on `TPMA_NV_ORDERLY` + `TPMA_NV_CLEAR_STCLEAR` Indexes and
//! TPM2_PolicySecret with a PIN Index (rejected before authorization, so DA and `pinCount` are
//! untouched), the mode across TPM Reset/Restart/Resume, its effect on the orderly state, and
//! that the command is not implemented without the feature.
#![cfg_attr(
    not(feature = "cc-read-only-control"),
    allow(dead_code, unused_imports)
)]

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
#[cfg(feature = "cc-read-only-control")]
use tpm2::{
    Handle, Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bNonce, TpmCc, TpmNt, TpmPt, TpmSe, TpmaNv,
    TpmiAlgHash,
    commands::{
        NVExtend, NVReadLock, NVReadPublic, NVSetBits, NVWrite, NVWriteLock, PolicySecret,
        ReadOnlyControl,
    },
};

/// `TPM_CC_ReadOnlyControl`.
const CC_READ_ONLY_CONTROL: u32 = 0x0000_01A0;
/// `TPMA_STARTUP_CLEAR.readOnly`.
const STARTUP_CLEAR_READ_ONLY: u32 = 1 << 4;

/// Sends `TPM2_ReadOnlyControl(authHandle, state)` (a raw `TPMI_YES_NO` octet) authorized
/// with an empty password; returns the response code.
fn read_only_control_rc(sim: &mut Tpm, auth_handle: u32, state: u8) -> u32 {
    let cmd = build(
        ST_SESSIONS,
        CC_READ_ONLY_CONTROL,
        &[auth_handle],
        Some(&PW_SESSION),
        &[state],
    );
    mssim_rc_of(sim, &cmd)
}

/// Enters (`true`) or leaves (`false`) Read-Only mode with platform authorization.
#[cfg(feature = "cc-read-only-control")]
fn set_read_only(sim: &mut Tpm, state: bool) {
    execute_with_password_sessions(
        sim,
        &ReadOnlyControl {
            auth_handle: Handle::RH_PLATFORM,
            state,
        },
        1,
        &[],
    )
    .unwrap();
}

/// Whether `TPMA_STARTUP_CLEAR.readOnly` is SET.
#[cfg(feature = "cc-read-only-control")]
fn is_read_only(sim: &mut Tpm) -> bool {
    get_tpm_property(sim, TpmPt::STARTUP_CLEAR) & STARTUP_CLEAR_READ_ONLY != 0
}

/// Without the feature, `TPM2_ReadOnlyControl` is not implemented (`TPM_RC_COMMAND_CODE`).
#[cfg(not(feature = "cc-read-only-control"))]
#[test]
fn not_implemented_without_feature() {
    let mut sim = Tpm::new();
    assert_eq!(
        read_only_control_rc(&mut sim, 0x4000_000C, 1),
        TpmRc::COMMAND_CODE.get()
    );
}

/// `TPM_CAP_COMMANDS` reports `TPM2_ReadOnlyControl` with the `nv` attribute and one handle
/// (`TPMA_CC_INITIALIZER(0x01A0, 0, 1, 0, 0, 1, 0, 0, 0)`).
#[cfg(feature = "cc-read-only-control")]
#[test]
fn command_attributes_are_nv_with_one_handle() {
    let mut sim = Tpm::new();
    assert_eq!(
        command_attributes(&mut sim, CC_READ_ONLY_CONTROL),
        0x0240_01A0
    );
}

/// The mode is CLEAR after TPM Reset, `TPM2_ReadOnlyControl(YES)` SETs and
/// `TPM2_ReadOnlyControl(NO)` CLEARs `TPMA_STARTUP_CLEAR.readOnly`; requesting the current mode
/// again succeeds.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn mode_is_reported_in_startup_clear() {
    let mut sim = Tpm::new();
    assert!(!is_read_only(&mut sim));
    set_read_only(&mut sim, true);
    assert!(is_read_only(&mut sim));
    set_read_only(&mut sim, true);
    assert!(is_read_only(&mut sim));
    set_read_only(&mut sim, false);
    assert!(!is_read_only(&mut sim));
    set_read_only(&mut sim, false);
    assert!(!is_read_only(&mut sim));
}

/// `authHandle` is a `TPMI_RH_PLATFORM` (`TPM_RC_VALUE` + H1 for other hierarchies), `state`
/// is a `TPMI_YES_NO` (`TPM_RC_VALUE` + P1 for other values), the platform authorization is
/// required (`TPM_RC_BAD_AUTH`), and a disabled platform hierarchy is `TPM_RC_HIERARCHY` + H1.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn platform_authorization_and_parameter_checks() {
    let mut sim = Tpm::new();
    for handle in [0x4000_0001, 0x4000_000B, 0x4000_000A, 0x4000_0007] {
        assert_eq!(
            read_only_control_rc(&mut sim, handle, 1),
            RC_VALUE_H1,
            "{handle:#x}"
        );
    }
    assert_eq!(read_only_control_rc(&mut sim, 0x4000_000C, 2), RC_VALUE_P1);
    let cmd = ReadOnlyControl {
        auth_handle: Handle::RH_PLATFORM,
        state: true,
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &cmd, 1, b"x").map(|_| ()),
        Err(RC_BAD_AUTH_S1)
    );
    assert!(!is_read_only(&mut sim));

    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_PLATFORM, false).unwrap();
    assert_eq!(
        read_only_control_rc(&mut sim, 0x4000_000C, 1),
        TpmRc::HIERARCHY.with(Position::handle(1)).get()
    );
}

/// Every implemented command that Part 3's "Commands Permitted in Read-Only Mode" lists as
/// *Not Permitted* fails with `TPM_RC_READ_ONLY` right after its command code, before its
/// handles, sessions and parameters are looked at (a bare command header suffices).
#[cfg(feature = "cc-read-only-control")]
#[test]
fn not_permitted_commands_fail_before_any_other_check() {
    let mut sim = Tpm::new();
    set_read_only(&mut sim, true);
    let mut not_permitted = vec![
        TpmCc::Create,
        TpmCc::ObjectChangeAuth,
        TpmCc::CreateLoaded,
        TpmCc::SetCommandCodeAuditStatus,
        TpmCc::PCRAllocate,
        TpmCc::PCRSetAuthPolicy,
        TpmCc::PCRSetAuthValue,
        TpmCc::CreatePrimary,
        TpmCc::HierarchyControl,
        TpmCc::SetPrimaryPolicy,
        TpmCc::ChangePPS,
        TpmCc::ChangeEPS,
        TpmCc::Clear,
        TpmCc::ClearControl,
        TpmCc::HierarchyChangeAuth,
        TpmCc::DictionaryAttackParameters,
        TpmCc::EvictControl,
        TpmCc::ClockSet,
        TpmCc::ClockRateAdjust,
        TpmCc::NVDefineSpace,
        TpmCc::NVUndefineSpace,
        TpmCc::NVUndefineSpaceSpecial,
        TpmCc::NVIncrement,
        TpmCc::NVGlobalWriteLock,
        TpmCc::NVChangeAuth,
    ];
    if cfg!(feature = "cc-nv-define-space2") {
        not_permitted.push(TpmCc::NVDefineSpace2);
    }
    for cc in not_permitted {
        for tag in [ST_NO_SESSIONS, ST_SESSIONS] {
            let cmd = build(tag, cc.code(), &[], None, &[]);
            assert_eq!(
                mssim_rc_of(&mut sim, &cmd),
                TpmRc::READ_ONLY.get(),
                "{cc:?}"
            );
        }
    }
    // Leaving the mode restores normal processing of the same bytes.
    set_read_only(&mut sim, false);
    let cmd = build(ST_NO_SESSIONS, 0x12A, &[], None, &[]);
    assert_ne!(mssim_rc_of(&mut sim, &cmd), TpmRc::READ_ONLY.get());
}

/// Commands that Part 1 lists as continuing to function in Read-Only mode do: reading and
/// extending PCRs, reading NV, random numbers, capabilities, DA lockout reset, and leaving
/// the mode.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn permitted_commands_keep_working() {
    let mut sim = Tpm::new();
    define_nv(&mut sim, 0x0100_0010, NV_RW, 8);
    nv_write_index(&mut sim, 0x0100_0010, &[7; 8]).unwrap();
    set_read_only(&mut sim, true);
    assert_eq!(nv_read_status(&mut sim, 0x0100_0010, 8), Ok(()));
    assert_eq!(
        pcr_extend_at(&mut sim, 0, 16, &[(0x000B, vec![0x42; 32])]),
        0
    );
    let get_random = build(ST_NO_SESSIONS, 0x17B, &[], None, &16u16.to_be_bytes());
    assert_eq!(mssim_rc_of(&mut sim, &get_random), 0);
    let da_reset = build(ST_SESSIONS, 0x139, &[0x4000_000A], Some(&PW_SESSION), &[]);
    assert_eq!(mssim_rc_of(&mut sim, &da_reset), 0);
    assert!(is_read_only(&mut sim));
}

/// TPM2_NV_Write, TPM2_NV_Extend, TPM2_NV_SetBits, TPM2_NV_WriteLock and TPM2_NV_ReadLock are
/// permitted on an Index with `TPMA_NV_ORDERLY` and `TPMA_NV_CLEAR_STCLEAR`.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn nv_updates_of_orderly_clear_stclear_indexes_are_permitted() {
    let mut sim = Tpm::new();
    let volatile = NV_RW | TpmaNv::ORDERLY | TpmaNv::CLEAR_STCLEAR;
    define_nv(
        &mut sim,
        0x0100_0020,
        volatile | TpmaNv::WRITE_STCLEAR | TpmaNv::READ_STCLEAR,
        8,
    );
    define_nv(
        &mut sim,
        0x0100_0021,
        volatile | TpmaNv::from(TpmNt::Extend),
        32,
    );
    define_nv(
        &mut sim,
        0x0100_0022,
        volatile | TpmaNv::from(TpmNt::Bits),
        8,
    );
    set_read_only(&mut sim, true);

    nv_write_index(&mut sim, 0x0100_0020, &[1; 8]).unwrap();
    let owner = Handle::RH_OWNER;
    let extend = NVExtend {
        auth_handle: owner,
        nv_index: Handle(0x0100_0021),
        data: Tpm2bMaxNvBuffer::from_bytes(b"measurement").unwrap(),
    };
    execute_with_password_sessions(&mut sim, &extend, 1, &[]).unwrap();
    let set_bits = NVSetBits {
        auth_handle: owner,
        nv_index: Handle(0x0100_0022),
        bits: 0x5,
    };
    execute_with_password_sessions(&mut sim, &set_bits, 1, &[]).unwrap();
    let write_lock = NVWriteLock {
        auth_handle: owner,
        nv_index: Handle(0x0100_0020),
    };
    execute_with_password_sessions(&mut sim, &write_lock, 1, &[]).unwrap();
    let read_lock = NVReadLock {
        auth_handle: owner,
        nv_index: Handle(0x0100_0020),
    };
    execute_with_password_sessions(&mut sim, &read_lock, 1, &[]).unwrap();
    assert_eq!(
        nv_write_index(&mut sim, 0x0100_0020, &[2; 8]),
        Err(TpmRc::NV_LOCKED.get())
    );
}

/// On any other Index, the NV update commands fail with `TPM_RC_READ_ONLY` once the handles
/// are validated but before authorization: a wrong password neither reports
/// `TPM_RC_AUTH_FAIL` nor counts as a DA failure, and the Index is unchanged.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn nv_updates_of_other_indexes_fail_before_authorization() {
    let mut sim = Tpm::new();
    let auth_rw = TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD;
    // ORDERLY alone, CLEAR_STCLEAR alone, neither.
    for (index, attributes) in [
        (0x0100_0030, auth_rw | TpmaNv::ORDERLY),
        (0x0100_0031, auth_rw | TpmaNv::CLEAR_STCLEAR),
        (
            0x0100_0032,
            auth_rw | TpmaNv::WRITEDEFINE | TpmaNv::READ_STCLEAR,
        ),
    ] {
        define_nv(&mut sim, index, attributes, 8);
    }
    let extend_index = 0x0100_0033;
    define_nv(
        &mut sim,
        extend_index,
        auth_rw | TpmaNv::from(TpmNt::Extend),
        32,
    );
    let bits_index = 0x0100_0034;
    define_nv(&mut sim, bits_index, auth_rw | TpmaNv::from(TpmNt::Bits), 8);
    set_read_only(&mut sim, true);
    let failures = get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER);

    for index in [0x0100_0030, 0x0100_0031, 0x0100_0032] {
        let write = NVWrite {
            auth_handle: Handle(index),
            nv_index: Handle(index),
            data: Tpm2bMaxNvBuffer::from_bytes(&[3; 8]).unwrap(),
            offset: 0,
        };
        for password in [&b""[..], b"wrong"] {
            assert_eq!(
                execute_with_password_sessions(&mut sim, &write, 1, password).map(|_| ()),
                Err(TpmRc::READ_ONLY.get()),
                "NV_Write({index:#x})"
            );
        }
        let read_lock = NVReadLock {
            auth_handle: Handle(index),
            nv_index: Handle(index),
        };
        assert_eq!(
            execute_with_password_sessions(&mut sim, &read_lock, 1, b"wrong").map(|_| ()),
            Err(TpmRc::READ_ONLY.get()),
            "NV_ReadLock({index:#x})"
        );
        let write_lock = NVWriteLock {
            auth_handle: Handle(index),
            nv_index: Handle(index),
        };
        assert_eq!(
            execute_with_password_sessions(&mut sim, &write_lock, 1, b"wrong").map(|_| ()),
            Err(TpmRc::READ_ONLY.get()),
            "NV_WriteLock({index:#x})"
        );
    }
    let extend = NVExtend {
        auth_handle: Handle(extend_index),
        nv_index: Handle(extend_index),
        data: Tpm2bMaxNvBuffer::from_bytes(b"x").unwrap(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &extend, 1, b"wrong").map(|_| ()),
        Err(TpmRc::READ_ONLY.get())
    );
    let set_bits = NVSetBits {
        auth_handle: Handle(bits_index),
        nv_index: Handle(bits_index),
        bits: 1,
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &set_bits, 1, b"wrong").map(|_| ()),
        Err(TpmRc::READ_ONLY.get())
    );
    // An undefined Index is still reported as such (the handle check comes first).
    assert_eq!(
        nv_write_index(&mut sim, 0x0100_00FF, &[0; 8]),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER), failures);

    // Nothing was written.
    for index in [
        0x0100_0030,
        0x0100_0031,
        0x0100_0032,
        extend_index,
        bits_index,
    ] {
        let rsp = sim
            .execute(NVReadPublic {
                nv_index: Handle(index),
            })
            .unwrap();
        assert!(
            !rsp.nv_public.0.attributes.contains(TpmaNv::WRITTEN),
            "{index:#x}"
        );
    }
}

/// TPM2_PolicySecret is not permitted with a PIN Pass or PIN Fail Index as `authHandle`: it
/// fails with `TPM_RC_READ_ONLY` before authorization, so a wrong PIN does not increment
/// `pinCount`. With another entity it is permitted.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn policy_secret_with_pin_index_fails_before_authorization() {
    let mut sim = Tpm::new();
    let pin_pass = 0x0100_0040;
    let pin_fail = 0x0100_0041;
    for (index, index_type) in [(pin_pass, TpmNt::PinPass), (pin_fail, TpmNt::PinFail)] {
        // pinCount = 0, pinLimit = 10, readable by the owner to check pinCount.
        let mut attributes = NV_RW | TpmaNv::AUTHREAD | TpmaNv::NO_DA;
        attributes.set_type(index_type);
        define_nv(&mut sim, index, attributes, 8);
        write_nv_owner(&mut sim, index, &[0, 0, 0, 0, 0, 0, 0, 10]);
    }
    set_read_only(&mut sim, true);

    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    for auth_handle in [pin_pass, pin_fail] {
        let cmd = PolicySecret {
            auth_handle: Handle(auth_handle),
            policy_session: session.session_handle,
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };
        for password in [&b""[..], b"wrong pin"] {
            assert_eq!(
                execute_with_password_sessions(&mut sim, &cmd, 1, password).map(|_| ()),
                Err(TpmRc::READ_ONLY.get()),
                "{auth_handle:#x}"
            );
        }
    }
    let cmd = PolicySecret {
        auth_handle: Handle::RH_OWNER,
        policy_session: session.session_handle,
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    // pinCount is still 0 for both Indexes.
    set_read_only(&mut sim, false);
    for index in [pin_pass, pin_fail] {
        assert_eq!(read_pin_count(&mut sim, index), 0, "{index:#x}");
    }
}

/// Part 1: "A TPM exits Read-Only mode if the TPM receives a `TPM2_Startup()` for TPM Reset
/// or TPM Restart. However Read-Only mode will remain enabled during TPM Resume."
#[cfg(feature = "cc-read-only-control")]
#[test]
fn mode_is_kept_by_resume_only() {
    let mut sim = Tpm::new();
    // TPM Reset.
    set_read_only(&mut sim, true);
    assert_eq!(power_cycle_with(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    assert!(!is_read_only(&mut sim));
    // TPM Restart.
    set_read_only(&mut sim, true);
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_CLEAR), 0);
    assert!(!is_read_only(&mut sim));
    // TPM Resume.
    set_read_only(&mut sim, true);
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_STATE), 0);
    assert!(is_read_only(&mut sim));
    let cmd = build(ST_NO_SESSIONS, 0x12A, &[], None, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::READ_ONLY.get());
    // Resume of a TPM that is not in Read-Only mode.
    set_read_only(&mut sim, false);
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_STATE), 0);
    assert!(!is_read_only(&mut sim));
}

/// The mode is state-clear data: changing it after `TPM2_Shutdown(TPM_SU_STATE)` clears the
/// orderly state, so TPM Resume fails (`TPM_RC_VALUE` + P1); requesting the current mode
/// changes nothing and Resume succeeds.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn changing_the_mode_clears_the_orderly_state() {
    let mut sim = Tpm::new();
    assert_eq!(shutdown(&mut sim, SU_STATE), 0);
    set_read_only(&mut sim, false);
    assert_eq!(power_cycle_with(&mut sim, None, SU_STATE), 0);

    assert_eq!(shutdown(&mut sim, SU_STATE), 0);
    set_read_only(&mut sim, true);
    assert_eq!(power_cycle_with(&mut sim, None, SU_STATE), RC_VALUE_P1);
    assert_eq!(startup(&mut sim, SU_CLEAR), 0);
    assert!(!is_read_only(&mut sim));
}

/// While NV is unavailable, a change of the mode of an orderly TPM fails with
/// `TPM_RC_NV_UNAVAILABLE` (the orderly state cannot be cleared), and the mode is unchanged.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn mode_change_needs_nv_when_orderly() {
    let mut sim = Tpm::new();
    assert_eq!(shutdown(&mut sim, SU_STATE), 0);
    nv_off(&mut sim);
    assert_eq!(
        read_only_control_rc(&mut sim, 0x4000_000C, 1),
        TpmRc::NV_UNAVAILABLE.get()
    );
    // Requesting the current mode needs no NV.
    assert_eq!(read_only_control_rc(&mut sim, 0x4000_000C, 0), 0);
    nv_on(&mut sim);
    assert!(!is_read_only(&mut sim));
}

/// Between `_TPM_Init` and `TPM2_Startup`, a command that is not permitted in Read-Only mode
/// fails with `TPM_RC_INITIALIZE` like every other command (Part 3, TPM2_Startup), whether or
/// not the TPM was in Read-Only mode before; the mode is then established by `TPM2_Startup`.
#[cfg(feature = "cc-read-only-control")]
#[test]
fn commands_before_startup_are_initialize_errors() {
    let mut sim = Tpm::new();
    let not_permitted = [TpmCc::NVDefineSpace, TpmCc::Clear, TpmCc::CreatePrimary];
    for read_only in [false, true] {
        set_read_only(&mut sim, read_only);
        assert_eq!(shutdown(&mut sim, SU_STATE), 0);
        for signal in [
            SimulatorPlatformSignal::PowerOff,
            SimulatorPlatformSignal::PowerOn,
            SimulatorPlatformSignal::NvOn,
        ] {
            sim.signal_platform(signal).unwrap();
        }
        for cc in not_permitted {
            let cmd = build(ST_NO_SESSIONS, cc.code(), &[], None, &[]);
            assert_eq!(
                mssim_rc_of(&mut sim, &cmd),
                TpmRc::INITIALIZE.get(),
                "{cc:?} (read_only = {read_only})"
            );
        }
        assert_eq!(startup(&mut sim, SU_STATE), 0);
        assert_eq!(is_read_only(&mut sim), read_only);
    }
}
