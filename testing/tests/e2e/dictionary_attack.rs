//! Dictionary-attack protection: lockout, DictionaryAttackParameters / LockReset, self-healing and
//! NV persistence of failures.

use crate::_common::{
    ATTR_AUDIT, ATTR_CONTINUE, AuthEntry, EMPTY_POLICY, RC_AUTH_FAIL_S1, RC_BAD_AUTH_S1,
    RC_LOCKOUT, RC_NV_UNAVAILABLE, RC_SUCCESS, SU_CLEAR, clear_control, create_da_protected_object,
    create_sealed, create_storage_primary_with_auth, da_lock_reset, da_parameters,
    da_parameters_unwrap, ecc_primary_template, execute_with_hmac_sessions_status,
    execute_with_password_sessions, fail_auth, get_tpm_property, handle_name,
    hierarchy_change_auth, hmac_entry, leak_bytes, lockout_counter, nv_off, nv_on, nv_unavailable,
    power_cycle_with, raw_entry, send_da_lock_reset, send_da_parameters, send_rc_with_auth_entries,
    set_da_parameters, sleep, start_auth_session, start_session_of_type, tpm2b_params,
    unseal_with_auth_entry,
};
use crate::_common::{NO_STREAM, PlatformConnection};
use tpm2::commands::{
    Create, DictionaryAttackLockReset, PolicyCommandCode, SetPrimaryPolicy, Shutdown, Startup,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bSensitiveData, TpmCc, TpmPt, TpmSe,
    TpmSu, TpmaObject, TpmaSession, TpmiAlgHash, TpmlPcrSelection, TpmsSensitiveCreate,
};
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

/// Sessions bound to DA-protected entities are lockout-checked and their failures counted (against lockoutAuth for TPM_RH_LOCKOUT binds)
///
/// Sessions bound to a DA-protected entity (C `isDaBound` / `isLockoutBound`, set by
/// `SessionCreate()`) are subject to DA however they are used: `ParseSessionBuffer()` checks
/// lockout for them and `IncrementLockout()` always counts their failures (against lockoutAuth
/// for a session bound to `TPM_RH_LOCKOUT`).
#[test]
fn da_bound_sessions_subject_to_lockout() {
    let owner = [handle_name(Handle::RH_OWNER.0)];
    let params = tpm2b_params(b"");

    // A failure of a DA-bound session authorizing the (DA-exempt) owner counts as a DA failure.
    {
        let mut sim = create_simulator!();
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"k", &[]);
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle(item),
            b"k",
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let before = lockout_counter(&mut sim);
        let auth = raw_entry(&session, ATTR_CONTINUE, &[0x55; 32]);
        let code = send_rc_with_auth_entries(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &params,
        );
        assert_eq!(code, RC_AUTH_FAIL_S1);
        assert_eq!(lockout_counter(&mut sim), before + 1);
    }

    // In lockout, a DA-bound session cannot be used, even with a correct HMAC for a DA-exempt
    // entity; an unbound session still can.
    {
        let mut sim = create_simulator!();
        set_da_parameters(&mut sim, 1, 1000, 1000);
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"k", &[]);
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle(item),
            b"k",
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        assert_eq!(
            unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"x")),
            RC_AUTH_FAIL_S1
        );
        let auth = hmac_entry(
            &session,
            TpmCc::HierarchyChangeAuth,
            &owner,
            &params,
            &[],
            ATTR_CONTINUE,
        );
        let code = send_rc_with_auth_entries(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &params,
        );
        assert_eq!(code, RC_LOCKOUT);
        let unbound = start_session_of_type(&mut sim, TpmSe::HMAC);
        let auth = hmac_entry(
            &unbound,
            TpmCc::HierarchyChangeAuth,
            &owner,
            &params,
            &[],
            ATTR_CONTINUE,
        );
        let code = send_rc_with_auth_entries(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &params,
        );
        assert_eq!(code, RC_SUCCESS);
    }

    // A failure of a session bound to TPM_RH_LOCKOUT disables lockoutAuth.
    {
        let mut sim = create_simulator!();
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_LOCKOUT,
            &[],
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let before = lockout_counter(&mut sim);
        let auth = raw_entry(&session, ATTR_CONTINUE, &[0x55; 32]);
        let code = send_rc_with_auth_entries(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &params,
        );
        assert_eq!(code, RC_AUTH_FAIL_S1);
        assert_eq!(lockout_counter(&mut sim), before);
        let code = send_rc_with_auth_entries(
            &mut sim,
            TpmCc::DictionaryAttackLockReset,
            &[Handle::RH_LOCKOUT.0],
            &[AuthEntry::pw(&[])],
            &[],
        );
        assert_eq!(code, RC_LOCKOUT);
    }
}

/// Lockout only blocks sessions using the authValue; non-DA failures are BAD_AUTH; the audit attribute does not change the response code
///
/// DA handling of session authorizations (C `CheckAuthSession()`, `IncrementLockout()`):
/// lockout only blocks sessions that use the authValue, failures that do not involve a DA
/// protected authValue are `TPM_RC_BAD_AUTH` without side effects, and the `audit` attribute does
/// not influence the response code.
#[test]
fn da_lockout_only_blocks_auth_value_sessions() {
    // 1. A policy session that does not use the authValue still works in lockout.
    {
        let mut sim = create_simulator!();
        set_da_parameters(&mut sim, 1, 1000, 1000);
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &EMPTY_POLICY);
        assert_eq!(
            unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"x")),
            RC_AUTH_FAIL_S1
        );
        assert_eq!(
            unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"a")),
            RC_LOCKOUT
        );

        let policy = start_session_of_type(&mut sim, TpmSe::Policy);
        assert_eq!(
            unseal_with_auth_entry(&mut sim, item, raw_entry(&policy, 0, &[])),
            RC_SUCCESS
        );
    }

    // 2. A failing policy session that does not include the authValue does not count as a DA
    //    failure.
    {
        let mut sim = create_simulator!();
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &EMPTY_POLICY);
        let before = lockout_counter(&mut sim);
        let policy = start_session_of_type(&mut sim, TpmSe::Policy);
        let code = unseal_with_auth_entry(
            &mut sim,
            item,
            raw_entry(&policy, ATTR_CONTINUE, &[1, 2, 3]),
        );
        assert_eq!(code, RC_BAD_AUTH_S1);
        assert_eq!(lockout_counter(&mut sim), before);
    }

    // 3. HMAC failure on a DA-exempt entity: TPM_RC_BAD_AUTH (no audit attribute involved).
    {
        let mut sim = create_simulator!();
        let session = start_session_of_type(&mut sim, TpmSe::HMAC);
        let auth = raw_entry(&session, ATTR_CONTINUE, &[0x55; 32]);
        let code = send_rc_with_auth_entries(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &tpm2b_params(b""),
        );
        assert_eq!(code, RC_BAD_AUTH_S1);
    }

    // 4. HMAC failure on a DA-protected entity with `audit` set: TPM_RC_AUTH_FAIL, and the
    //    failure is counted.
    {
        let mut sim = create_simulator!();
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &[]);
        let before = lockout_counter(&mut sim);
        let session = start_session_of_type(&mut sim, TpmSe::HMAC);
        let auth = raw_entry(&session, ATTR_CONTINUE | ATTR_AUDIT, &[0x55; 32]);
        assert_eq!(
            unseal_with_auth_entry(&mut sim, item, auth),
            RC_AUTH_FAIL_S1
        );
        assert_eq!(lockout_counter(&mut sim), before + 1);
    }
}

/// TPM2_DictionaryAttackParameters with maxTries=0 puts DA-protected authorization in lockout
///
/// `maxTries == 0` puts the TPM in lockout (C `CheckLockedOut()`: `failedTries >= maxTries`).
#[test]
fn da_max_tries_zero_enters_lockout() {
    let mut sim = create_simulator!();
    let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &[]);
    set_da_parameters(&mut sim, 0, 1000, 1000);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"a")),
        RC_LOCKOUT
    );
}

/// A DA failure that cannot be written to NV becomes pending and blocks DA-protected authorization with TPM_RC_NV_UNAVAILABLE
///
/// A pending DA update that cannot be written to NV blocks further DA-protected
/// authorizations with `TPM_RC_NV_UNAVAILABLE` (C `CheckLockedOut()`:
/// `RETURN_IF_NV_IS_NOT_AVAILABLE` while `s_DAPendingOnNV`).
#[test]
fn da_pending_nv_update_blocks_da_protected_auth() {
    let mut sim = create_simulator!();
    let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &[]);
    // A DA-protected authorization with NV available records SU_DA_USED_VALUE.
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"a")),
        RC_SUCCESS
    );

    sim.signal_platform(SimulatorPlatformSignal::NvOff, NO_STREAM)
        .unwrap();
    // The failure cannot be recorded in NV: it becomes pending.
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"x")),
        RC_AUTH_FAIL_S1
    );
    // While the update is pending and NV is off, DA-protected authorization is refused.
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"a")),
        RC_NV_UNAVAILABLE
    );

    sim.signal_platform(SimulatorPlatformSignal::NvOn, NO_STREAM)
        .unwrap();
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"a")),
        RC_SUCCESS
    );
}

/// DictionaryAttackLockReset/Parameters fail with NV_UNAVAILABLE and leave maxAuthFail unchanged.
#[test]
fn handlers_check_nv_before_mutation() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(da_lock_reset(&mut sim), Err(nv_unavailable()));
    assert_eq!(da_parameters(&mut sim, 1, 1, 1), Err(nv_unavailable()));
    nv_on(&mut sim);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 3);
}

/// DictionaryAttackLockReset clears failed tries; without a session it is TPM_RC_AUTH_MISSING
#[test]
fn lock_reset_clears_failures() {
    let mut sim = create_simulator!();
    // Allow enough failures that the TPM does not enter lockout.
    assert_eq!(send_da_parameters(&mut sim, 10, 1000, 1000), 0);
    let object = create_da_protected_object(&mut sim);

    // 3 failed auth attempts
    fail_auth(&mut sim, object, 3);
    assert_eq!(lockout_counter(&mut sim), 3);

    // Without a session, the lockout handle (USER role) is not authorized: C
    // `CheckAuthNoSession` returns TPM_RC_AUTH_MISSING regardless of the (empty) lockoutAuth.
    let rc = send_da_lock_reset(&mut sim, false);
    assert_eq!(rc, 0x125); // TPM_RC_AUTH_MISSING
    assert_eq!(lockout_counter(&mut sim), 3);

    fail_auth(&mut sim, object, 2);
    assert_eq!(lockout_counter(&mut sim), 5);
    let rc2 = send_da_lock_reset(&mut sim, true);
    assert_eq!(rc2, 0);
    assert_eq!(lockout_counter(&mut sim), 0);
}

/// DictionaryAttackLockReset/Parameters without a session fail with AUTH_MISSING even with empty lockoutAuth.
///
/// DictionaryAttackLockReset / Parameters without a session -> AUTH_MISSING even with an empty
/// lockoutAuth.
#[test]
fn lockout_commands_require_session() {
    let mut sim = create_simulator!();
    let rc = execute_with_password_sessions(
        &mut sim,
        &DictionaryAttackLockReset {
            lock_handle: Handle::RH_LOCKOUT,
        },
        0,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_MISSING.get());
}

/// A lockoutPolicy session still authorizes DictionaryAttackLockReset while direct lockoutAuth use is locked out.
///
/// A `lockoutPolicy` policy session (without PolicyAuthValue/PolicyPassword) keeps working
/// while direct use of `lockoutAuth` is disabled (`IsAuthValueAvailable` / `CheckLockedOut`
/// only when the authValue is used).
#[test]
fn lockout_policy_works_while_lockout_auth_locked() {
    use sha2::{Digest, Sha256};
    let mut sim = create_simulator!();

    // lockoutPolicy = PolicyCommandCode(TPM_CC_DictionaryAttackLockReset).
    let mut hasher = Sha256::new();
    hasher.update([0u8; 32]);
    hasher.update(0x16Cu32.to_be_bytes()); // TPM_CC_PolicyCommandCode
    hasher.update(0x139u32.to_be_bytes()); // TPM_CC_DictionaryAttackLockReset
    let policy = hasher.finalize().to_vec();
    execute_with_password_sessions(
        &mut sim,
        &SetPrimaryPolicy {
            auth_handle: Handle::RH_LOCKOUT,
            auth_policy: Tpm2bDigest::from_bytes(leak_bytes(&policy)).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .unwrap();

    // A wrong lockoutAuth disables direct use of lockoutAuth.
    hierarchy_change_auth(&mut sim, Handle::RH_LOCKOUT, &[], b"lock").unwrap();
    let lock_reset = |sim: &mut Simulator<'_>, auth: &[u8]| {
        execute_with_password_sessions(
            sim,
            &DictionaryAttackLockReset {
                lock_handle: Handle::RH_LOCKOUT,
            },
            1,
            auth,
        )
        .map(|_| ())
    };
    assert!(lock_reset(&mut sim, b"bad").is_err());
    assert_eq!(lock_reset(&mut sim, b"lock"), Err(TpmRc::LOCKOUT.get()));

    // The lockout policy still authorizes DictionaryAttackLockReset.
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes = TpmaSession::CONTINUE_SESSION;
    sim.execute(PolicyCommandCode {
        policy_session: session.session_handle,
        code: TpmCc::DictionaryAttackLockReset,
    })
    .unwrap();
    let lockout_name = Handle::RH_LOCKOUT.0.to_be_bytes();
    execute_with_hmac_sessions_status(
        &mut sim,
        &DictionaryAttackLockReset {
            lock_handle: Handle::RH_LOCKOUT,
        },
        &[&lockout_name],
        core::slice::from_mut(&mut session),
        &[b"lock"],
    )
    .expect("lockoutPolicy rejected while lockoutAuth is disabled");
}

/// DictionaryAttackParameters(newMaxTries=0) puts the TPM in lockout (TPM_PT_PERMANENT.inLockout)
///
/// `newMaxTries == 0` puts the TPM in lockout: `TPM_PT_PERMANENT.inLockout` is reported.
#[test]
fn max_tries_zero_enters_lockout() {
    let mut sim = create_simulator!();
    let permanent = get_tpm_property(&mut sim, TpmPt::PERMANENT);
    assert_eq!(permanent & (1 << 9), 0, "inLockout before");
    da_parameters_unwrap(&mut sim, 0, 1000, 1000);
    let permanent = get_tpm_property(&mut sim, TpmPt::PERMANENT);
    assert_ne!(permanent & (1 << 9), 0, "inLockout with maxTries == 0");
}

/// With orderly state and NV unavailable, DA-protected use returns TPM_RC_NV_UNAVAILABLE
#[test]
fn orderly_state_with_nv_off_is_nv_unavailable() {
    let mut sim = create_simulator!();

    // Put the TPM in an orderly state (TPM2_Shutdown) and make NV unavailable.
    sim.execute(Shutdown {
        shutdown_type: TpmSu::Clear,
    })
    .expect("Shutdown(CLEAR) failed");
    sim.signal_platform(SimulatorPlatformSignal::NvOff, NO_STREAM)
        .unwrap();

    let rc = send_da_lock_reset(&mut sim, true);
    assert_eq!(rc, TpmRc::NV_UNAVAILABLE.get()); // 0x923
}

/// DictionaryAttackParameters needs NV and its values persist across a power cycle.
#[test]
fn parameters_need_nv_and_persist() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(da_parameters(&mut sim, 5, 10, 10), Err(nv_unavailable()));
    nv_on(&mut sim);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 3);
    da_parameters(&mut sim, 5, 10, 10).unwrap();
    assert_eq!(power_cycle_with(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 5);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_INTERVAL), 10);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_RECOVERY), 10);
}

/// DictionaryAttackParameters updates MAX_AUTH_FAIL, LOCKOUT_INTERVAL and LOCKOUT_RECOVERY
#[test]
fn parameters_update_properties() {
    let mut sim = create_simulator!();

    // Send TPM2_DictionaryAttackParameters(maxTries=5, recoveryTime=100, lockoutRecovery=1000)
    let rc = send_da_parameters(&mut sim, 5, 100, 1000);
    assert_eq!(rc, 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 5);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_INTERVAL), 100);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_RECOVERY), 1000);

    // Test with PW session 0x8002
    let rc2 = send_da_parameters(&mut sim, 10, 200, 2000);
    assert_eq!(rc2, 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 10);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_INTERVAL), 200);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_RECOVERY), 2000);
}

/// recoveryTime=0 disables DA protection and resets failedTries
#[test]
fn recovery_time_zero_disables_protection() {
    let mut sim = create_simulator!();
    assert_eq!(send_da_parameters(&mut sim, 10, 1000, 1000), 0);
    let object = create_da_protected_object(&mut sim);
    fail_auth(&mut sim, object, 3);
    assert_eq!(lockout_counter(&mut sim), 3);

    // Setting recoveryTime to 0 disables DA and resets failedTries to 0
    let rc = send_da_parameters(&mut sim, 5, 0, 1000);
    assert_eq!(rc, 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_INTERVAL), 0);
    assert_eq!(lockout_counter(&mut sim), 0);
}

/// DA self-healing does not run while NV is unavailable; DA failures, lock reset and ClearControl NV checks.
#[test]
fn self_heal_and_lock_reset_need_nv() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(da_lock_reset(&mut sim), Err(nv_unavailable()));
    assert_eq!(
        clear_control(&mut sim, Handle::RH_LOCKOUT, true),
        Err(nv_unavailable())
    );
    nv_on(&mut sim);

    // DASelfHeal must not run while NV is unavailable (`TimeUpdateToCurrent`).
    da_parameters(&mut sim, 3, 1, 1000).unwrap();
    hierarchy_change_auth(&mut sim, Handle::RH_OWNER, &[], b"owner").unwrap();
    let (key, _) = create_storage_primary_with_auth(&mut sim, Handle::RH_OWNER, b"owner");
    // A wrong password for the (DA-protected) key counts as a DA failure.
    let rc = execute_with_password_sessions(
        &mut sim,
        &Create {
            parent_handle: key,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: Tpm2b(ecc_primary_template()),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        1,
        b"wrong",
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_FAIL.with(Position::session(1)).get());
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER), 1);
    nv_off(&mut sim);
    sleep(std::time::Duration::from_millis(1300));
    assert_eq!(
        get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER),
        1,
        "DASelfHeal ran while NV was unavailable"
    );
    nv_on(&mut sim);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER), 0);
}

/// After use of a DA-protected object, an unorderly reset increments failedTries and persists
/// it; use of lockoutAuth alone does not count (it is protected by lockoutRecovery)
#[test]
fn unorderly_reset_counts_failure() {
    let mut sim = create_simulator!();
    let unorderly_reset = |sim: &mut Simulator<'_>| {
        // An unorderly VM crash/reset (no Shutdown command) followed by Startup(CLEAR).
        sim.signal_platform(SimulatorPlatformSignal::PowerOff, NO_STREAM)
            .unwrap();
        sim.signal_platform(SimulatorPlatformSignal::PowerOn, NO_STREAM)
            .unwrap();
        sim.signal_platform(SimulatorPlatformSignal::NvOn, NO_STREAM)
            .unwrap();
        sim.execute(Startup {
            startup_type: TpmSu::Clear,
        })
        .expect("Startup(CLEAR) failed");
    };

    // Configure DA: maxTries=5, recoveryTime=100, lockoutRecovery=1000. This authorizes with
    // lockoutAuth, which is not governed by failedTries, so it does not set the "DA-protected
    // object used" flag (TPM 2.0 Part 1, "Non-orderly Shutdown"; C `CheckLockedOut()`).
    let rc = send_da_parameters(&mut sim, 5, 100, 1000);
    assert_eq!(rc, 0);
    assert_eq!(lockout_counter(&mut sim), 0);
    unorderly_reset(&mut sim);
    assert_eq!(lockout_counter(&mut sim), 0);

    // Using a DA-protected object records SU_DA_USED in the orderly state.
    let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &[]);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"a")),
        RC_SUCCESS
    );
    unorderly_reset(&mut sim);

    // failed_tries must have incremented by 1 (and been persisted to NV)
    assert_eq!(lockout_counter(&mut sim), 1);

    // Reset lockout; the reset value must persist across another (orderly) power cycle.
    let rc_reset = send_da_lock_reset(&mut sim, true);
    assert_eq!(rc_reset, 0);
    assert_eq!(lockout_counter(&mut sim), 0);
    sim.execute(Shutdown {
        shutdown_type: TpmSu::Clear,
    })
    .expect("Shutdown(CLEAR) failed");
    sim.signal_platform(SimulatorPlatformSignal::PowerOff, NO_STREAM)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn, NO_STREAM)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn, NO_STREAM)
        .unwrap();
    sim.execute(Startup {
        startup_type: TpmSu::Clear,
    })
    .expect("Startup(CLEAR) failed");
    assert_eq!(lockout_counter(&mut sim), 0);
}
