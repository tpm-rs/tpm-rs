//! TPM2_HierarchyControl: enabling/disabling hierarchies, who may do it, and NV/orderly ordering.

use crate::_common::{
    CC_HIERARCHY_CONTROL, ST_NO_SESSIONS, SU_CLEAR, build_pw_cmd, build_raw_cmd,
    create_storage_primary_with_auth, evict, execute_with_password_sessions, hierarchy_control,
    mssim_rc_of, nv_off, nv_on, nv_unavailable, object_exists, rc_p, shutdown_raw,
};
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::create_simulator;

/// HierarchyControl runs RETURN_IF_ORDERLY before changing state, and a no-op call needs no NV.
#[test]
fn orderly_check_before_state_change() {
    let mut sim = create_simulator!();
    // Make the TPM orderly again so that RETURN_IF_ORDERLY needs NV.
    assert_eq!(shutdown_raw(&mut sim, SU_CLEAR), 0);
    nv_off(&mut sim);
    // No-op: the storage hierarchy is already enabled.
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, true)
        .expect("no-op HierarchyControl needed NV");
    // A real change fails without modifying the state.
    assert_eq!(
        hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, false),
        Err(nv_unavailable())
    );
    nv_on(&mut sim);
    create_storage_primary_with_auth(&mut sim, Handle::RH_OWNER, &[]);
}

/// Same ordering through the engine path (owner re-enable no-op is not AUTH_TYPE).
#[test]
fn owner_noop_and_failed_disable_keep_state() {
    let mut sim = create_simulator!();
    assert_eq!(
        hierarchy_control(
            &mut sim,
            Handle::RH_ENDORSEMENT,
            Handle::RH_ENDORSEMENT,
            true
        ),
        Ok(())
    );
    assert_eq!(shutdown_raw(&mut sim, SU_CLEAR), 0);
    nv_off(&mut sim);
    assert_eq!(
        hierarchy_control(
            &mut sim,
            Handle::RH_ENDORSEMENT,
            Handle::RH_ENDORSEMENT,
            false
        ),
        Err(nv_unavailable())
    );
    nv_on(&mut sim);
    // The endorsement hierarchy is still enabled.
    create_storage_primary_with_auth(&mut sim, Handle::RH_ENDORSEMENT, &[]);
}

/// Same evict-object behavior through the generic hierarchy finding.
#[test]
fn owner_reenable_rules_and_change_pps_flush() {
    let mut sim = create_simulator!();
    // Owner may "enable" the already enabled storage hierarchy (no-op success).
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, true).unwrap();
    hierarchy_control(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        Handle::RH_ENDORSEMENT,
        true,
    )
    .unwrap();
    // ...but not re-enable it once disabled: ownerAuth is unusable while shEnable is CLEAR
    // (`EntityGetLoadStatus` -> TPM_RC_HIERARCHY + H1); only platform auth can re-enable it.
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, false).unwrap();
    assert_eq!(
        hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, true),
        Err(TpmRc::HIERARCHY.with(Position::handle(1)).get())
    );
    assert_eq!(
        hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, true),
        Ok(())
    );

    // ChangePPS flushes platform evict objects but keeps owner ones.
    let (owner_key, _) = create_storage_primary_with_auth(&mut sim, Handle::RH_OWNER, &[]);
    evict(&mut sim, Handle::RH_OWNER, owner_key, 0x8100_0002);
    let (platform_key, _) = create_storage_primary_with_auth(&mut sim, Handle::RH_PLATFORM, &[]);
    evict(&mut sim, Handle::RH_PLATFORM, platform_key, 0x8180_0002);
    execute_with_password_sessions(
        &mut sim,
        &ChangePPS {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap();
    assert!(!object_exists(&mut sim, 0x8180_0002));
    assert!(object_exists(&mut sim, 0x8100_0002));
}

/// `TPM2_HierarchyControl` parameters are validated by the handler after authorization, in
/// parameter order.
#[test]
fn parameters_validated_after_auth_in_order() {
    let mut sim = create_simulator!();
    // Both parameters invalid: `enable` (parameter 1) is reported.
    let mut params = 0x4000_0005u32.to_be_bytes().to_vec();
    params.push(2);
    let cmd = build_pw_cmd(CC_HIERARCHY_CONTROL, &[Handle::RH_PLATFORM.0], 1, &params);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_p(TpmRc::VALUE, 1));
    // Without a session, the missing authorization is reported before any parameter error.
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_HIERARCHY_CONTROL,
        &[Handle::RH_PLATFORM.0],
        None,
        &params,
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::AUTH_MISSING.get());
}

/// HierarchyControl: phEnableNV can be SET again, and owner may no-op enable.
#[test]
fn ph_enable_nv_reenable_and_owner_noop() {
    let mut sim = create_simulator!();
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_PLATFORM_NV, false).unwrap();
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_PLATFORM_NV, true)
        .expect("phEnableNV could not be re-enabled");
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, true).unwrap();
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, false).unwrap();
    assert_eq!(
        hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_ENDORSEMENT, true),
        Ok(())
    );
}
