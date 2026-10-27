//! What TPM2_GetCapability reports about the Authenticated Countdown Timers: `TPM_CAP_ACT` (one
//! `TPMS_ACT_DATA` per implemented ACT), the ACT handles among the permanent handles
//! (`TPM_CAP_HANDLES`), the ACT policies (`TPM_CAP_AUTH_POLICIES`, reset by TPM Reset and TPM
//! Restart, kept by TPM Resume) and TPM2_ACT_SetTimeout in `TPM_CAP_COMMANDS`.

use crate::_common::{
    TPM_SU_CLEAR, TPM_SU_STATE, act_set_timeout, cap_act, cap_handles, command_attributes, get_cap,
    implemented_act_handles, power_cycle_with, rc_p, set_primary_policy, sleep,
};
use std::time::Duration;
use testing::tpm::Tpm;
use tpm2::commands::GetCapability;
use tpm2::errors::TpmRc;
use tpm2::{Handle, TpmCap, TpmsCapabilityData, TpmtHa};

/// `TPM_RH_ACT_0`.
const ACT_0: u32 = 0x4000_0110;
/// `TPM_CAP_ACT`.
const CAP_ACT: u32 = 0xA;

/// A `TPMS_TAGGED_POLICY`: the handle and its policy digest (`None`: `TPM_ALG_NULL`).
type TaggedPolicy = (u32, Option<Vec<u8>>);

/// The `(handle, policy digest)` of every `TPM_CAP_AUTH_POLICIES` entry from `property` on
/// (at most 16), and `moreData`.
fn auth_policies(sim: &mut Tpm, property: u32, count: u32) -> (Vec<TaggedPolicy>, bool) {
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::AuthPolicies,
            property,
            property_count: count,
        })
        .unwrap();
    let TpmsCapabilityData::AuthPolicies(policies) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    let list = policies
        .as_ref()
        .iter()
        .map(|p| {
            (
                p.handle.0,
                p.policy_hash.map(|ha: TpmtHa| ha.digest().to_vec()),
            )
        })
        .collect();
    (list, rsp.more_data)
}

/// `TPM_CAP_ACT` lists the implemented ACTs from `property` on (at most `propertyCount`),
/// with `moreData` SET if an implemented ACT was left out; `propertyCount` zero lists none.
#[test]
fn act_capability_lists_the_implemented_acts() {
    let mut sim = Tpm::new();
    let acts = implemented_act_handles();
    let all: Vec<(u32, u32, u32)> = acts.iter().map(|&a| (a, 0, 0)).collect();
    assert_eq!(cap_act(&mut sim, ACT_0, 16), Ok((all.clone(), false)));
    assert_eq!(
        cap_act(&mut sim, ACT_0, 1),
        Ok((all[..1].to_vec(), acts.len() > 1))
    );
    assert_eq!(cap_act(&mut sim, ACT_0, 0), Ok((vec![], true)));
    // From the property on.
    assert_eq!(
        cap_act(&mut sim, ACT_0 + 1, 16),
        Ok((all[1..].to_vec(), false))
    );
    assert_eq!(
        cap_act(&mut sim, Handle::RH_ACT_F.0, 16),
        Ok((vec![], false))
    );
    assert_eq!(
        cap_act(&mut sim, Handle::RH_ACT_F.0, 0),
        Ok((vec![], false))
    );
}

/// A `TPM_CAP_ACT` property outside `{TPM_RH_ACT_0:TPM_RH_ACT_F}` is `TPM_RC_VALUE + RC_P2`.
#[test]
fn act_capability_rejects_non_act_properties() {
    let mut sim = Tpm::new();
    for property in [
        0,
        Handle::RH_PLATFORM.0,
        ACT_0 - 1,
        Handle::RH_ACT_F.0 + 1,
        u32::MAX,
    ] {
        assert_eq!(
            get_cap(&mut sim, CAP_ACT, property, 1).map(|_| ()),
            Err(rc_p(TpmRc::VALUE, 2)),
            "property {property:#x}"
        );
    }
}

/// `TPM_CAP_ACT` reports the pending timeout of an update before the tick applies it.
#[test]
fn act_capability_reports_the_pending_timeout() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 30), 0);
    let (list, _) = cap_act(&mut sim, ACT_0, 1).unwrap();
    assert_eq!(list, vec![(ACT_0, 30, 0)]);
    sleep(Duration::from_secs(1));
    let (list, _) = cap_act(&mut sim, ACT_0, 1).unwrap();
    assert_eq!(list, vec![(ACT_0, 29, 0)]);
}

/// The implemented ACTs are permanent handles (`TPM_CAP_HANDLES`), in handle order after
/// `TPM_RH_AUTH_00`.
#[test]
fn act_handles_are_permanent_handles() {
    let mut sim = Tpm::new();
    let (handles, more) = cap_handles(&mut sim, 0x4000_0000, 64).unwrap();
    assert!(!more);
    for act in implemented_act_handles() {
        assert!(handles.contains(&act), "{act:#x} missing from {handles:x?}");
    }
    for act in Handle::RH_ACT_0.0..=Handle::RH_ACT_F.0 {
        assert_eq!(
            handles.contains(&act),
            implemented_act_handles().contains(&act),
            "{act:#x}"
        );
    }
    assert!(handles.windows(2).all(|w| w[0] < w[1]), "{handles:x?}");
    let (from_act, _) = cap_handles(&mut sim, ACT_0, 64).unwrap();
    assert_eq!(
        &from_act[..implemented_act_handles().len()],
        &implemented_act_handles()[..]
    );
}

/// `TPM_CAP_AUTH_POLICIES` lists every implemented ACT after the hierarchies (and before the
/// firmware-limited and SVN-limited hierarchies), with `TPM_ALG_NULL` until
/// TPM2_SetPrimaryPolicy sets its policy.
#[test]
fn act_policies_are_reported() {
    let mut sim = Tpm::new();
    let acts = implemented_act_handles();
    let (list, more) = auth_policies(&mut sim, Handle::RH_OWNER.0, 16);
    assert!(!more);
    let handles: Vec<u32> = list.iter().map(|e| e.0).collect();
    let mut expected = vec![
        Handle::RH_OWNER.0,
        Handle::RH_LOCKOUT.0,
        Handle::RH_ENDORSEMENT.0,
        Handle::RH_PLATFORM.0,
    ];
    expected.extend(&acts);
    // The firmware-limited and SVN-limited hierarchies with a policy follow
    // (`limited_hierarchies.rs`).
    expected.extend([
        Handle::RH_FW_OWNER.0,
        Handle::RH_FW_ENDORSEMENT.0,
        Handle::RH_FW_PLATFORM.0,
        Handle::RH_SVN_OWNER_BASE.0,
        Handle::RH_SVN_ENDORSEMENT_BASE.0,
        Handle::RH_SVN_PLATFORM_BASE.0,
    ]);
    assert_eq!(handles, expected);
    assert!(list.iter().all(|e| e.1.is_none()));
    // The hierarchies alone leave the ACTs out: moreData.
    let (list, more) = auth_policies(&mut sim, Handle::RH_OWNER.0, 4);
    assert_eq!(list.len(), 4);
    assert!(more);

    assert_eq!(set_primary_policy(&mut sim, Handle(ACT_0), &[0x5A; 32]), 0);
    let (list, more) = auth_policies(&mut sim, ACT_0, 1);
    assert_eq!(list, vec![(ACT_0, Some(vec![0x5A; 32]))]);
    // Further ACTs or the limited hierarchies follow.
    assert!(more);
}

/// The ACT policies are kept by TPM Resume and reset to the Empty Policy by TPM Restart and TPM
/// Reset (Part 1, "Authenticated Countdown Timer (ACT)").
#[test]
fn act_policies_survive_resume_only() {
    let mut sim = Tpm::new();
    let policy_of = |sim: &mut Tpm| auth_policies(sim, ACT_0, 1).0[0].1.clone();
    assert_eq!(set_primary_policy(&mut sim, Handle(ACT_0), &[0x66; 32]), 0);
    assert_eq!(
        power_cycle_with(&mut sim, Some(TPM_SU_STATE), TPM_SU_STATE),
        0
    );
    assert_eq!(policy_of(&mut sim), Some(vec![0x66; 32]));
    assert_eq!(
        power_cycle_with(&mut sim, Some(TPM_SU_STATE), TPM_SU_CLEAR),
        0
    );
    assert_eq!(policy_of(&mut sim), None);

    assert_eq!(set_primary_policy(&mut sim, Handle(ACT_0), &[0x77; 32]), 0);
    assert_eq!(
        power_cycle_with(&mut sim, Some(TPM_SU_CLEAR), TPM_SU_CLEAR),
        0
    );
    assert_eq!(policy_of(&mut sim), None);

    assert_eq!(set_primary_policy(&mut sim, Handle(ACT_0), &[0x88; 32]), 0);
    assert_eq!(power_cycle_with(&mut sim, None, TPM_SU_CLEAR), 0);
    assert_eq!(policy_of(&mut sim), None);
}

/// TPM2_ACT_SetTimeout is implemented: `TPM_CAP_COMMANDS` reports it with one handle and no
/// other attribute (the TCG reference's `TPMA_CC_INITIALIZER(0x0198, 0, 0, 0, 0, 1, 0, 0, 0)`).
#[test]
fn act_set_timeout_command_attributes() {
    let mut sim = Tpm::new();
    assert_eq!(command_attributes(&mut sim, 0x198), 0x0200_0198);
}
