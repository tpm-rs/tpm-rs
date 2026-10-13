//! TPM2_ChangePPS / TPM2_ChangeEPS: seed replacement and its effect on primaries, persistent
//! objects and policies.

use crate::_common::{
    create_storage_primary_with_auth, evict, execute_rc, execute_with_password_sessions,
    get_tpm_property, hash_ticket_digest, hierarchy_control, object_exists, primary_public,
    pw_session,
};
use testing::tpm::Tpm;
use tpm2::commands::{ChangeEPS, ChangePPS, GetCapability, SetPrimaryPolicy};
use tpm2::{Handle, Tpm2bDigest, TpmCap, TpmPt, TpmiAlgHash, TpmsCapabilityData};

/// ChangeEPS flushes endorsement persistent objects (not storage ones) and resets the endorsement authPolicy alg to NULL.
///
/// ChangeEPS flushes endorsement evict objects (but not storage ones) and resets endorsementAlg.
#[test]
fn change_eps_flushes_endorsement_objects() {
    let mut sim = Tpm::new();
    let (ek, _) = create_storage_primary_with_auth(&mut sim, Handle::RH_ENDORSEMENT, &[]);
    evict(&mut sim, Handle::RH_OWNER, ek, 0x8101_0001);
    let (srk, _) = create_storage_primary_with_auth(&mut sim, Handle::RH_OWNER, &[]);
    evict(&mut sim, Handle::RH_OWNER, srk, 0x8100_0003);
    execute_with_password_sessions(
        &mut sim,
        &SetPrimaryPolicy {
            auth_handle: Handle::RH_ENDORSEMENT,
            auth_policy: Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .unwrap();

    // The storage hierarchy being disabled must not protect endorsement evict objects stored in
    // the owner persistent range: NvFlushHierarchy only looks at the stored hierarchy.
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, false).unwrap();
    execute_with_password_sessions(
        &mut sim,
        &ChangeEPS {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap();
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, true).unwrap();
    assert!(
        !object_exists(&mut sim, 0x8101_0001),
        "EK survived ChangeEPS"
    );
    assert!(
        object_exists(&mut sim, 0x8100_0003),
        "SRK deleted by ChangeEPS"
    );

    // TPM_CAP_AUTH_POLICIES reports TPM_ALG_NULL for the endorsement hierarchy again.
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::AuthPolicies,
            property: Handle::RH_ENDORSEMENT.0,
            property_count: 1,
        })
        .unwrap();
    match rsp.capability_data {
        TpmsCapabilityData::AuthPolicies(policies) => {
            let entry = policies
                .as_ref()
                .iter()
                .find(|p| p.handle == Handle::RH_ENDORSEMENT)
                .expect("endorsement policy missing");
            assert!(
                entry.policy_hash.is_none(),
                "endorsementAlg not reset: {entry:?}"
            );
        }
        other => panic!("unexpected capability data {other:?}"),
    }
}

/// ChangeEPS replaces the endorsement seed and proof and leaves the endorsement hierarchy enabled.
///
/// `TPM2_ChangeEPS` replaces the endorsement primary seed and the endorsement proof, and
/// leaves the endorsement hierarchy enabled.
#[test]
fn change_eps_replaces_endorsement_seed() {
    let mut sim = Tpm::new();

    let initial_ep_primary = primary_public(&mut sim, Handle::RH_ENDORSEMENT);
    let initial_eh_ticket = hash_ticket_digest(&mut sim, Handle::RH_ENDORSEMENT);

    // Send ChangeEPS with TPM_RH_PLATFORM
    let cmd = ChangeEPS {
        auth_handle: Handle::RH_PLATFORM,
    };
    // TPM_RH_PLATFORM requires authorization (C `CheckAuthNoSession` -> TPM_RC_AUTH_MISSING
    // without a session), so use an empty password session.
    assert_eq!(
        execute_rc(&mut sim, &cmd, &[pw_session()]),
        0,
        "ChangeEPS failed"
    );

    assert_ne!(
        primary_public(&mut sim, Handle::RH_ENDORSEMENT),
        initial_ep_primary
    );
    assert_ne!(
        hash_ticket_digest(&mut sim, Handle::RH_ENDORSEMENT),
        initial_eh_ticket
    );
    // TPMA_STARTUP_CLEAR.ehEnable (bit 2) is still set.
    let startup_clear = get_tpm_property(&mut sim, TpmPt::STARTUP_CLEAR);
    assert_ne!(startup_clear & (1 << 2), 0, "ehEnable cleared by ChangeEPS");
}

/// ChangePPS with TPM_RH_OWNER as auth handle fails.
#[test]
fn change_pps_rejects_owner_handle() {
    let mut sim = Tpm::new();

    // Send ChangePPS with non-platform handle TPM_RH_OWNER (should fail)
    let cmd = ChangePPS {
        auth_handle: Handle::RH_OWNER,
    };
    let err = execute_rc(&mut sim, &cmd, &[]);

    assert_ne!(err, 0, "ChangePPS should fail with non-platform handle");
}

/// ChangePPS replaces the platform seed and proof: platform primaries and tickets change.
///
/// `TPM2_ChangePPS` replaces the platform primary seed and the platform proof: platform
/// primary keys and platform tickets change.
#[test]
fn change_pps_replaces_platform_seed() {
    let mut sim = Tpm::new();

    let initial_pp_primary = primary_public(&mut sim, Handle::RH_PLATFORM);
    let initial_ph_ticket = hash_ticket_digest(&mut sim, Handle::RH_PLATFORM);

    // Send ChangePPS with TPM_RH_PLATFORM
    let cmd = ChangePPS {
        auth_handle: Handle::RH_PLATFORM,
    };
    // TPM_RH_PLATFORM requires authorization (C `CheckAuthNoSession` -> TPM_RC_AUTH_MISSING
    // without a session), so use an empty password session.
    assert_eq!(
        execute_rc(&mut sim, &cmd, &[pw_session()]),
        0,
        "ChangePPS failed"
    );

    assert_ne!(
        primary_public(&mut sim, Handle::RH_PLATFORM),
        initial_pp_primary
    );
    assert_ne!(
        hash_ticket_digest(&mut sim, Handle::RH_PLATFORM),
        initial_ph_ticket
    );
}
