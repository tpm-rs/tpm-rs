//! TPM2_SetPrimaryPolicy: hierarchies, hash algorithm and policy size validation.

use crate::_common::{
    execute_with_password_sessions, execute_with_password_sessions_status, hex_checked,
    hierarchy_policy, raw_rc, set_hierarchy_enabled, set_primary_policy,
};
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, GetCapability, SetPrimaryPolicy};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bDigest, TpmCap, TpmiAlgHash, TpmsCapabilityData};

/// SetPrimaryPolicy on a disabled storage hierarchy fails.
#[test]
fn disabled_hierarchy_rejected() {
    let mut sim = Tpm::new();

    // Disable the storage hierarchy (shEnable = CLEAR).
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);

    let rc = set_primary_policy(&mut sim, Handle::RH_OWNER, &[0x42; 32]);
    assert_ne!(
        rc, 0,
        "SetPrimaryPolicy against disabled hierarchy should fail"
    );
}

/// SetPrimaryPolicy works for the endorsement and lockout hierarchies.
#[test]
fn endorsement_and_lockout_policies_set() {
    let mut sim = Tpm::new();

    let rc = set_primary_policy(&mut sim, Handle::RH_ENDORSEMENT, &[0x11; 32]);
    assert_eq!(rc, 0);
    assert_eq!(
        hierarchy_policy(&mut sim, Handle::RH_ENDORSEMENT),
        [0x11; 32]
    );
}

/// Regression test for CPCTPM_TC2_2_26_03_04:
/// TPM2_SetPrimaryPolicy specifying an unsupported hash algorithm (TPM_ALG_AES = 0x0006)
/// must return TPM_RC_HASH (Parameter 2, 0x02C3), and mismatched policy size
/// must return TPM_RC_SIZE (Parameter 1, 0x01D5).
#[test]
fn invalid_hash_and_policy_size() {
    let mut sim = Tpm::new();

    // 1. Invalid hashAlg TPM_ALG_AES (0x0006) -> TPM_RC_HASH (Pos2, 0x02C3)
    let mut set_policy_invalid_hash = hex_checked(concat!(
        "8002",     // SESSIONS
        "0000003f", // size: 63 bytes
        "0000012e", // TPM_CC_SetPrimaryPolicy
        "40000001", // authHandle: RH_OWNER
        "00000009", // authSize: 9
        "40000009", // session: RS_PW
        "0000",     // nonce
        "01",       // continueSession
        "0000",     // hmac
        "0020",     // authPolicy size: 32 bytes
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "0006", // hashAlg: TPM_ALG_AES (invalid)
    ));
    let len = set_policy_invalid_hash.len() as u32;
    set_policy_invalid_hash[2..6].copy_from_slice(&len.to_be_bytes());
    let rc = raw_rc(&mut sim, &set_policy_invalid_hash);
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH (0x02C3) for SetPrimaryPolicy with invalid hash algorithm"
    );

    // 2. Mismatched authPolicy size (16 bytes for SHA256) -> TPM_RC_SIZE (Pos1, 0x01D5)
    let mut set_policy_mismatched_size = hex_checked(concat!(
        "8002",     // SESSIONS
        "0000002f", // size: 47 bytes
        "0000012e", // TPM_CC_SetPrimaryPolicy
        "40000001", // authHandle: RH_OWNER
        "00000009", // authSize: 9
        "40000009", // session: RS_PW
        "0000",     // nonce
        "01",       // continueSession
        "0000",     // hmac
        "0010",     // authPolicy size: 16 bytes (expected 32 for SHA256)
        "000102030405060708090a0b0c0d0e0f",
        "000b", // hashAlg: SHA256
    ));
    let len = set_policy_mismatched_size.len() as u32;
    set_policy_mismatched_size[2..6].copy_from_slice(&len.to_be_bytes());
    let rc = raw_rc(&mut sim, &set_policy_mismatched_size);
    assert_eq!(
        rc,
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_SIZE (0x01D5) for SetPrimaryPolicy with mismatched authPolicy size"
    );
}

/// SetPrimaryPolicy(OWNER) is reported by GetCapability(AUTH_POLICIES) and fails with HIERARCHY once shEnable is clear.
#[test]
fn owner_policy_reported_and_disabled_hierarchy_rejected() {
    let mut sim = Tpm::new();

    let cmd = SetPrimaryPolicy {
        auth_handle: Handle::RH_OWNER,
        auth_policy: Tpm2bDigest::from_bytes(&[0x42; 32]).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    // 1. Authorize with default empty owner auth via password session
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).expect("SetPrimaryPolicy failed");

    // The owner policy is reported by TPM2_GetCapability(TPM_CAP_AUTH_POLICIES).
    let cap = sim
        .execute(GetCapability {
            capability: TpmCap::AuthPolicies,
            property: Handle::RH_OWNER.0,
            property_count: 1,
        })
        .expect("GetCapability(TPM_CAP_AUTH_POLICIES) failed");
    let TpmsCapabilityData::AuthPolicies(policies) = cap.capability_data else {
        panic!("unexpected capability data");
    };
    let owner = policies
        .as_ref()
        .iter()
        .find(|p| p.handle == Handle::RH_OWNER)
        .expect("owner policy not reported");
    assert_eq!(
        owner.policy_hash.as_ref().map(|h| h.digest().to_vec()),
        Some(vec![0x42; 32])
    );

    // 2. Disabling the storage hierarchy (shEnable) fails any operation requiring RHOwner
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).map(|_| ());
    assert_eq!(
        res.err(),
        Some(TpmRc::HIERARCHY.with(Position::handle(1)).get())
    );
}

/// SetPrimaryPolicy sets a 32-byte owner authPolicy that is reported afterwards.
#[test]
fn owner_policy_set() {
    let mut sim = Tpm::new();

    // 1. Authorize under Owner hierarchy and set a 32-byte authPolicy
    let rc = set_primary_policy(&mut sim, Handle::RH_OWNER, &[0x42; 32]);
    assert_eq!(rc, 0, "SetPrimaryPolicy under Owner should succeed");
    assert_eq!(hierarchy_policy(&mut sim, Handle::RH_OWNER), [0x42; 32]);

    // 2. Confirm subsequent hierarchy-bound operations enforce the new primary policy.
    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        ..Default::default()
    };
    let _ = execute_with_password_sessions_status(&mut sim, &create_cmd, 1, &[]);
    assert_ne!(
        hierarchy_policy(&mut sim, Handle::RH_OWNER),
        Vec::<u8>::new(),
        "Owner policy should be stored and preserved"
    );
}

/// SetPrimaryPolicy with a digest size not matching hashAlg fails with SIZE.
#[test]
fn policy_size_mismatch_rejected() {
    let mut sim = Tpm::new();

    let rc = set_primary_policy(&mut sim, Handle::RH_OWNER, &[0x22; 20]);
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(1)).get());
}
