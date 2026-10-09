use crate::test_utils::*;
use tpm2::Handle;
use tpm2::Tpm2bAuth;
use tpm2::commands::{HierarchyChangeAuth, HierarchyChangeAuthHandles};
use tpm2::errors::TpmRc;
use tpm2_simulator::{Simulator, create_simulator};

const AUTH_KEY: &[u8] = b"authkey";
const NEW_AUTH_KEY: &[u8] = b"newAuthKey";

// In Go, the three subtests of `TestHierarchyChangeAuth` share a single TPM
// and run in order, each depending on the state left by the previous ones.
// Each Rust test therefore replays the preceding subtests (via the helpers
// below) on a fresh simulator before running its own steps.

/// Body of `TestHierarchyChangeAuth/HierarchyChangeAuthOwner`: sets the owner
/// auth to `AUTH_KEY` using an empty password session.
fn hierarchy_change_auth_owner(sim: &mut Simulator<'_>) {
    let hca = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(AUTH_KEY).unwrap(),
    };
    let hca_handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let resp = execute_with_password_sessions(sim, &hca, hca_handles, 1, &[]);
    assert!(resp.is_ok(), "failed HierarchyChangeAuth: {:?}", resp.err());
}

/// Body of `TestHierarchyChangeAuth/HierarchyChangeAuthOwnerUnauth`: tries to
/// change the owner auth with an empty password, which must fail with
/// `TPM_RC_BAD_AUTH`.
fn hierarchy_change_auth_owner_unauth(sim: &mut Simulator<'_>) {
    let hca = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(NEW_AUTH_KEY).unwrap(),
    };
    let hca_handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let resp = execute_with_password_sessions(sim, &hca, hca_handles, 1, &[]);
    // Go's `errors.Is(err, TPMRCBadAuth)` compares the canonical format-1
    // error code, ignoring the handle/parameter/session index.
    let canonical = resp
        .as_ref()
        .err()
        .and_then(|&rc| TpmRc::new(rc))
        .and_then(TpmRc::to_fmt1)
        .map(|(fmt1, _)| fmt1);
    assert_eq!(
        canonical,
        Some(TpmRc::BAD_AUTH),
        "failed HierarchyChangeAuthWithoutAuth: want TPM_RC_BAD_AUTH, got {:?}",
        resp.err()
    );
}

/// Body of `TestHierarchyChangeAuth/HierarchyChangeAuthOwnerAuth`: changes
/// the owner auth to `NEW_AUTH_KEY` using the correct password `AUTH_KEY`.
fn hierarchy_change_auth_owner_auth(sim: &mut Simulator<'_>) {
    let hca = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(NEW_AUTH_KEY).unwrap(),
    };
    let hca_handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let resp = execute_with_password_sessions(sim, &hca, hca_handles, 1, AUTH_KEY);
    assert!(
        resp.is_ok(),
        "failed HierarchyChangeAuthWithAuth: {:?}",
        resp.err()
    );
}

// Original Go test: hierarchy_change_auth_test.go - TestHierarchyChangeAuth/HierarchyChangeAuthOwner
#[test]
fn test_hierarchy_change_auth_hierarchy_change_auth_owner() {
    let mut sim = create_simulator!();
    hierarchy_change_auth_owner(&mut sim);
}

// Original Go test: hierarchy_change_auth_test.go - TestHierarchyChangeAuth/HierarchyChangeAuthOwnerUnauth
#[test]
fn test_hierarchy_change_auth_hierarchy_change_auth_owner_unauth() {
    let mut sim = create_simulator!();
    // State left by the preceding subtest.
    hierarchy_change_auth_owner(&mut sim);

    hierarchy_change_auth_owner_unauth(&mut sim);
}

// Original Go test: hierarchy_change_auth_test.go - TestHierarchyChangeAuth/HierarchyChangeAuthOwnerAuth
#[test]
fn test_hierarchy_change_auth_hierarchy_change_auth_owner_auth() {
    let mut sim = create_simulator!();
    // State left by the preceding subtests.
    hierarchy_change_auth_owner(&mut sim);
    hierarchy_change_auth_owner_unauth(&mut sim);

    hierarchy_change_auth_owner_auth(&mut sim);
}
