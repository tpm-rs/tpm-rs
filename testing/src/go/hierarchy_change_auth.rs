use crate::test_utils::*;
use tpm2::Handle;
use tpm2::Tpm2bAuth;
use tpm2::commands::{HierarchyChangeAuth, HierarchyChangeAuthHandles};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// Original Go test: hierarchy_change_auth_test.go - TestHierarchyChangeAuth/HierarchyChangeAuthOwner
#[test]
fn test_hierarchy_change_auth_owner() {
    let mut sim = create_simulator!();

    let auth_key = b"authkey";

    let hca_cmd = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(auth_key).unwrap(),
    };

    let hca_handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, hca_handles, 1, &[]);
    assert!(resp.is_ok(), "failed HierarchyChangeAuth: {:?}", resp.err());
}

// Original Go test: hierarchy_change_auth_test.go - TestHierarchyChangeAuth/HierarchyChangeAuthOwnerUnauth
#[test]
fn test_hierarchy_change_auth_owner_unauth() {
    let mut sim = create_simulator!();

    let auth_key = b"authkey";
    let new_auth_key = b"newAuthKey";

    // Setup: change to auth_key first
    let hca_cmd_setup = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(auth_key).unwrap(),
    };
    let hca_handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let resp =
        execute_with_password_sessions(&mut sim, &hca_cmd_setup, hca_handles.clone(), 1, &[]);
    assert!(resp.is_ok(), "setup failed: {:?}", resp.err());

    // Test unauth
    let hca_cmd = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(new_auth_key).unwrap(),
    };
    let resp_unauth = execute_with_password_sessions(&mut sim, &hca_cmd, hca_handles, 1, &[]);
    assert!(
        resp_unauth.is_err(),
        "failed HierarchyChangeAuthWithoutAuth: want err, got ok"
    );
    if let Err(e) = resp_unauth {
        // TPMRCBadAuth is generally 0x0989 but with FMT1 might have session info.
        // 0x9A2 is TPM_RC_S + (1 << 8) + TPM_RC_BAD_AUTH (0x022 + 0x080)
        assert_eq!(e, 0x9A2, "Expected TPM_RC_BAD_AUTH for session 1");
    }
}

// Original Go test: hierarchy_change_auth_test.go - TestHierarchyChangeAuth/HierarchyChangeAuthOwnerAuth
#[test]
fn test_hierarchy_change_auth_owner_auth() {
    let mut sim = create_simulator!();

    let auth_key = b"authkey";
    let new_auth_key = b"newAuthKey";

    // Setup: change to auth_key first
    let hca_cmd_setup = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(auth_key).unwrap(),
    };
    let hca_handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let resp =
        execute_with_password_sessions(&mut sim, &hca_cmd_setup, hca_handles.clone(), 1, &[]);
    assert!(resp.is_ok(), "setup failed: {:?}", resp.err());

    // Test auth
    let hca_cmd = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(new_auth_key).unwrap(),
    };
    let resp_auth = execute_with_password_sessions(&mut sim, &hca_cmd, hca_handles, 1, auth_key);
    assert!(
        resp_auth.is_ok(),
        "failed HierarchyChangeAuthWithAuth: {:?}",
        resp_auth.err()
    );
}
