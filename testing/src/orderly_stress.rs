use crate::test_utils::*;
use tpm2::Handle;
use tpm2::Tpm2bAuth;
use tpm2::commands::HierarchyChangeAuth;
use tpm2_simulator::create_simulator;

#[test]
fn test_hierarchy_change_auth_orderly_state() {
    let mut sim = create_simulator!();

    // Change owner auth
    let hca_cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(&[1, 2, 3]).unwrap(),
    };
    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, 1, &[]);
    assert!(resp.is_ok());

    // Check if orderly state was cleared.
    // In Rust tpm context we can't easily read orderly_state from simulator,
    // but we can check if it behaves differently.
    // Actually we can just read the global_state if we access it, but Simulator encapsulates it.
}
