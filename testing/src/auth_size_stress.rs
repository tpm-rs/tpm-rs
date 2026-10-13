use crate::test_utils::*;
use tpm2::Handle;
use tpm2::Tpm2bAuth;
use tpm2::commands::HierarchyChangeAuth;
use tpm2_simulator::create_simulator;

#[test]
fn test_hierarchy_change_auth_max_size() {
    let mut sim = create_simulator!();

    // The max auth size should be the digest size of the context integrity hash.
    // In this simulator, it is SHA256 -> 32 bytes.
    let valid_auth = vec![1u8; 32];

    let hca_cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(&valid_auth).unwrap(),
    };
    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, 1, &[]);
    assert!(resp.is_ok(), "32 byte auth should be valid");

    // Try a 33-byte auth. This should FAIL with TPM_RC_SIZE.
    let invalid_auth = vec![2u8; 33];
    let hca_cmd2 = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(&invalid_auth).unwrap(),
    };
    let resp2 = execute_with_password_sessions(&mut sim, &hca_cmd2, 1, &valid_auth);

    println!("Response for 33 bytes: {:?}", resp2);
    // The test SHOULD enforce that it fails
    assert!(resp2.is_err(), "33 byte auth MUST fail with TPM_RC_SIZE");
}
