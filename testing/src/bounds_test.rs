use crate::test_utils::*;
use tpm2::Handle;
use tpm2::Tpm2bAuth;
use tpm2::commands::{HierarchyChangeAuth, HierarchyChangeAuthHandles};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_hierarchy_change_auth_bounds() {
    let mut sim = create_simulator!();

    // CONTEXT_INTEGRITY_HASH_SIZE in most TPMs is SHA256 (32 bytes).
    // Let's see if 40 bytes is accepted.
    let oversized_auth = vec![1u8; 40];

    let hca_cmd = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(&oversized_auth).unwrap(),
    };
    let hca_handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, hca_handles, 1, &[]);
    println!("Resp for 40 bytes auth: {:?}", resp);

    let max_auth = vec![2u8; 64];
    let hca_cmd2 = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(&max_auth).unwrap(),
    };
    let hca_handles2 = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_PLATFORM,
    };

    let resp2 = execute_with_password_sessions(&mut sim, &hca_cmd2, hca_handles2, 1, &[]);
    println!("Resp for 64 bytes auth: {:?}", resp2);
}
