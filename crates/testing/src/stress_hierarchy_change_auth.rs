use crate::test_utils::*;
use tpm2::Handle;
use tpm2::Tpm2bAuth;
use tpm2::commands::{HierarchyChangeAuth, HierarchyChangeAuthHandles};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

#[test]
fn stress_test_auth_size() {
    let mut sim = create_simulator!();

    // Change owner auth
    let new_auth = b"newownerauth";
    let hca_cmd = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(new_auth).unwrap(),
    };
    let hca_handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let resp = execute_with_password_sessions(&mut sim, &hca_cmd, hca_handles.clone(), 1, &[]);
    assert!(resp.is_ok());

    // Power cycle
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.global_state.initialized = false;
    sim.power_on_start_up();

    // Check if new owner auth is still valid!
    let hca_cmd2 = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"another").unwrap(),
    };
    let resp2 = execute_with_password_sessions(&mut sim, &hca_cmd2, hca_handles, 1, new_auth);
    assert!(
        resp2.is_ok(),
        "Owner auth was not saved across power cycle! State is LOST!"
    );
}
