#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::EvictControl;
use tpm2::commands::EvictControlHandles;
use tpm2::errors::TpmRc;
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_evict_control_auth_missing() {
    let mut sim = create_simulator!();

    let handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: Handle::RH_NULL, // doesn't matter
    };
    let cmd = EvictControl {
        persistent_handle: Handle(0x81000000),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err,
        TpmRc::AUTH_MISSING.get(),
        "Expected AuthMissing, got {:x?}",
        err
    );
}
