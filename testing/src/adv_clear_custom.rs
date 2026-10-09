#![allow(unused_imports, dead_code)]
use tpm2::Handle;
use tpm2::Unmarshal;
use tpm2::commands::{
    Clear, ClearControl, ClearControlHandles, ClearHandles, CreatePrimary, CreatePrimaryHandles,
    FlushContext,
};
use tpm2::errors::TpmRc;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn clear_disabled() {
    let mut sim = create_simulator!();

    let disable_cmd = ClearControl { disable: true };
    let disable_handles = ClearControlHandles {
        auth: Handle::RH_LOCKOUT,
    };
    sim.execute_with_handles(disable_cmd, disable_handles)
        .expect("ClearControl failed");

    let cmd = Clear {};
    let cmd_handles = ClearHandles {
        auth_handle: Handle::RH_LOCKOUT,
    };

    let err = sim.execute_with_handles(cmd, cmd_handles).unwrap_err();
    assert_eq!(err.get(), TpmRc::DISABLED.get());

    let reenable_cmd = ClearControl { disable: false };
    let reenable_handles = ClearControlHandles {
        auth: Handle::RH_LOCKOUT,
    };
    let err2 = sim
        .execute_with_handles(reenable_cmd, reenable_handles)
        .unwrap_err();
    assert_eq!(err2.get(), TpmRc::AUTH_FAIL.get());
}
