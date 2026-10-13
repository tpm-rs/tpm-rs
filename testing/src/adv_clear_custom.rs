#![allow(unused_imports, dead_code)]
use tpm2::Handle;
use tpm2::Unmarshal;
use tpm2::commands::{Clear, ClearControl, CreatePrimary, FlushContext};
use tpm2::errors::TpmRc;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn clear_disabled() {
    let mut sim = create_simulator!();

    let disable_cmd = ClearControl {
        auth: Handle::RH_LOCKOUT,
        disable: true,
    };
    sim.execute(disable_cmd).expect("ClearControl failed");

    let cmd = Clear {
        auth_handle: Handle::RH_LOCKOUT,
    };

    let err = sim.execute(cmd).unwrap_err();
    assert_eq!(err.get(), TpmRc::DISABLED.get());

    let reenable_cmd = ClearControl {
        auth: Handle::RH_LOCKOUT,
        disable: false,
    };
    let err2 = sim.execute(reenable_cmd).unwrap_err();
    assert_eq!(err2.get(), TpmRc::AUTH_FAIL.get());
}
