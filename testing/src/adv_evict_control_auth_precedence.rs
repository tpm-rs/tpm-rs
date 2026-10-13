#![forbid(unsafe_code)]

use crate::test_utils::*;
use tpm2::commands::*;
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_simulator::*;

#[test]
#[allow(deprecated)]
fn test_evict_control_auth_precedence() {
    let mut sim = create_simulator!();

    // objectHandle must be a loaded object: C rejects RH_OWNER at handle
    // unmarshal (VALUE+H2) before the AUTH_MISSING check.
    let (in_sensitive, in_public) = create_test_keys();
    let created = execute_with_password_sessions(
        &mut sim,
        &CreateLoaded {
            parent_handle: Handle::RH_OWNER,
            in_sensitive,
            in_public,
        },
        1,
        &[],
    )
    .unwrap();

    let evict_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: created.object_handle,
        persistent_handle: Handle::RH_PLATFORM, // 0x4000000C Invalid
    };

    let res = execute_with_password_sessions(&mut sim, &evict_cmd, 0, &[]);

    let rc = res.unwrap_err();
    println!("Return Code: 0x{:04X}", rc);
    assert_eq!(
        rc,
        TpmRc::AUTH_MISSING.get(),
        "Expected AuthMissing ({:04X}), got 0x{:04X}",
        TpmRc::AUTH_MISSING.get(),
        rc
    );
}
