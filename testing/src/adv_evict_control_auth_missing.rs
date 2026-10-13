#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::EvictControl;
use tpm2::errors::TpmRc;
use tpm2_simulator::create_simulator;

#[test]
#[allow(deprecated)]
fn test_evict_control_auth_missing() {
    let mut sim = create_simulator!();

    // objectHandle must be a loaded object: C rejects RH_NULL at handle
    // unmarshal (VALUE+H2) and an unloaded transient with REFERENCE_H1, both
    // before the AUTH_MISSING check (ExecuteCommand.c / SessionProcess.c:1650).
    let (in_sensitive, in_public) = create_test_keys();
    let created = execute_with_password_sessions(
        &mut sim,
        &tpm2::commands::CreateLoaded {
            parent_handle: Handle::RH_OWNER,
            in_sensitive,
            in_public,
        },
        1,
        &[],
    )
    .unwrap();
    let cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: created.object_handle,
        persistent_handle: Handle(0x81000000),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err,
        TpmRc::AUTH_MISSING.get(),
        "Expected AuthMissing, got {:x?}",
        err
    );
}
