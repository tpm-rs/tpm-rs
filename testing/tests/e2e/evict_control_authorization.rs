//! TPM2_EvictControl authorization: required sessions and which hierarchy may persist or evict
//! which objects.

#![allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream but still implemented.

use crate::_common::{create_test_keys, execute_with_password_sessions, get_ecc_srk_template};
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, EvictControl, *};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, *};

/// TPM2_EvictControl without sessions on a loaded object fails with TPM_RC_AUTH_MISSING (handle unmarshal checked first)
#[test]
fn evict_control_auth_missing_after_handle_checks() {
    let mut sim = Tpm::new();

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

/// EvictControl without an authorization session fails with TPM_RC_AUTH_MISSING.
#[test]
fn missing_authorization_rejected() {
    let mut sim = Tpm::new();

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

/// Owner auth cannot evict a platform persistent object (HIERARCHY).
#[test]
fn owner_cannot_evict_platform_persistent_object() {
    let mut sim = Tpm::new();

    // CreatePrimary in Platform hierarchy
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_PLATFORM,
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // Make persistent at Platform range
    let persistent_handle = Handle(0x81800000);
    let evict_cmd = EvictControl {
        auth: Handle::RH_PLATFORM,
        object_handle: rsp_handles.object_handle,
        persistent_handle,
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]).unwrap();

    // Owner tries to evict it
    let evict_cmd2 = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: persistent_handle,
        persistent_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &evict_cmd2, 1, &[]);

    let expected = TpmRc::HIERARCHY.with(Position::handle(2)).get();
    match res {
        Err(e) if e == expected => { /* Success! It matched tpm-c */ }
        Err(e) => panic!(
            "Expected hierarchy_for (0x{:x}), but got 0x{:x}",
            expected, e
        ),
        Ok(_) => panic!("Expected error but succeeded"),
    }
}

/// Platform auth can evict an owner persistent object.
#[test]
fn platform_can_evict_owner_object() {
    let mut sim = Tpm::new();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let rsp_owner = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let owner_transient_handle = rsp_owner.object_handle;

    let persistent_handle = Handle(0x81000000);
    let make_pers_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: owner_transient_handle,
        persistent_handle,
    };
    execute_with_password_sessions(&mut sim, &make_pers_cmd, 1, &[]).unwrap();

    let evict_cmd = EvictControl {
        auth: Handle::RH_PLATFORM,
        object_handle: persistent_handle,
        persistent_handle,
    };
    let evict_res = execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]);
    assert!(
        evict_res.is_ok(),
        "Platform failed to evict owner persistent object! Error code: {:?}",
        evict_res.err()
    );
}

/// Platform auth cannot persist an endorsement-hierarchy object; owner auth can persist an owner object.
#[test]
fn platform_cannot_persist_endorsement_object() {
    let mut sim = Tpm::new();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    // 1. CreatePrimary in Endorsement hierarchy
    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let rsp_handles_ek = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // 2. Platform Auth should NOT be able to make Endorsement object persistent.
    // The current Rust implementation will ALLOW this!
    let evict_cmd = EvictControl {
        auth: Handle::RH_PLATFORM,
        object_handle: rsp_handles_ek.object_handle,
        persistent_handle: Handle(0x81800001),
    };
    let res = execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]);
    // It should be Err, but it's probably Ok right now due to the bug!
    println!("{:?}", res);
    assert!(
        res.is_err(),
        "Platform auth should NOT be able to persist Endorsement objects (bug 1)"
    );

    // 3. CreatePrimary in Owner hierarchy
    let create_cmd_owner = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let rsp_handles_owner =
        execute_with_password_sessions(&mut sim, &create_cmd_owner, 1, &[]).unwrap();

    // 4. Owner Auth makes it persistent
    let evict_owner_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: rsp_handles_owner.object_handle,
        persistent_handle: Handle(0x81000001),
    };
    execute_with_password_sessions(&mut sim, &evict_owner_cmd, 1, &[]).unwrap();

    // 5. Platform Auth should BE ABLE to evict an Owner hierarchy persistent object!
    // The current Rust implementation will FAIL this!
    let evict_plat_cmd = EvictControl {
        auth: Handle::RH_PLATFORM,
        object_handle: Handle(0x81000001),
        persistent_handle: Handle(0x81000001),
    };
    let res2 = execute_with_password_sessions(&mut sim, &evict_plat_cmd, 1, &[]);
    assert!(
        res2.is_ok(),
        "Platform auth should be able to evict Owner persistent objects (bug 2)"
    );
}

/// Platform auth cannot persist an endorsement-hierarchy object (HIERARCHY).
#[test]
fn platform_cannot_persist_endorsement_primary() {
    let mut sim = Tpm::new();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    // Create a transient object in Endorsement hierarchy
    let rsp_end = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let end_transient_handle = rsp_end.object_handle;

    // Try to persist with Platform auth
    let cmd = EvictControl {
        auth: Handle::RH_PLATFORM,
        object_handle: end_transient_handle,
        persistent_handle: Handle(0x81800005),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);

    assert!(
        res.is_err(),
        "Platform auth should not be able to persist an Endorsement object!"
    );
    let err = res.unwrap_err();
    assert_eq!(
        err,
        TpmRc::HIERARCHY.with(Position::handle(2)).get(),
        "Should return TPM_RC_HIERARCHY"
    );
}
