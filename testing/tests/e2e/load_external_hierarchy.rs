//! TPM2_LoadExternal hierarchy handling: disabled hierarchies and invalid hierarchy values.

use crate::_common::{ECC_D, ECC_X, ECC_Y, make_ecc_public_area, set_hierarchy_enabled};
use testing::tpm::Tpm;
use tpm2::commands::LoadExternal;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, TpmaObject, TpmtSensitive,
    TpmuSensitiveComposite,
};

/// LoadExternal into the endorsement hierarchy fails with TPM_RC_HIERARCHY when ehEnable is clear.
#[test]
fn endorsement_hierarchy_disabled_rejected() {
    let mut sim = Tpm::new();
    set_hierarchy_enabled(&mut sim, Handle::RH_ENDORSEMENT, false);

    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_ENDORSEMENT,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::HIERARCHY.with(Position::parameter(3));
    assert_eq!(err.get(), expected.get());
}

/// An invalid hierarchy handle value is rejected.
#[test]
fn invalid_hierarchy_handle_rejected() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle(0x80000000), // completely invalid handle
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// LoadExternal into the owner hierarchy fails with TPM_RC_HIERARCHY when shEnable is clear.
#[test]
fn owner_hierarchy_disabled_rejected() {
    let mut sim = Tpm::new();
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);

    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_OWNER,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::HIERARCHY.with(Position::parameter(3));
    assert_eq!(err.get(), expected.get());
}

/// Loading a key with a sensitive area into a hierarchy other than TPM_RH_NULL fails.
#[test]
fn sensitive_outside_null_hierarchy_rejected() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_OWNER,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}
