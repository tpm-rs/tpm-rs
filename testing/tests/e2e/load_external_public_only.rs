//! TPM2_LoadExternal of public-only keys into the different hierarchies.
#![allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream, but the TPM implements it.

use crate::_common::{
    AES128_CFB, ECC_X, ECC_Y, RSA_N, command_rc, create, ecc_sign_template,
    external_storage_public, flush_context, load_external, make_ecc_public_area,
    make_rsa_public_area_opt_name_alg, make_template, rc0, read_public, sealed_template,
    sensitive_create, try_create_primary_in,
};
use testing::tpm::Tpm;
use tpm2::commands::{LoadExternal, *};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bDigest, Tpm2bEccParameter, TpmEccCurve, TpmaObject, TpmiAlgHash,
    TpmsEccParms, TpmsEccPoint, TpmtPublic,
};

/// Loads a public-only ECC key into the endorsement hierarchy.
#[test]
fn ecc_public_only_endorsement_hierarchy() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_ENDORSEMENT,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a public-only ECC key into the owner hierarchy.
#[test]
fn ecc_public_only_owner_hierarchy() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_OWNER,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a public-only ECC key into the platform hierarchy.
#[test]
fn ecc_public_only_platform_hierarchy() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_PLATFORM,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a public-only ECC key with SHA-384 nameAlg into the platform hierarchy.
#[test]
fn ecc_sha384_name_alg_platform_hierarchy() {
    let mut sim = Tpm::new();
    let pub_struct = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha384),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(ECC_X).unwrap(),
                y: Tpm2bEccParameter::from_bytes(ECC_Y).unwrap(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_PLATFORM,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// An externally loaded copy of a primary public area (QN == Name) is neither flushed nor modified when the primary is re-created.
#[test]
fn external_alias_survives_primary_recreation() {
    let mut sim = Tpm::new();
    let template = ecc_sign_template(
        TpmiAlgHash::Sha256,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    );
    let (p, rsp) = try_create_primary_in(&mut sim, Handle::RH_OWNER, template, &[]).unwrap();
    flush_context(&mut sim, p).unwrap();

    // Load the same public area externally: same Name, but QN == Name.
    let ext = load_external(&mut sim, rsp.out_public.0, None, Handle::RH_OWNER).unwrap();
    let ext_qn = read_public(&mut sim, ext).unwrap().qualified_name;

    // Re-creating the primary must neither flush nor modify the external object.
    let (p2, rsp2) = try_create_primary_in(&mut sim, Handle::RH_OWNER, template, &[]).unwrap();
    assert_eq!(rsp2.name.get_buffer(), rsp.name.get_buffer());
    let after = read_public(&mut sim, ext).expect("external object was flushed");
    assert_eq!(after.qualified_name.get_buffer(), ext_qn.get_buffer());
    assert!(read_public(&mut sim, p2).is_ok());
}

/// External objects (public-only restricted storage keys) cannot act as parents: bare AUTH_UNAVAILABLE.
#[test]
fn external_storage_key_rejected_as_parent() {
    let mut sim = Tpm::new();
    let ext = load_external(&mut sim, external_storage_public(), None, Handle::RH_OWNER).unwrap();
    for rc in [
        create(
            &mut sim,
            ext,
            sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
            &[],
            b"x",
        )
        .unwrap_err(),
        command_rc(
            &mut sim,
            &CreateLoaded {
                parent_handle: ext,
                in_sensitive: sensitive_create(&[], b"x"),
                in_public: make_template(&sealed_template(
                    TpmiAlgHash::Sha256,
                    TpmaObject::empty(),
                )),
            },
            1,
        ),
    ] {
        // An external object can only be a (restricted) parent candidate if it is public-only,
        // and C rejects those during authorization with a bare AUTH_UNAVAILABLE.
        assert_eq!(
            rc,
            rc0(TpmRc::AUTH_UNAVAILABLE),
            "external object accepted as a parent: {rc:#x}"
        );
    }
}

/// A public-only external object as Create parent fails with bare AUTH_UNAVAILABLE during authorization.
#[test]
fn public_only_object_has_no_auth_and_is_not_parent() {
    let mut sim = Tpm::new();
    let ext = load_external(&mut sim, external_storage_public(), None, Handle::RH_OWNER).unwrap();
    // A public-only object has no authValue (C: TPM_RC_AUTH_UNAVAILABLE during authorization)
    // and is never a parent (TPM_RC_TYPE + RC_H1 in the action code).
    let rc = create(
        &mut sim,
        ext,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"x",
    )
    .unwrap_err();
    // C: IsAuthValueAvailable is FALSE for public-only objects -> bare AUTH_UNAVAILABLE
    // before the action code (whose TYPE+H1 is defense in depth).
    assert_eq!(
        rc,
        rc0(TpmRc::AUTH_UNAVAILABLE),
        "public-only parent accepted: {rc:#x}"
    );
}

/// Loads a public-only RSA key into the endorsement hierarchy.
#[test]
fn rsa_public_only_endorsement_hierarchy() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_ENDORSEMENT,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a public-only RSA key into the owner hierarchy.
#[test]
fn rsa_public_only_owner_hierarchy() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_OWNER,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a public-only RSA key into the platform hierarchy.
#[test]
fn rsa_public_only_platform_hierarchy() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_PLATFORM,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a public-only RSA key whose nameAlg is SHA-384.
#[test]
fn rsa_public_only_sha384_name_alg() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha384),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a public-only symmetric key object.
#[test]
fn symcipher_public_only() {
    let mut sim = Tpm::new();

    let sym_unique = [0x01; 32];
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            AES128_CFB,
            Tpm2bDigest::from_bytes(&sym_unique).unwrap(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Unseal of a public-only KEYEDHASH external object fails with AUTH_UNAVAILABLE.
#[test]
fn unseal_public_only_keyedhash_auth_unavailable() {
    let mut sim = Tpm::new();
    let mut public = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    public.parms_and_id =
        PublicParmsAndId::KeyedHash(None, Tpm2bDigest::from_bytes(&[3u8; 32]).unwrap());
    let ext = load_external(&mut sim, public, None, Handle::RH_OWNER).unwrap();
    let rc = command_rc(&mut sim, &Unseal { item_handle: ext }, 1);
    assert_eq!(rc, rc0(TpmRc::AUTH_UNAVAILABLE));
}
