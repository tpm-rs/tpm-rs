//! TPM2_Duplicate: object/new-parent requirements, encryptedDuplication, inner wrapper keys and
//! outer wrapper hashing.

use crate::_common::{
    AES128_CFB, command_rc, create_and_load, create_dup_target, create_srk, create_storage_primary,
    create_unwrap, dup_policy, duplicable_sign_template, duplicate, duplicate_alg,
    duplicate_command, duplicate_command_with_name_alg, evict_control, flush_context, import, load,
    load_with_name, owner_srk, rc_p, read_public, rewrap, rsa_dup_target,
    rsa_storage_template_with, storage_attrs, try_create_owner_primary, try_create_primary_in,
};
use testing::tpm::Tpm;
use tpm2::commands::{Duplicate, Import};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bPrivate,
    TpmaObject, TpmiAlgHash, TpmtKeyedHashScheme, TpmtPublic,
};

/// Duplicate of an encryptedDuplication object fails without an inner wrapper and with newParentHandle = TPM_RH_NULL.
///
/// `TPM2_Duplicate` of an `encryptedDuplication` object fails without an
/// inner wrapper and with `newParentHandle = TPM_RH_NULL`.
#[test]
fn encrypted_duplication_requires_wrappers() {
    let mut sim = Tpm::new();

    // 1. A parent storage key
    let parent = create_srk(&mut sim);

    // 2. A target signing key with the ENCRYPTED_DUPLICATION attribute
    let target = create_unwrap(
        &mut sim,
        parent,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::ENCRYPTED_DUPLICATION),
        &[],
    );
    let (target_handle, _) =
        load_with_name(&mut sim, parent, target.out_private, target.out_public).unwrap();

    // 3. Call Duplicate with Null symmetricAlg -> should fail
    let res = duplicate_command_with_name_alg(
        &mut sim,
        target_handle,
        parent,
        &Duplicate {
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
            // The handles are filled in by the helper.
            ..Default::default()
        },
        TpmiAlgHash::Sha256,
    );
    assert!(
        res.is_err(),
        "Expected Duplicate command to fail because ENCRYPTED_DUPLICATION is set but symmetricAlg is Null"
    );

    // 4. Call Duplicate with newParentHandle = TPM_RH_NULL and a non-null symmetricAlg -> fail
    let res_null_parent = duplicate_command_with_name_alg(
        &mut sim,
        target_handle,
        Handle::RH_NULL,
        &Duplicate {
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: Some(AES128_CFB),
            // The handles are filled in by the helper.
            ..Default::default()
        },
        TpmiAlgHash::Sha256,
    );
    assert!(
        res_null_parent.is_err(),
        "Expected Duplicate command to fail because ENCRYPTED_DUPLICATION is set but newParentHandle is RHNull"
    );
}

/// Duplicate of a fixedParent object fails with TPM_RC_ATTRIBUTES on the object handle.
///
/// `TPM2_Duplicate` of a `fixedParent` object fails with `TPM_RC_ATTRIBUTES`
/// on the object handle.
#[test]
fn fixed_parent_object_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent storage key
    let parent = create_srk(&mut sim);

    // 2. A target signing key with the FIXED_PARENT attribute (a fixedParent child of a fixedTPM
    //    parent must also be fixedTPM)
    let target = create_unwrap(
        &mut sim,
        parent,
        rsa_dup_target(
            TpmiAlgHash::Sha256,
            TpmaObject::FIXED_PARENT | TpmaObject::FIXED_TPM,
        ),
        &[],
    );
    let (target_handle, _) =
        load_with_name(&mut sim, parent, target.out_private, target.out_public).unwrap();

    // 3. Call Duplicate on fixedParent key -> should fail with Attributes
    let res = duplicate_command_with_name_alg(
        &mut sim,
        target_handle,
        parent,
        &Duplicate {
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
            // The handles are filled in by the helper.
            ..Default::default()
        },
        TpmiAlgHash::Sha256,
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );
}

/// Duplicate of a keyedHash (HMAC) key succeeds.
///
/// `TPM2_Duplicate` of a keyedHash (HMAC) key succeeds.
#[test]
fn keyed_hash_key_duplicates() {
    let mut sim = Tpm::new();

    // 1. A parent storage key
    let parent = create_srk(&mut sim);

    // 2. A target keyedhash key
    let target = create_unwrap(
        &mut sim,
        parent,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::from_bytes(dup_policy(TpmiAlgHash::Sha256)).unwrap(),
            parms_and_id: PublicParmsAndId::KeyedHash(
                Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
                Tpm2bDigest::default(),
            ),
        },
        b"hello, unseal",
    );
    let (target_handle, _) =
        load_with_name(&mut sim, parent, target.out_private, target.out_public).unwrap();

    // 3. Execute Duplicate on target under parent
    let dup_resp = duplicate_command_with_name_alg(
        &mut sim,
        target_handle,
        parent,
        &Duplicate {
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
            // The handles are filled in by the helper.
            ..Default::default()
        },
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    assert!(dup_resp.duplicate.get_size() > 0);
}

/// Duplicate outer wrapper uses the new parent nameAlg (verified via Rewrap/Import); inner wrapper key required for non-NULL symmetricAlg.
#[test]
fn outer_wrapper_uses_new_parent_name_alg() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let parent = try_create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        rsa_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    )
    .unwrap()
    .0;
    // A SHA-384 object duplicated to a SHA-256 parent: the outer wrapper must use the parent's
    // nameAlg, which TPM2_Rewrap (an independent implementation of UnwrapOuter) verifies.
    let (obj, obj_rsp) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha384),
        &[],
        &[],
    );
    let name = read_public(&mut sim, obj).unwrap().name;
    let dup = duplicate_alg(&mut sim, obj, parent, None, TpmiAlgHash::Sha384).unwrap();
    // Free the slots of the source object and its parent for the Load below.
    flush_context(&mut sim, obj).unwrap();
    flush_context(&mut sim, srk).unwrap();
    let plain = rewrap(
        &mut sim,
        parent,
        Handle::RH_NULL,
        dup.duplicate,
        name,
        dup.out_sym_seed,
    )
    .expect("outer wrapper must use the new parent's nameAlg");

    // Import with an outer wrapper produced by Rewrap (parent nameAlg) works as well.
    let wrapped = rewrap(
        &mut sim,
        Handle::RH_NULL,
        parent,
        plain.out_duplicate,
        name,
        Tpm2bEncryptedSecret::default(),
    )
    .unwrap();
    let private = import(
        &mut sim,
        parent,
        obj_rsp.out_public,
        wrapped.out_duplicate,
        wrapped.out_sym_seed,
    )
    .expect("Import must verify the outer wrapper with the parent's nameAlg");
    load(&mut sim, parent, private, obj_rsp.out_public).unwrap();

    // An inner wrapper key is required whenever symmetricAlg is not NULL.
    let cmd = Import {
        parent_handle: parent,
        encryption_key: Tpm2bData::default(),
        object_public: obj_rsp.out_public,
        duplicate: Tpm2bPrivate::from_bytes(&[0, 2, 0, 0]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: Some(AES128_CFB),
    };
    assert_eq!(command_rc(&mut sim, &cmd, 1), rc_p(TpmRc::SIZE, 1));
}

/// Duplicate works for a persistent object (NULL new parent) and to a persistent new parent; the
/// result imports and loads. A persistent parent occupies an object slot for the duration of the
/// command, so the Load needs a free slot for it besides the one for the new object.
#[test]
fn persistent_object_and_persistent_new_parent() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let (obj, obj_rsp) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha256),
        &[],
        &[],
    );
    evict_control(&mut sim, Handle::RH_OWNER, obj, Handle(0x8100_0200)).unwrap();
    evict_control(&mut sim, Handle::RH_OWNER, srk, Handle(0x8100_0201)).unwrap();

    // Persistent object, NULL new parent.
    duplicate(&mut sim, Handle(0x8100_0200), Handle::RH_NULL, None).expect("Duplicate(persistent)");
    // Transient object, persistent new parent; the result imports under that parent.
    let dup = duplicate(&mut sim, obj, Handle(0x8100_0201), None).expect("Duplicate(new parent)");
    let private = import(
        &mut sim,
        Handle(0x8100_0201),
        obj_rsp.out_public,
        dup.duplicate,
        dup.out_sym_seed,
    )
    .expect("Import");
    // SRK + object + the persistent parent fill all three slots: no room for the new object.
    assert_eq!(
        load(&mut sim, Handle(0x8100_0201), private, obj_rsp.out_public),
        Err(TpmRc::OBJECT_MEMORY.get())
    );
    flush_context(&mut sim, obj).unwrap();
    load(&mut sim, Handle(0x8100_0201), private, obj_rsp.out_public).expect("Load");
}

/// Duplicate (no inner wrapper) of an RSA signing key to a SHA-1 named RSA storage parent succeeds.
///
/// `TPM2_Duplicate` (no inner wrapper) of an RSA signing key to a SHA-1 named
/// RSA storage parent succeeds.
#[test]
fn rsa_key_to_sha1_storage_parent() {
    let mut sim = Tpm::new();

    let parent = create_storage_primary(&mut sim, TpmiAlgHash::Sha1);
    let (target, _) = create_dup_target(&mut sim, parent);

    let res = duplicate_command(
        &mut sim,
        target,
        parent,
        &Duplicate {
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
            // The handles are filled in by the helper.
            ..Default::default()
        },
    );
    assert!(res.is_ok(), "Duplicate failed: {:?}", res.err());
}

/// Duplicate to a non-asymmetric (symmetric storage) new parent fails with TPM_RC_TYPE.
///
/// `TPM2_Duplicate` to a new parent that is not an asymmetric storage key fails
/// with `TPM_RC_TYPE` on `newParentHandle`.
///
/// The white-box original injected a restricted decryption keyedHash object with a NULL
/// scheme, which `TPM2_CreatePrimary` rejects (`TPM_RC_SCHEME`); a symmetric storage key is
/// used as the non-asymmetric parent instead.
#[test]
fn symmetric_new_parent_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent key that is NOT asymmetric (symmetric storage key)
    let (parent, _) = try_create_owner_primary(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: storage_attrs(),
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
        },
    )
    .expect("CreatePrimary(symmetric parent) failed");

    // 2. A target key
    let srk = create_srk(&mut sim);
    let target = create_unwrap(
        &mut sim,
        srk,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    );
    let (target_handle, _) =
        load_with_name(&mut sim, srk, target.out_private, target.out_public).unwrap();

    // 3. Call Duplicate with invalid parent type -> should fail with Type
    let res = duplicate_command_with_name_alg(
        &mut sim,
        target_handle,
        parent,
        &Duplicate {
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
            // The handles are filled in by the helper.
            ..Default::default()
        },
        TpmiAlgHash::Sha256,
    );
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(2)).get()));
}

/// Duplicate with a wrongly sized inner wrapper key fails with TPM_RC_SIZE on encryptionKeyIn.
///
/// `TPM2_Duplicate` with an inner wrapper key of the wrong size fails with
/// `TPM_RC_SIZE` on `encryptionKeyIn`.
#[test]
fn wrong_inner_key_size_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent storage key
    let parent = create_srk(&mut sim);

    // 2. A target signing key
    let target = create_unwrap(
        &mut sim,
        parent,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    );
    let (target_handle, _) =
        load_with_name(&mut sim, parent, target.out_private, target.out_public).unwrap();

    // 3. Call Duplicate with an 8-byte encryption key instead of 16 for AES-128
    let res = duplicate_command_with_name_alg(
        &mut sim,
        target_handle,
        parent,
        &Duplicate {
            encryption_key_in: Tpm2bData::from_bytes(&[0u8; 8]).unwrap(),
            symmetric_alg: Some(AES128_CFB),
            // The handles are filled in by the helper.
            ..Default::default()
        },
        TpmiAlgHash::Sha256,
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
}
