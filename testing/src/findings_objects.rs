//! End-to-end regression tests for the `objects` findings in command-handlers.toml.
//!
//! Owned by the `fix-objects` worker; add submodules under `findings_objects/` if this grows.
//!
//! Every test is named after the finding it covers, drives the simulator strictly through its
//! command interface, and fails on the code before the corresponding fix.

#![allow(unused_imports)]

mod crypto_blobs;
mod helpers;

use helpers::*;

// ---------------------------------------------------------------------------------------------
// Sequence-object handles
// ---------------------------------------------------------------------------------------------

// tpm2-readpublic-returns-tpm-rc-reference-h0
#[test]
fn tpm2_readpublic_returns_tpm_rc_reference_h0() {
    let mut sim = create_simulator!();
    let seq = hash_sequence_start(&mut sim);
    // C ReadPublic.c: a sequence object has no public area.
    assert_eq!(
        read_public(&mut sim, seq).unwrap_err(),
        rc0(TpmRc::SEQUENCE)
    );
}

// read-public-and-object-handlers-sequence-handle-error-discrepancies
#[test]
fn read_public_and_object_handlers_sequence_handle_error_discrepancies() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let seq = hash_sequence_start(&mut sim);

    // ReadPublic: sequence -> TPM_RC_SEQUENCE, TPM_RH_NULL -> VALUE + RC_H1.
    assert_eq!(
        read_public(&mut sim, seq).unwrap_err(),
        rc0(TpmRc::SEQUENCE)
    );
    assert_eq!(
        read_public(&mut sim, Handle::RH_NULL).unwrap_err(),
        rc_h(TpmRc::VALUE, 1)
    );

    // Unseal: a sequence object is not a KEYEDHASH object.
    let rc = rc_of(&mut sim, &Unseal {}, UnsealHandles { item_handle: seq }, 1);
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));

    // MakeCredential: a sequence object is not an asymmetric key.
    let rc = rc_of(
        &mut sim,
        &MakeCredential {
            credential: Tpm2bDigest::from_bytes(&[1; 16]).unwrap(),
            object_name: Tpm2bName::from_bytes(&[0, 0x0b, 1, 2, 3]).unwrap(),
        },
        MakeCredentialHandles { handle: seq },
        0,
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));

    // ActivateCredential: keyHandle is a sequence object.
    let rc = rc_of(
        &mut sim,
        &ActivateCredential {
            credential_blob: Tpm2bIdObject::default(),
            secret: Tpm2bEncryptedSecret::default(),
        },
        ActivateCredentialHandles {
            activate_handle: srk,
            key_handle: seq,
        },
        2,
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 2));

    // Create / Load: a sequence object is never a parent.
    let rc = create(
        &mut sim,
        seq,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));
}

// sequence-object-handle-validation-and-error-code-discrepancies
#[test]
fn sequence_object_handle_validation_and_error_code_discrepancies() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let seq = hash_sequence_start(&mut sim);

    // EvictControl: sequence objects are temporary -> ATTRIBUTES + RC_H2.
    assert_eq!(
        evict_control(&mut sim, Handle::RH_OWNER, seq, Handle(0x8100_0100)).unwrap_err(),
        rc_h(TpmRc::ATTRIBUTES, 2)
    );

    // ObjectChangeAuth on a sequence object -> TYPE + RC_H1.
    let rc = rc_of(
        &mut sim,
        &ObjectChangeAuth {
            new_auth: Tpm2bAuth::default(),
        },
        ObjectChangeAuthHandles {
            object_handle: seq,
            parent_handle: srk,
        },
        1,
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));

    // CreateLoaded with a sequence parent -> TYPE + RC_H1 (not REFERENCE_H0).
    let rc = rc_of(
        &mut sim,
        &CreateLoaded {
            in_sensitive: sensitive_create(&[], &[]),
            in_public: make_template(&ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty())),
        },
        CreateLoadedHandles { parent_handle: seq },
        1,
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));
}

// sequence-object-handle-resolution-and-evictcontrol-external-object-bugs
#[test]
fn sequence_object_handle_resolution_and_evictcontrol_external_object_bugs() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let seq = hash_sequence_start(&mut sim);

    assert_eq!(
        read_public(&mut sim, seq).unwrap_err(),
        rc0(TpmRc::SEQUENCE)
    );
    assert_eq!(
        evict_control(&mut sim, Handle::RH_OWNER, seq, Handle(0x8100_0101)).unwrap_err(),
        rc_h(TpmRc::ATTRIBUTES, 2)
    );
    // Load with a sequence parent.
    let child = create(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"x",
    )
    .unwrap();
    assert_eq!(
        load(&mut sim, seq, child.out_private, child.out_public).unwrap_err(),
        rc_h(TpmRc::TYPE, 1)
    );

    // EvictControl must check NV availability before it mutates NV.
    let (obj, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(
            TpmiAlgHash::Sha256,
            TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
        ),
        &[],
        &[],
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        evict_control(&mut sim, Handle::RH_OWNER, obj, Handle(0x8100_0102)).unwrap_err(),
        rc0(TpmRc::NV_UNAVAILABLE)
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    assert!(
        read_public(&mut sim, Handle(0x8100_0102)).is_err(),
        "the object must not have been persisted"
    );
}

// tpm2-evictcontrol-handle-error-codes-and-validation-order
#[test]
fn tpm2_evictcontrol_handle_error_codes_and_validation_order() {
    let mut sim = create_simulator!();
    // A platform persistent object.
    let (primary, _) =
        create_primary(&mut sim, Handle::RH_PLATFORM, fixed_rsa_storage(), &[]).unwrap();
    evict_control(&mut sim, Handle::RH_PLATFORM, primary, Handle(0x8180_0000)).unwrap();

    // Owner evicting a platform object with a mismatching persistentHandle: C checks
    // persistentHandle != objectHandle (HANDLE + RC_H2) before the hierarchy (HIERARCHY + RC_H2).
    assert_eq!(
        evict_control(
            &mut sim,
            Handle::RH_OWNER,
            Handle(0x8180_0000),
            Handle(0x8180_0001)
        )
        .unwrap_err(),
        rc_h(TpmRc::HANDLE, 2)
    );
    // With matching handles the owner is refused for the platform object.
    assert_eq!(
        evict_control(
            &mut sim,
            Handle::RH_OWNER,
            Handle(0x8180_0000),
            Handle(0x8180_0000)
        )
        .unwrap_err(),
        rc_h(TpmRc::HIERARCHY, 2)
    );

    // Sequence handle -> ATTRIBUTES + RC_H2.
    let seq = hash_sequence_start(&mut sim);
    assert_eq!(
        evict_control(&mut sim, Handle::RH_OWNER, seq, Handle(0x8100_0103)).unwrap_err(),
        rc_h(TpmRc::ATTRIBUTES, 2)
    );

    // NV unavailable: no mutation.
    let srk = owner_srk(&mut sim);
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        evict_control(&mut sim, Handle::RH_OWNER, srk, Handle(0x8100_0104)).unwrap_err(),
        rc0(TpmRc::NV_UNAVAILABLE)
    );
    assert_eq!(
        evict_control(
            &mut sim,
            Handle::RH_PLATFORM,
            Handle(0x8180_0000),
            Handle(0x8180_0000)
        )
        .unwrap_err(),
        rc0(TpmRc::NV_UNAVAILABLE)
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    assert!(read_public(&mut sim, Handle(0x8100_0104)).is_err());
    assert!(read_public(&mut sim, Handle(0x8180_0000)).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Permanent handles as TPMI_DH_OBJECT
// ---------------------------------------------------------------------------------------------

// create-permanent-handle-rejection-order-and-error-code-bugs
#[test]
fn create_permanent_handle_rejection_order_and_error_code_bugs() {
    let mut sim = create_simulator!();
    let rc = create(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, rc_h(TpmRc::VALUE, 1));
}

// tpm2-create-load-and-objectchangeauth-parent-handle-and-sensitive-error-bugs
#[test]
fn tpm2_create_load_and_objectchangeauth_parent_handle_and_sensitive_error_bugs() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let child = create(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"s",
    )
    .unwrap();

    // Permanent parent handles are invalid TPMI_DH_OBJECT values.
    assert_eq!(
        create(
            &mut sim,
            Handle::RH_OWNER,
            sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
            &[],
            b"s"
        )
        .unwrap_err(),
        rc_h(TpmRc::VALUE, 1)
    );
    assert_eq!(
        load(
            &mut sim,
            Handle::RH_OWNER,
            child.out_private,
            child.out_public
        )
        .unwrap_err(),
        rc_h(TpmRc::VALUE, 1)
    );
    let rc = rc_of(
        &mut sim,
        &ObjectChangeAuth {
            new_auth: Tpm2bAuth::from_bytes(b"new").unwrap(),
        },
        ObjectChangeAuthHandles {
            object_handle: srk,
            parent_handle: Handle::RH_OWNER,
        },
        1,
    );
    assert_eq!(rc, rc_h(TpmRc::VALUE, 2));

    // A corrupted outer integrity value is TPM_RC_INTEGRITY + RC_P1 (RC_Load_inPrivate).
    let mut blob = child.out_private.get_buffer().to_vec();
    blob[5] ^= 0xff;
    let corrupted = Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap();
    assert_eq!(
        load(&mut sim, srk, corrupted, child.out_public).unwrap_err(),
        rc_p(TpmRc::INTEGRITY, 1)
    );
}

// ---------------------------------------------------------------------------------------------
// Persistent objects in Duplicate / ObjectChangeAuth
// ---------------------------------------------------------------------------------------------

/// A duplicable ECC signing key template whose authPolicy is `PolicyCommandCode(Duplicate)`
/// (computed with `name_alg`).
fn duplicable_sign_template(name_alg: TpmiAlgHash) -> TpmtPublic<'static> {
    let mut t = ecc_sign_template(name_alg, TpmaObject::empty());
    t.auth_policy = dup_policy_digest_for(name_alg);
    t
}

// tpm2-duplicate-rejects-persistent-objects-for-both
#[test]
fn tpm2_duplicate_rejects_persistent_objects_for_both() {
    let mut sim = create_simulator!();
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
    load(&mut sim, Handle(0x8100_0201), private, obj_rsp.out_public).expect("Load");
}

// tpm2-objectchangeauth-explicitly-rejects-persistent-objects
#[test]
fn tpm2_objectchangeauth_explicitly_rejects_persistent_objects() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    // ADMIN role on a persistent object always needs a policy session (C
    // IsPolicySessionRequired), so the object's authPolicy is PolicyCommandCode(ObjectChangeAuth).
    let mut t = sealed_template(
        TpmiAlgHash::Sha256,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    );
    t.auth_policy = policy_command_code_digest(TpmiAlgHash::Sha256, TpmCc::ObjectChangeAuth);
    let (obj, obj_rsp) = create_and_load(&mut sim, srk, t, b"old", b"sealed");
    evict_control(&mut sim, Handle::RH_OWNER, obj, Handle(0x8100_0300)).unwrap();
    let sess = policy_command_code_session(&mut sim, TpmiAlgHash::Sha256, TpmCc::ObjectChangeAuth);
    let (rsp, _) = execute_with_hmac_sessions(
        &mut sim,
        &ObjectChangeAuth {
            new_auth: Tpm2bAuth::from_bytes(b"new").unwrap(),
        },
        ObjectChangeAuthHandles {
            object_handle: Handle(0x8100_0300),
            parent_handle: srk,
        },
        &[],
        &mut [sess],
        &[&[]],
    )
    .expect("ObjectChangeAuth on a persistent object");
    let new_obj = load(&mut sim, srk, rsp.out_private, obj_rsp.out_public).unwrap();
    let (unsealed, _) = execute_with_password_sessions(
        &mut sim,
        &Unseal {},
        UnsealHandles {
            item_handle: new_obj,
        },
        1,
        b"new",
    )
    .expect("Unseal with the new auth");
    assert_eq!(unsealed.out_data.get_buffer(), b"sealed");
}

// object-change-auth-validation-order-and-non-storage-parent-error-code
#[test]
fn object_change_auth_validation_order_and_non_storage_parent_error_code() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let (obj, _) = create_and_load(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"x",
    );
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    );
    let oca = |sim: &mut Simulator<'_>, parent: Handle, auth: &[u8]| {
        rc_of(
            sim,
            &ObjectChangeAuth {
                new_auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
            },
            ObjectChangeAuthHandles {
                object_handle: obj,
                parent_handle: parent,
            },
            1,
        )
    };
    // A non-storage parentHandle is blamed on handle 2.
    assert_eq!(oca(&mut sim, signer, b"new"), rc_h(TpmRc::TYPE, 2));
    // newAuth size is checked before the parent.
    assert_eq!(oca(&mut sim, signer, &[7u8; 33]), rc_p(TpmRc::SIZE, 1));
    // Correct parent works.
    assert_eq!(oca(&mut sim, srk, b"new"), 0);
}

// tpm2-objectchangeauth-handle2-error-positions-and-seedvalue-corruption
#[test]
fn tpm2_objectchangeauth_handle2_error_positions_and_seedvalue_corruption() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    // SHA-512 sealed object: the re-encrypted sensitive area must keep the 64-byte seedValue,
    // otherwise the reloaded object fails its binding check.
    let (obj, obj_rsp) = create_and_load(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha512, TpmaObject::empty()),
        &[],
        b"payload",
    );
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    );
    let run_oca = |sim: &mut Simulator<'_>, parent: Handle| {
        run(
            sim,
            &ObjectChangeAuth {
                new_auth: Tpm2bAuth::from_bytes(b"pw").unwrap(),
            },
            ObjectChangeAuthHandles {
                object_handle: obj,
                parent_handle: parent,
            },
            1,
        )
    };
    assert_eq!(run_oca(&mut sim, signer).unwrap_err(), rc_h(TpmRc::TYPE, 2));
    let (rsp, _) = run_oca(&mut sim, srk).unwrap();
    let reloaded = load(&mut sim, srk, rsp.out_private, obj_rsp.out_public).expect("Load");
    let (unsealed, _) = execute_with_password_sessions(
        &mut sim,
        &Unseal {},
        UnsealHandles {
            item_handle: reloaded,
        },
        1,
        b"pw",
    )
    .unwrap();
    assert_eq!(unsealed.out_data.get_buffer(), b"payload");
}

// ---------------------------------------------------------------------------------------------
// Parent selection
// ---------------------------------------------------------------------------------------------

// tpm2-create-tpm2-load-and-tpm2-import
#[test]
fn tpm2_create_tpm2_load_and_tpm2_import() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let (deriver, _) = create_and_load(
        &mut sim,
        srk,
        derivation_parent_template(TpmiAlgHash::Sha256, TpmaObject::SENSITIVE_DATA_ORIGIN),
        &[],
        &[],
    );
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    );
    let import_rc = |sim: &mut Simulator<'_>, parent: Handle| {
        import(
            sim,
            parent,
            Tpm2b(ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty())),
            Tpm2bPrivate::from_bytes(&[0, 2, 0, 0]).unwrap(),
            Tpm2bEncryptedSecret::default(),
        )
        .unwrap_err()
    };
    // Derivation parents and non-storage keys are not parents for Import.
    assert_eq!(import_rc(&mut sim, deriver), rc_h(TpmRc::TYPE, 1));
    assert_eq!(import_rc(&mut sim, signer), rc_h(TpmRc::TYPE, 1));
}

/// A public-only RSA-2048 storage key public area with a fake (but well-formed) modulus.
fn external_storage_public() -> TpmtPublic<'static> {
    let mut modulus = [0x5au8; 256];
    modulus[0] = 0xc1;
    let mut t = rsa_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    if let PublicParmsAndId::Rsa(_, unique) = &mut t.parms_and_id {
        *unique = Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&modulus)).unwrap();
    }
    t
}

// public-only-objects-bypass-isauthvalueavailable-isauthpolicyavailable-checks
#[test]
fn public_only_objects_bypass_isauthvalueavailable_isauthpolicyavailable_checks() {
    let mut sim = create_simulator!();
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

// loadexternal-external-objects-accepted-as-parents-with-public-name-seed
#[test]
fn loadexternal_external_objects_accepted_as_parents_with_public_name_seed() {
    let mut sim = create_simulator!();
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
        rc_of(
            &mut sim,
            &CreateLoaded {
                in_sensitive: sensitive_create(&[], b"x"),
                in_public: make_template(&sealed_template(
                    TpmiAlgHash::Sha256,
                    TpmaObject::empty(),
                )),
            },
            CreateLoadedHandles { parent_handle: ext },
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

// unseal-public-only-keyedhash-and-oversized-private-failure-mode
#[test]
fn unseal_public_only_keyedhash_and_oversized_private_failure_mode() {
    let mut sim = create_simulator!();
    let mut public = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    public.parms_and_id =
        PublicParmsAndId::KeyedHash(None, Tpm2bDigest::from_bytes(&[3u8; 32]).unwrap());
    let ext = load_external(&mut sim, public, None, Handle::RH_OWNER).unwrap();
    let rc = rc_of(&mut sim, &Unseal {}, UnsealHandles { item_handle: ext }, 1);
    assert_eq!(rc, rc0(TpmRc::AUTH_UNAVAILABLE));
}

// ---------------------------------------------------------------------------------------------
// Primary objects
// ---------------------------------------------------------------------------------------------

// tpm2-createprimary-and-createloaded-primary-seed-derivation-vulnerability
#[test]
fn tpm2_createprimary_and_createloaded_primary_seed_derivation_vulnerability() {
    let mut sim = create_simulator!();
    let plain = ecc_sign_template(
        TpmiAlgHash::Sha256,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    );
    let mut with_policy = plain;
    with_policy
        .object_attributes
        .remove(TpmaObject::USER_WITH_AUTH);
    with_policy.auth_policy = Tpm2bDigest::from_bytes(&[0x42; 32]).unwrap();

    let key = |sim: &mut Simulator<'_>, t: TpmtPublic<'static>, data: &[u8]| {
        let (h, rsp) = create_primary(sim, Handle::RH_OWNER, t, data).unwrap();
        flush_context(sim, h).unwrap();
        ecc_point(&rsp.out_public.0)
    };
    let a = key(&mut sim, plain, &[]);
    // Deterministic for the same template...
    assert_eq!(a, key(&mut sim, plain, &[]));
    // ...but bound to the whole template and to inSensitive.data.
    assert_ne!(
        a,
        key(&mut sim, with_policy, &[]),
        "template not bound into the primary seed"
    );
    assert_ne!(
        a,
        key(&mut sim, plain, b"extra"),
        "inSensitive.data not bound into the seed"
    );

    // CreateLoaded with a hierarchy parent derives the same primary object as CreatePrimary.
    let (rsp, _) = run(
        &mut sim,
        &CreateLoaded {
            in_sensitive: sensitive_create(&[], &[]),
            in_public: make_template(&with_policy),
        },
        CreateLoadedHandles {
            parent_handle: Handle::RH_OWNER,
        },
        1,
    )
    .unwrap();
    assert_eq!(
        ecc_point(&rsp.out_public.0),
        key(&mut sim, with_policy, &[])
    );
}

// create-primary-spurious-nv-clear-orderly-and-transient-slot-allocation-order-bugs
#[test]
fn create_primary_spurious_nv_clear_orderly_and_transient_slot_allocation_order_bugs() {
    let mut sim = create_simulator!();
    // CreatePrimary does not need NV.
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    let (h, _) = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template(
            TpmiAlgHash::Sha256,
            TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
        ),
        &[],
    )
    .expect("CreatePrimary with NV unavailable");
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    flush_context(&mut sim, h).unwrap();

    // Fill every transient slot.
    let srk = owner_srk(&mut sim);
    let sealed = create(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"x",
    )
    .unwrap();
    let mut loaded = vec![srk];
    loop {
        match load(&mut sim, srk, sealed.out_private, sealed.out_public) {
            Ok(h) => loaded.push(h),
            Err(rc) => {
                assert_eq!(rc, rc0(TpmRc::OBJECT_MEMORY));
                break;
            }
        }
        assert!(loaded.len() < 64, "no object memory limit reached");
    }

    // With no free slot, OBJECT_MEMORY precedes template, inPrivate and hierarchy errors.
    let mut bad = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::FIXED_TPM);
    bad.object_attributes.remove(TpmaObject::FIXED_PARENT);
    assert_eq!(
        create_primary(&mut sim, Handle::RH_OWNER, bad, &[]).unwrap_err(),
        rc0(TpmRc::OBJECT_MEMORY)
    );
    assert_eq!(
        load(&mut sim, srk, Tpm2bPrivate::default(), sealed.out_public).unwrap_err(),
        rc0(TpmRc::OBJECT_MEMORY)
    );
    set_hierarchy_enabled(&mut sim, Handle::RH_ENDORSEMENT, false);
    let mut public = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    public.parms_and_id =
        PublicParmsAndId::KeyedHash(None, Tpm2bDigest::from_bytes(&[3u8; 32]).unwrap());
    assert_eq!(
        load_external(&mut sim, public, None, Handle::RH_ENDORSEMENT).unwrap_err(),
        rc0(TpmRc::OBJECT_MEMORY)
    );
}

// create-loaded-template-unmarshal-order-error-codes-and-namealg-bugs
#[test]
fn create_loaded_template_unmarshal_order_error_codes_and_namealg_bugs() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let mut t = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.name_alg = None;
    let rc = rc_of(
        &mut sim,
        &CreateLoaded {
            in_sensitive: sensitive_create(&[], b"x"),
            in_public: make_template(&t),
        },
        CreateLoadedHandles { parent_handle: srk },
        1,
    );
    assert_eq!(rc, rc_p(TpmRc::HASH, 2));
}

// update-aliased-transient-objects-corrupts-qualified-names-and-flushes-handles
#[test]
fn update_aliased_transient_objects_corrupts_qualified_names_and_flushes_handles() {
    let mut sim = create_simulator!();
    let template = ecc_sign_template(
        TpmiAlgHash::Sha256,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    );
    let (p, rsp) = create_primary(&mut sim, Handle::RH_OWNER, template, &[]).unwrap();
    flush_context(&mut sim, p).unwrap();

    // Load the same public area externally: same Name, but QN == Name.
    let ext = load_external(&mut sim, rsp.out_public.0, None, Handle::RH_OWNER).unwrap();
    let ext_qn = read_public(&mut sim, ext).unwrap().qualified_name;

    // Re-creating the primary must neither flush nor modify the external object.
    let (p2, rsp2) = create_primary(&mut sim, Handle::RH_OWNER, template, &[]).unwrap();
    assert_eq!(rsp2.name.get_buffer(), rsp.name.get_buffer());
    let after = read_public(&mut sim, ext).expect("external object was flushed");
    assert_eq!(after.qualified_name.get_buffer(), ext_qn.get_buffer());
    assert!(read_public(&mut sim, p2).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Template / scheme validation
// ---------------------------------------------------------------------------------------------

// object-attributes-and-schemechecks-validation-bugs
#[test]
fn object_attributes_and_schemechecks_validation_bugs() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let p2 = |rc| rc_p(rc, 2);

    // Sealed data object with a non-NULL scheme.
    let mut t = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.parms_and_id = PublicParmsAndId::KeyedHash(
        Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        Tpm2bDigest::default(),
    );
    assert_eq!(
        create(&mut sim, srk, t, &[], b"x").unwrap_err(),
        p2(TpmRc::SCHEME)
    );

    // KEYEDHASH signing key with a NULL scheme.
    let mut t = sealed_template(
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::SENSITIVE_DATA_ORIGIN,
    );
    t.parms_and_id = PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default());
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::SCHEME)
    );

    // Unrestricted RSA decryption key with a symmetric algorithm.
    let mut t = rsa_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.object_attributes.remove(TpmaObject::RESTRICTED);
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::SYMMETRIC)
    );

    // Storage parent without a symmetric algorithm.
    let mut t = ecc_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    if let PublicParmsAndId::Ecc(parms, _) = &mut t.parms_and_id {
        parms.symmetric = None;
    }
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::SYMMETRIC)
    );

    // A fixedParent storage child must use its parent's nameAlg.
    let t = ecc_storage_template(
        TpmiAlgHash::Sha384,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    );
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::HASH)
    );

    // Dual-use asymmetric key with a scheme.
    let mut t = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::DECRYPT);
    assert!(matches!(t.parms_and_id, PublicParmsAndId::Ecc(..)));
    if let PublicParmsAndId::Ecc(parms, _) = &mut t.parms_and_id {
        parms.scheme = Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256));
    }
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::SCHEME)
    );

    // A sealed data object can not have sensitiveDataOrigin SET.
    let t = sealed_template(TpmiAlgHash::Sha256, TpmaObject::SENSITIVE_DATA_ORIGIN);
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::ATTRIBUTES)
    );

    // A SYMCIPHER decryption key may use the NULL mode.
    let mut t = sym_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.parms_and_id = PublicParmsAndId::Sym(TpmtSymDefObject::Aes128(None), Tpm2bDigest::default());
    create(&mut sim, srk, t, &[], &[]).expect("SYMCIPHER decrypt key with NULL mode");

    // A primary object with sensitiveDataOrigin may get inSensitive.data (extra KDF input).
    create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template(
            TpmiAlgHash::Sha256,
            TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
        ),
        b"entropy",
    )
    .expect("primary with sensitiveDataOrigin and data");
}

// compute-pcr-digest-omits-sha512-and-pcr-allocation-filter
#[test]
fn compute_pcr_digest_omits_sha512_and_pcr_allocation_filter() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let selection = TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha384, &[0x01, 0x00, 0x00]).unwrap(),
        TpmsPcrSelection::new(TpmiAlgHash::Sha512, &[0x01, 0x00, 0x00]).unwrap(),
    ])
    .unwrap();
    let cmd = Create {
        in_sensitive: sensitive_create(&[], b"x"),
        in_public: Tpm2b(sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty())),
        outside_info: Tpm2bData::default(),
        creation_pcr: selection,
    };
    let (rsp, _) = run(&mut sim, &cmd, CreateHandles { parent_handle: srk }, 1)
        .expect("SHA-512 creationPCR must be accepted");
    let creation = rsp.creation_data.0;
    // Both banks are unallocated by default: their bits are filtered out and nothing is hashed.
    for sel in creation.pcr_select.pcr_selections() {
        assert!(
            sel.pcr_select().iter().all(|&b| b == 0),
            "unfiltered selection: {sel:?}"
        );
    }
    assert_eq!(
        creation.pcr_digest.get_buffer(),
        hash(TpmiAlgHash::Sha256, &[]).as_slice()
    );
}

// tpm2-loadexternal-rejects-null-namealg-and-omits-scheme-and-key-validation
#[test]
fn tpm2_loadexternal_rejects_null_namealg_and_omits_scheme_and_key_validation() {
    let mut sim = create_simulator!();
    // 1. SchemeChecks run for public-only keys: a restricted signing key needs a scheme.
    let mut t = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::RESTRICTED);
    if let PublicParmsAndId::Ecc(parms, point) = &mut t.parms_and_id {
        parms.scheme = None;
        *point = crypto_blobs::p256_generator();
    }
    assert_eq!(
        load_external(&mut sim, t, None, Handle::RH_OWNER).unwrap_err(),
        rc_p(TpmRc::SCHEME, 2)
    );

    // 2. seedValue must be digest-sized for SYMCIPHER/KEYEDHASH keys with a sensitive area.
    let key = [9u8; 16];
    let seed = [1u8; 16];
    let unique = hash(TpmiAlgHash::Sha256, &[&seed, &key]);
    let mut t = sym_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.object_attributes
        .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
    t.parms_and_id = PublicParmsAndId::Sym(
        TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
        Tpm2bDigest::from_bytes(leak_bytes(&unique)).unwrap(),
    );
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(leak_bytes(&seed)).unwrap(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(leak_bytes(&key)).unwrap()),
    };
    assert_eq!(
        load_external(&mut sim, t, Some(sensitive), Handle::RH_NULL).unwrap_err(),
        rc_p(TpmRc::KEY_SIZE, 1)
    );

    // 3. A public-only KEYEDHASH object needs a digest-sized unique.
    let t = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    assert_eq!(
        load_external(&mut sim, t, None, Handle::RH_OWNER).unwrap_err(),
        rc_p(TpmRc::KEY, 2)
    );

    // 4. RSA-3072 public keys are accepted like in create_loaded.
    let mut modulus = [0x33u8; 384];
    modulus[0] = 0xd5;
    let t = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(3072),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&modulus)).unwrap(),
        ),
    };
    load_external(&mut sim, t, None, Handle::RH_OWNER).expect("RSA-3072 public key");
}

// validate-and-import-sensitive-rsa-msb-and-ecc-validation-bugs
#[test]
fn validate_and_import_sensitive_rsa_msb_and_ecc_validation_bugs() {
    let mut sim = create_simulator!();
    // RSA modulus without its most significant bit SET.
    let mut modulus = [0x5au8; 256];
    modulus[0] = 0x01;
    let mut t = rsa_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.object_attributes.remove(TpmaObject::RESTRICTED);
    t.parms_and_id = PublicParmsAndId::Rsa(
        TpmsRsaParms {
            symmetric: None,
            scheme: None,
            key_bits: TpmiRsaKeyBits(2048),
            exponent: 0,
        },
        Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&modulus)).unwrap(),
    );
    assert_eq!(
        load_external(&mut sim, t, None, Handle::RH_OWNER).unwrap_err(),
        rc_p(TpmRc::KEY, 2)
    );

    // ECC private scalars outside 0 < d < n are rejected even with a NULL nameAlg.
    let ecc_ext = |d: &[u8]| {
        let mut t = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty());
        t.name_alg = None;
        t.object_attributes
            .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
        let s = TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::default(),
            sensitive: TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::from_bytes(leak_bytes(d)).unwrap(),
            ),
        };
        (t, s)
    };
    let (t, s) = ecc_ext(&[0u8; 32]);
    assert_eq!(
        load_external(&mut sim, t, Some(s), Handle::RH_NULL).unwrap_err(),
        rc1(TpmRc::KEY_SIZE)
    );
    let (t, s) = ecc_ext(&crypto_blobs::p256_order());
    assert_eq!(
        load_external(&mut sim, t, Some(s), Handle::RH_NULL).unwrap_err(),
        rc1(TpmRc::KEY_SIZE)
    );
    let (t, s) = ecc_ext(&[1u8; 32]);
    load_external(&mut sim, t, Some(s), Handle::RH_NULL).expect("valid scalar");

    // A public/sensitive binding mismatch is a bare TPM_RC_BINDING (CryptValidateKeys and
    // CryptRsaLoadPrivateExponent return it without blame).
    let mut t = sym_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.object_attributes
        .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
    t.parms_and_id = PublicParmsAndId::Sym(
        TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
        Tpm2bDigest::from_bytes(&[0xee; 32]).unwrap(),
    );
    let s = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[1; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(&[2; 16]).unwrap()),
    };
    assert_eq!(
        load_external(&mut sim, t, Some(s), Handle::RH_NULL).unwrap_err(),
        rc1(TpmRc::BINDING)
    );
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

// tpm2-activatecredential-and-tpm2-makecredential-reject-valid
#[test]
fn tpm2_activatecredential_and_tpm2_makecredential_reject_valid() {
    let mut sim = create_simulator!();
    // ECC protector whose public x coordinate has a stripped leading zero byte; it is imported
    // with its private key (d = 379) so that it can be used on both sides.
    let srk = owner_srk(&mut sim);
    let ecc_ek = crypto_blobs::load_stripped_ecc_storage_key(&mut sim, srk);
    let ek_name = read_public(&mut sim, ecc_ek).unwrap().name;
    let mc = |sim: &mut Simulator<'_>, handle: Handle, cred: &[u8], name: Tpm2bName<'static>| {
        run(
            sim,
            &MakeCredential {
                credential: Tpm2bDigest::from_bytes(leak_bytes(cred)).unwrap(),
                object_name: name,
            },
            MakeCredentialHandles { handle },
            0,
        )
    };
    let (made, _) = mc(&mut sim, ecc_ek, &[1; 16], ek_name)
        .expect("stripped ECC coordinate must be accepted by MakeCredential");
    // The credential size is validated against the key's nameAlg.
    assert_eq!(
        mc(&mut sim, ecc_ek, &[1; 33], ek_name).unwrap_err(),
        rc_p(TpmRc::SIZE, 1)
    );
    // ActivateCredential with the same key (activateHandle = the key itself).
    let (activated, _) = run(
        &mut sim,
        &ActivateCredential {
            credential_blob: made.credential_blob,
            secret: made.secret,
        },
        ActivateCredentialHandles {
            activate_handle: ecc_ek,
            key_handle: ecc_ek,
        },
        2,
    )
    .expect("stripped ECC coordinate must be accepted by ActivateCredential");
    assert_eq!(activated.cert_info.get_buffer(), &[1; 16]);

    // ActivateCredential error codes.
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    );
    let ac = |sim: &mut Simulator<'_>, key: Handle, blob: &[u8], secret: &[u8]| {
        rc_of(
            sim,
            &ActivateCredential {
                credential_blob: Tpm2bIdObject::from_bytes(leak_bytes(blob)).unwrap(),
                secret: Tpm2bEncryptedSecret::from_bytes(leak_bytes(secret)).unwrap(),
            },
            ActivateCredentialHandles {
                activate_handle: signer,
                key_handle: key,
            },
            2,
        )
    };
    // Non-decryption key -> TYPE + RC_H2.
    assert_eq!(ac(&mut sim, signer, &[], &[]), rc_h(TpmRc::TYPE, 2));
    // RSA decryption failure -> VALUE + RC_P2.
    assert_eq!(ac(&mut sim, srk, &[], &[0x11; 256]), rc_p(TpmRc::VALUE, 2));

    // A valid secret with a tampered credential blob -> INTEGRITY + RC_P1.
    let signer_name = read_public(&mut sim, signer).unwrap().name;
    let (made, _) = run(
        &mut sim,
        &MakeCredential {
            credential: Tpm2bDigest::from_bytes(&[5; 20]).unwrap(),
            object_name: signer_name,
        },
        MakeCredentialHandles { handle: srk },
        0,
    )
    .unwrap();
    let mut blob = made.credential_blob.get_buffer().to_vec();
    let last = blob.len() - 1;
    blob[last] ^= 1;
    assert_eq!(
        ac(&mut sim, srk, &blob, made.secret.get_buffer()),
        rc_p(TpmRc::INTEGRITY, 1)
    );
    // Untampered blob works.
    assert_eq!(
        ac(
            &mut sim,
            srk,
            made.credential_blob.get_buffer(),
            made.secret.get_buffer()
        ),
        0
    );
}

// ---------------------------------------------------------------------------------------------
// Duplication, import and rewrap
// ---------------------------------------------------------------------------------------------

// tpm2-duplicate-and-import-outer-wrapper-hash-and-seed-bugs
#[test]
fn tpm2_duplicate_and_import_outer_wrapper_hash_and_seed_bugs() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let parent = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        rsa_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
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
        encryption_key: Tpm2bData::default(),
        object_public: obj_rsp.out_public,
        duplicate: Tpm2bPrivate::from_bytes(&[0, 2, 0, 0]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
    };
    assert_eq!(
        rc_of(
            &mut sim,
            &cmd,
            ImportHandles {
                parent_handle: parent
            },
            1
        ),
        rc_p(TpmRc::SIZE, 1)
    );
}

// tpm2-duplicate-and-import-outer-wrap-hash-and-inner-key-bugs
#[test]
fn tpm2_duplicate_and_import_outer_wrap_hash_and_inner_key_bugs() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let parent = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        rsa_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    )
    .unwrap()
    .0;
    let (obj, obj_rsp) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha512),
        &[],
        &[],
    );
    let name = read_public(&mut sim, obj).unwrap().name;
    let dup = duplicate_alg(&mut sim, obj, parent, None, TpmiAlgHash::Sha512).unwrap();
    rewrap(
        &mut sim,
        parent,
        Handle::RH_NULL,
        dup.duplicate,
        name,
        dup.out_sym_seed,
    )
    .expect("outer wrapper hash must be the parent's nameAlg");

    // Corrupted outer integrity -> INTEGRITY + RC_P3 (RC_Import_duplicate).
    let dup = duplicate_alg(&mut sim, obj, parent, None, TpmiAlgHash::Sha512).unwrap();
    let mut blob = dup.duplicate.get_buffer().to_vec();
    blob[4] ^= 0x80;
    assert_eq!(
        import(
            &mut sim,
            parent,
            obj_rsp.out_public,
            Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
            dup.out_sym_seed,
        )
        .unwrap_err(),
        rc_p(TpmRc::INTEGRITY, 3)
    );
    // Inner wrapper: the integrity TPM2B_DIGEST is unmarshaled (size > 64 -> SIZE) and checked
    // (INTEGRITY) before the TPM2B_SENSITIVE is looked at (C CheckInnerIntegrity).
    let key = [0x24u8; 16];
    let inner_import = |sim: &mut Simulator<'_>, plain: &[u8]| {
        let mut blob = plain.to_vec();
        crypto_blobs::aes128_cfb_zero_iv_encrypt(&key, &mut blob);
        rc_of(
            sim,
            &Import {
                encryption_key: Tpm2bData::from_bytes(leak_bytes(&key)).unwrap(),
                object_public: obj_rsp.out_public,
                duplicate: Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
                in_sym_seed: Tpm2bEncryptedSecret::default(),
                symmetric_alg: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
            },
            ImportHandles {
                parent_handle: parent,
            },
            1,
        )
    };
    let mut plain = vec![0x00, 0x41];
    plain.extend([0u8; 8]);
    assert_eq!(inner_import(&mut sim, &plain), rc_p(TpmRc::SIZE, 3));
    let mut plain = vec![0x00, 0x40];
    plain.extend([0u8; 64 + 8]);
    assert_eq!(inner_import(&mut sim, &plain), rc_p(TpmRc::INTEGRITY, 3));

    // Truncated duplicate -> INSUFFICIENT + RC_P3.
    assert_eq!(
        import(
            &mut sim,
            parent,
            obj_rsp.out_public,
            Tpm2bPrivate::from_bytes(&[0]).unwrap(),
            dup.out_sym_seed,
        )
        .unwrap_err(),
        rc_p(TpmRc::INSUFFICIENT, 3)
    );
}

// tpm2-rewrap-reuses-old-protection-seed-instead
#[test]
fn tpm2_rewrap_reuses_old_protection_seed_instead() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let ecc_parent = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    )
    .unwrap()
    .0;
    let (obj, obj_rsp) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha256),
        &[],
        &[],
    );
    let name = read_public(&mut sim, obj).unwrap().name;

    // Unwrapped duplicate -> Rewrap to an ECC parent (fresh ECDH seed) -> Import -> Load.
    let dup = duplicate(&mut sim, obj, Handle::RH_NULL, None).unwrap();
    let wrapped = rewrap(
        &mut sim,
        Handle::RH_NULL,
        ecc_parent,
        dup.duplicate,
        name,
        Tpm2bEncryptedSecret::default(),
    )
    .expect("Rewrap to an ECC parent");
    assert!(wrapped.out_sym_seed.get_size() > 0);
    let private = import(
        &mut sim,
        ecc_parent,
        obj_rsp.out_public,
        wrapped.out_duplicate,
        wrapped.out_sym_seed,
    )
    .expect("Import of a rewrapped duplicate");
    load(&mut sim, ecc_parent, private, obj_rsp.out_public).unwrap();

    // ECC old parent: unwrap and wrap again to a NULL parent.
    let back = rewrap(
        &mut sim,
        ecc_parent,
        Handle::RH_NULL,
        wrapped.out_duplicate,
        name,
        wrapped.out_sym_seed,
    )
    .expect("Rewrap from an ECC parent");
    assert_eq!(back.out_duplicate.get_buffer(), dup.duplicate.get_buffer());

    // A maximum-size unwrapped duplicate can not get an outer wrapper: VALUE + RC_P1 (no panic).
    let big = vec![0x42u8; Tpm2bPrivate::CAP];
    assert_eq!(
        rewrap(
            &mut sim,
            Handle::RH_NULL,
            ecc_parent,
            Tpm2bPrivate::from_bytes(leak_bytes(&big)).unwrap(),
            name,
            Tpm2bEncryptedSecret::default(),
        )
        .unwrap_err(),
        rc_p(TpmRc::VALUE, 1)
    );
}

// tpm2-rewrap-unwrap-outer-and-overflow-missing-rc-p1-error-positions
#[test]
fn tpm2_rewrap_unwrap_outer_and_overflow_missing_rc_p1_error_positions() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let parent = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        rsa_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    )
    .unwrap()
    .0;
    let (obj, _) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha256),
        &[],
        &[],
    );
    let name = read_public(&mut sim, obj).unwrap().name;
    let dup = duplicate(&mut sim, obj, parent, None).unwrap();

    // Truncated inDuplicate -> INSUFFICIENT + RC_P1.
    assert_eq!(
        rewrap(
            &mut sim,
            parent,
            Handle::RH_NULL,
            Tpm2bPrivate::from_bytes(&[0]).unwrap(),
            name,
            dup.out_sym_seed,
        )
        .unwrap_err(),
        rc_p(TpmRc::INSUFFICIENT, 1)
    );
    // Corrupted integrity -> INTEGRITY + RC_P1.
    let mut blob = dup.duplicate.get_buffer().to_vec();
    blob[3] ^= 1;
    assert_eq!(
        rewrap(
            &mut sim,
            parent,
            Handle::RH_NULL,
            Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
            name,
            dup.out_sym_seed,
        )
        .unwrap_err(),
        rc_p(TpmRc::INTEGRITY, 1)
    );
    // Output overflow -> VALUE + RC_P1.
    let big = vec![0x42u8; Tpm2bPrivate::CAP];
    assert_eq!(
        rewrap(
            &mut sim,
            Handle::RH_NULL,
            parent,
            Tpm2bPrivate::from_bytes(leak_bytes(&big)).unwrap(),
            name,
            Tpm2bEncryptedSecret::default(),
        )
        .unwrap_err(),
        rc_p(TpmRc::VALUE, 1)
    );
}

// ---------------------------------------------------------------------------------------------
// Sensitive area contents
// ---------------------------------------------------------------------------------------------

// transient-object-seed-truncation-to-32-bytes-and-zero-stripping
#[test]
fn transient_object_seed_truncation_to_32_bytes_and_zero_stripping() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    // SHA-384 SYMCIPHER key: its 48-byte seedValue must be kept in full.
    let mut t = sym_template(TpmiAlgHash::Sha384, TpmaObject::empty());
    t.auth_policy = dup_policy_digest_for(TpmiAlgHash::Sha384);
    let (obj, rsp) = create_and_load(&mut sim, srk, t, b"pw", &[]);
    let dup = duplicate_with_policy(&mut sim, obj, TpmiAlgHash::Sha384);
    let sensitive = parse_plain_duplicate(dup.duplicate.get_buffer());
    assert_eq!(sensitive.seed_value.get_size(), 48, "seedValue truncated");
    let key = match sensitive.sensitive {
        TpmuSensitiveComposite::Sym(k) => k.get_buffer().to_vec(),
        _ => panic!("not a symmetric key"),
    };
    let unique = match rsp.out_public.0.parms_and_id {
        PublicParmsAndId::Sym(_, u) => u.get_buffer().to_vec(),
        _ => unreachable!(),
    };
    assert_eq!(
        hash(
            TpmiAlgHash::Sha384,
            &[sensitive.seed_value.get_buffer(), &key]
        ),
        unique
    );

    // C CryptCreateObject drops the seedValue of non-parent asymmetric keys.
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha256),
        &[],
        &[],
    );
    let dup = duplicate(&mut sim, signer, Handle::RH_NULL, None).unwrap();
    assert_eq!(
        parse_plain_duplicate(dup.duplicate.get_buffer())
            .seed_value
            .get_size(),
        0
    );
}

// parent-seed-truncation-trailing-zero-strip-and-stclear-omission
#[test]
fn parent_seed_truncation_trailing_zero_strip_and_stclear_omission() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    // A SHA-512 KEYEDHASH object: its 64-byte seedValue must survive creation and loading.
    let mut t = sealed_template(TpmiAlgHash::Sha512, TpmaObject::empty());
    t.auth_policy = dup_policy_digest_for(TpmiAlgHash::Sha512);
    let (obj, rsp) = create_and_load(&mut sim, srk, t, &[], b"data");
    let dup = duplicate_with_policy(&mut sim, obj, TpmiAlgHash::Sha512);
    let sensitive = parse_plain_duplicate(dup.duplicate.get_buffer());
    assert_eq!(sensitive.seed_value.get_size(), 64, "seedValue truncated");
    let unique = match rsp.out_public.0.parms_and_id {
        PublicParmsAndId::KeyedHash(_, u) => u.get_buffer().to_vec(),
        _ => unreachable!(),
    };
    assert_eq!(
        hash(
            TpmiAlgHash::Sha512,
            &[sensitive.seed_value.get_buffer(), b"data"]
        ),
        unique
    );
    // MarshalSensitive pads the (empty) authValue to the nameAlg digest size.
    assert_eq!(sensitive.auth_value.get_size(), 64);
}

// tpm2b-private-encrypted-sensitive-size-and-auth-padding-bug
#[test]
fn tpm2b_private_encrypted_sensitive_size_and_auth_padding_bug() {
    crypto_blobs::private_area_format_round_trip();
}

// tpm2-createloaded-derivation-parent-kdf-seed-rsa-and-symcipher-bugs
#[test]
fn tpm2_createloaded_derivation_parent_kdf_seed_rsa_and_symcipher_bugs() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    // Two derivation parents with the same sensitive bits (but different random seeds).
    let parent_t = derivation_parent_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    let (p1, _) = create_and_load(&mut sim, srk, parent_t, &[], &[0x77; 32]);
    let (p2, _) = create_and_load(&mut sim, srk, parent_t, &[], &[0x77; 32]);
    let derived = |sim: &mut Simulator<'_>, parent: Handle| {
        let child = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::FIXED_PARENT);
        let mut child = child;
        child
            .object_attributes
            .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
        let template = make_derive_template(
            &child,
            &TpmsDerive {
                label: Tpm2bLabel::from_bytes(b"label").unwrap(),
                context: Tpm2bLabel::from_bytes(b"context").unwrap(),
            },
        );
        let (rsp, h) = run(
            sim,
            &CreateLoaded {
                in_sensitive: sensitive_create(&[], &[]),
                in_public: template,
            },
            CreateLoadedHandles {
                parent_handle: parent,
            },
            1,
        )
        .expect("derived CreateLoaded");
        flush_context(sim, h.object_handle).unwrap();
        ecc_point(&rsp.out_public.0)
    };
    // The derivation secret is the parent's sensitive bits, not its seedValue.
    assert_eq!(derived(&mut sim, p1), derived(&mut sim, p2));
}
