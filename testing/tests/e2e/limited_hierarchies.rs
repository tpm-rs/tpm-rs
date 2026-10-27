//! Firmware-limited (`TPM_RH_FW_*`) and SVN-limited (`TPM_RH_SVN_*_BASE + SVN`) hierarchies
//! (TPM 2.0 Part 1, "TPM Firmware-Limited and SVN-Limited Objects"): their seeds and proofs are
//! derived from the base hierarchy's and the platform's Firmware Secret / Firmware SVN Secret
//! (the simulator and the C references use the reference platform's dummy secrets: firmware hash
//! 0, SVN 10, maximum SVN 255), they are available while the base hierarchy is enabled and (SVN)
//! the SVN does not exceed the firmware's current SVN, they are authorized by their base
//! hierarchy, their objects (and those objects' descendants) stay in the limited hierarchy
//! (contexts, tickets) and cannot be made persistent, and they are listed by
//! `TPM2_GetCapability`.

use crate::_common::{
    PW_SESSION, authorized_entity, build, context_load, context_save, create,
    create_ecc_signing_key, evict_control, execute_certify, execute_sign,
    execute_with_hmac_sessions, execute_with_password_sessions, flush_context,
    get_ecc_signing_key_template, get_ecc_srk_template, get_tpm_property, hierarchy_change_auth,
    leak_bytes, load, load_external, policy_signed_digest, policy_signed_with_nonce, policy_ticket,
    rc_h, rc_of, rc_p, run, set_hierarchy_enabled, set_primary_policy, start_auth_session,
    try_create_primary_in,
};
use sha2::{Digest, Sha256};
use testing::tpm::Tpm;
use tpm2::Marshal;
use tpm2::commands::{
    Certify, CertifyCreation, CreatePrimary, GetCapability, Hash, PolicyAuthorize, PolicySecret,
    SetPrimaryPolicy, StartAuthSession,
};
#[allow(deprecated)]
use tpm2::commands::{CreateLoaded, Sign, VerifySignature};
use tpm2::errors::{Fmt1, TpmRc};
use tpm2::{
    Handle, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret,
    Tpm2bMaxBuffer, Tpm2bNonce, Tpm2bTemplate, TpmCap, TpmPt, TpmSe, TpmaObject, TpmiAlgHash,
    TpmlPcrSelection, TpmsCapabilityData, TpmtHa, TpmtPublic, TpmtSensitive, TpmtSigScheme,
    TpmtTkAuth, TpmtTkCreation, TpmtTkHashcheck, TpmuSensitiveComposite,
};

/// `TPM_RH_FW_OWNER`.
const FW_OWNER: Handle = Handle::RH_FW_OWNER;
/// `TPM_RH_FW_ENDORSEMENT`.
const FW_ENDORSEMENT: Handle = Handle::RH_FW_ENDORSEMENT;
/// `TPM_RH_FW_PLATFORM`.
const FW_PLATFORM: Handle = Handle::RH_FW_PLATFORM;
/// `TPM_RH_FW_NULL`.
const FW_NULL: Handle = Handle::RH_FW_NULL;

/// The SVN of the simulated firmware (and of the C references' platform).
const CURRENT_SVN: u16 = 10;

/// The SVN-limited hierarchy of `base` (`TPM_RH_SVN_<base>_BASE`) limited to `svn`.
fn svn(base: Handle, svn: u16) -> Handle {
    Handle(base.0 + u32::from(svn))
}

/// The base hierarchies with their firmware-limited hierarchy and SVN-limited base handle.
const HIERARCHIES: [(Handle, Handle, Handle); 4] = [
    (Handle::RH_OWNER, FW_OWNER, Handle::RH_SVN_OWNER_BASE),
    (
        Handle::RH_ENDORSEMENT,
        FW_ENDORSEMENT,
        Handle::RH_SVN_ENDORSEMENT_BASE,
    ),
    (
        Handle::RH_PLATFORM,
        FW_PLATFORM,
        Handle::RH_SVN_PLATFORM_BASE,
    ),
    (Handle::RH_NULL, FW_NULL, Handle::RH_SVN_NULL_BASE),
];

/// An ECC P-256 storage key template (restricted decrypt, AES-128-CFB, fixedTPM, fixedParent)
/// with `extra` attributes.
fn storage_template(extra: TpmaObject) -> TpmtPublic<'static> {
    let mut t = get_ecc_srk_template();
    t.object_attributes |= extra;
    t
}

/// An ECC P-256 signing key template with fixedTPM and fixedParent and `extra` attributes.
fn fixed_signing_template(extra: TpmaObject) -> TpmtPublic<'static> {
    let mut t = get_ecc_signing_key_template();
    t.object_attributes |= TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT | extra;
    t
}

/// `TPM2_CreatePrimary(hierarchy, template)`; returns the handle and the Name.
fn create_primary(
    tpm: &mut Tpm,
    hierarchy: Handle,
    template: TpmtPublic<'static>,
) -> Result<(Handle, Vec<u8>), u32> {
    try_create_primary_in(tpm, hierarchy, template, &[])
        .map(|(handle, rsp)| (handle, rsp.name.get_buffer().to_vec()))
}

/// `TPM2_CreateLoaded(parent, template)`; returns the handle and the Name.
#[allow(deprecated)]
fn create_loaded(
    tpm: &mut Tpm,
    parent: Handle,
    template: TpmtPublic<'static>,
) -> Result<(Handle, Vec<u8>), u32> {
    let mut buf = [0u8; <TpmtPublic as Marshal>::MAX_SIZE];
    let len = template.marshal(&mut buf);
    let cmd = CreateLoaded {
        parent_handle: parent,
        in_sensitive: crate::_common::sensitive_create(&[], &[]),
        in_public: Tpm2bTemplate::from_bytes(leak_bytes(&buf[..len])).unwrap(),
    };
    run(tpm, &cmd, 1).map(|rsp| (rsp.object_handle, rsp.name.get_buffer().to_vec()))
}

/// A Primary Object of a limited hierarchy is derived from a seed of its own: the same template
/// gives a different key in the base hierarchy, the firmware-limited hierarchy and each
/// SVN-limited hierarchy (Part 1, "Firmware-limited and SVN-limited hierarchy seeds and proof
/// values": the seed is `KDFa(hashAlg, bSecret, bSecretLabel, aSecret, aSecretLabel, bits)`),
/// and the same key again when it is recreated (TPM2_CreatePrimary: "If this command is called
/// multiple times with the same *inPublic* parameter, *inSensitive.data*, and Primary Seed, the
/// TPM shall produce the same Primary Object."). The differential tests check the derived keys
/// against the C references byte for byte.
#[test]
fn limited_primary_keys_are_distinct_and_deterministic() {
    let mut tpm = Tpm::new();
    for (base, fw, svn_base) in HIERARCHIES {
        let handles = [
            base,
            fw,
            svn_base,
            svn(svn_base, 1),
            svn(svn_base, CURRENT_SVN),
        ];
        let mut names = Vec::new();
        for hierarchy in handles {
            let (handle, name) = create_primary(
                &mut tpm,
                hierarchy,
                fixed_signing_template(TpmaObject::empty()),
            )
            .unwrap_or_else(|rc| panic!("CreatePrimary({hierarchy:?}): {rc:#x}"));
            flush_context(&mut tpm, handle).unwrap();
            let (again, name_again) = create_primary(
                &mut tpm,
                hierarchy,
                fixed_signing_template(TpmaObject::empty()),
            )
            .unwrap();
            flush_context(&mut tpm, again).unwrap();
            assert_eq!(name, name_again, "{hierarchy:?} is deterministic");
            names.push(name);
        }
        for (i, a) in names.iter().enumerate() {
            for b in &names[i + 1..] {
                assert_ne!(a, b, "the hierarchies of {base:?} have distinct seeds");
            }
        }
    }
}

/// An SVN-limited hierarchy whose SVN is larger than the firmware's current SVN is unavailable:
/// Part 1, "Enrollment of SVN-Limited Objects": "Creation or loading of such objects shall fail
/// if the given SVN is greater than the TPM firmware's current SVN", with Part 2's
/// "TPM_RC_SVN_LIMITED | the hierarchy is SVN-limited but the Firmware SVN Secret associated with
/// the given SVN is unavailable", at the handle (`+ H1`).
#[test]
fn svn_above_current_svn_is_unavailable() {
    let mut tpm = Tpm::new();
    for (_, _, svn_base) in HIERARCHIES {
        for limit in [CURRENT_SVN + 1, 0x00FF, 0xFFFF] {
            let hierarchy = svn(svn_base, limit);
            let expected = rc_h(TpmRc::SVN_LIMITED, 1);
            assert_eq!(
                create_primary(
                    &mut tpm,
                    hierarchy,
                    fixed_signing_template(TpmaObject::empty())
                ),
                Err(expected)
            );
            assert_eq!(
                create_loaded(
                    &mut tpm,
                    hierarchy,
                    fixed_signing_template(TpmaObject::empty())
                ),
                Err(expected)
            );
        }
    }
}

/// The SVN-limited hierarchies follow the firmware's SVN (the MSSIM `TPM_SET_FW_SVN` signal
/// installs a firmware image with another SVN): after a downgrade the hierarchies of the larger
/// SVNs are unavailable (`TPM_RC_SVN_LIMITED`), also for the contexts of their objects, and after
/// an upgrade the keys of the older SVNs are unchanged. The SVN is capped at the maximum SVN
/// (255), which `TPM_PT_FIRMWARE_SVN` reports.
#[test]
fn svn_limited_hierarchies_follow_the_firmware_svn() {
    let mut tpm = Tpm::new();
    let (key, name) = create_primary(
        &mut tpm,
        svn(Handle::RH_SVN_OWNER_BASE, 7),
        fixed_signing_template(TpmaObject::SVN_LIMITED),
    )
    .unwrap();
    let context = context_save(&mut tpm, key);
    flush_context(&mut tpm, key).unwrap();

    tpm.set_firmware_svn(6);
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::FIRMWARE_SVN), 6);
    assert_eq!(
        create_primary(
            &mut tpm,
            svn(Handle::RH_SVN_OWNER_BASE, 7),
            fixed_signing_template(TpmaObject::SVN_LIMITED)
        ),
        Err(rc_h(TpmRc::SVN_LIMITED, 1))
    );
    // The context's integrity needs the hierarchy's proof, which needs the Firmware SVN Secret.
    assert_eq!(
        context_load(&mut tpm, context),
        Err(TpmRc::SVN_LIMITED.to_rc().get())
    );
    // The hierarchies of smaller SVNs are still available.
    let (key6, _) = create_primary(
        &mut tpm,
        svn(Handle::RH_SVN_OWNER_BASE, 6),
        fixed_signing_template(TpmaObject::SVN_LIMITED),
    )
    .unwrap();
    flush_context(&mut tpm, key6).unwrap();

    tpm.set_firmware_svn(u16::MAX);
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::FIRMWARE_SVN), 255);
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::FIRMWARE_MAX_SVN), 255);
    let restored = context_load(&mut tpm, context).expect("the context loads again");
    flush_context(&mut tpm, restored).unwrap();
    let (again, name_again) = create_primary(
        &mut tpm,
        svn(Handle::RH_SVN_OWNER_BASE, 7),
        fixed_signing_template(TpmaObject::SVN_LIMITED),
    )
    .unwrap();
    assert_eq!(name, name_again, "an upgrade keeps the SVN-limited keys");
    flush_context(&mut tpm, again).unwrap();
    assert_eq!(
        create_primary(
            &mut tpm,
            svn(Handle::RH_SVN_OWNER_BASE, 256),
            fixed_signing_template(TpmaObject::SVN_LIMITED)
        ),
        Err(rc_h(TpmRc::SVN_LIMITED, 1))
    );
}

/// The firmware-limited hierarchies are bound to the firmware image (the MSSIM `TPM_SET_FW_HASH`
/// signal installs an image with another hash and so another Firmware Secret): their keys change
/// with the image and come back with it (Part 1, "Firmware-Limited Attestation Keys": "When
/// *firmwareVersion* is unchanged, firmware-limited objects are also unchanged. This includes
/// situations where the TPM may run firmware version A, then firmware version B, then firmware
/// version A again."), while the SVN-limited and base hierarchies' keys stay the same.
#[test]
fn firmware_limited_keys_follow_the_firmware_image() {
    let mut tpm = Tpm::new();
    let template = || fixed_signing_template(TpmaObject::empty());
    let names = |tpm: &mut Tpm| -> Vec<Vec<u8>> {
        [
            FW_OWNER,
            svn(Handle::RH_SVN_OWNER_BASE, 3),
            Handle::RH_OWNER,
        ]
        .into_iter()
        .map(|h| {
            let (handle, name) = create_primary(tpm, h, template()).unwrap();
            flush_context(tpm, handle).unwrap();
            name
        })
        .collect()
    };
    let image_a = names(&mut tpm);
    let (fw_key, _) = create_primary(&mut tpm, FW_OWNER, template()).unwrap();
    let context = context_save(&mut tpm, fw_key);
    flush_context(&mut tpm, fw_key).unwrap();

    tpm.set_firmware_hash(0x0102_0304);
    let image_b = names(&mut tpm);
    assert_ne!(
        image_a[0], image_b[0],
        "a new image has a new Firmware Secret"
    );
    assert_eq!(image_a[1..], image_b[1..]);
    // Another Firmware Secret is another proof: the context fails its integrity check.
    assert_eq!(
        context_load(&mut tpm, context),
        Err(rc_p(TpmRc::INTEGRITY, 1))
    );

    tpm.set_firmware_hash(0);
    assert_eq!(names(&mut tpm), image_a);
    let restored = context_load(&mut tpm, context).expect("image A's context loads again");
    flush_context(&mut tpm, restored).unwrap();
}

/// A limited hierarchy is present only while its base hierarchy is enabled (the reference's
/// `ValidateHierarchy`: `TPM_RC_HIERARCHY` at the handle), and disabling the base hierarchy
/// flushes the loaded objects of its limited hierarchies (TPM2_HierarchyControl: "the TPM shall
/// flush all transient objects ... in the hierarchy").
#[test]
fn limited_hierarchy_needs_its_base_hierarchy_enabled() {
    let mut tpm = Tpm::new();
    let (fw_key, _) =
        create_primary(&mut tpm, FW_OWNER, storage_template(TpmaObject::empty())).unwrap();
    let (svn_key, _) = create_primary(
        &mut tpm,
        svn(Handle::RH_SVN_OWNER_BASE, 2),
        storage_template(TpmaObject::empty()),
    )
    .unwrap();
    let (other, _) = create_primary(
        &mut tpm,
        FW_ENDORSEMENT,
        storage_template(TpmaObject::empty()),
    )
    .unwrap();
    set_hierarchy_enabled(&mut tpm, Handle::RH_OWNER, false);
    for hierarchy in [FW_OWNER, svn(Handle::RH_SVN_OWNER_BASE, 0)] {
        assert_eq!(
            create_primary(&mut tpm, hierarchy, storage_template(TpmaObject::empty())),
            Err(rc_h(TpmRc::HIERARCHY, 1))
        );
    }
    // The owner hierarchy's limited objects are gone; the endorsement one is not.
    for handle in [fw_key, svn_key] {
        assert_eq!(flush_context(&mut tpm, handle), Err(rc_p(TpmRc::HANDLE, 1)));
    }
    flush_context(&mut tpm, other).unwrap();
    // An SVN beyond the current one fails with TPM_RC_SVN_LIMITED before the base hierarchy is
    // checked.
    assert_eq!(
        create_primary(
            &mut tpm,
            svn(Handle::RH_SVN_OWNER_BASE, CURRENT_SVN + 1),
            storage_template(TpmaObject::empty())
        ),
        Err(rc_h(TpmRc::SVN_LIMITED, 1))
    );
}

/// A limited hierarchy is authorized by its base hierarchy (Part 1, "Primary Seed
/// Authorizations": "For Primary Objects created in firmware-limited or SVN-limited
/// hierarchies, the required authorization is that of the associated base hierarchy"): its
/// authValue (password and HMAC sessions, where a session bound to the base hierarchy is bound to
/// the limited one) and its authPolicy.
#[test]
fn limited_hierarchy_uses_base_hierarchy_authorization() {
    let mut tpm = Tpm::new();
    hierarchy_change_auth(&mut tpm, Handle::RH_OWNER, &[], b"owner").unwrap();
    let cmd = |hierarchy: Handle| CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: crate::_common::sensitive_create(&[], &[]),
        in_public: Tpm2b(fixed_signing_template(TpmaObject::empty())),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    for hierarchy in [FW_OWNER, svn(Handle::RH_SVN_OWNER_BASE, 4)] {
        // Password session.
        assert_eq!(
            execute_with_password_sessions(&mut tpm, &cmd(hierarchy), 1, b"wrong").err(),
            Some(
                TpmRc::BAD_AUTH
                    .with(tpm2::errors::Position::session(1))
                    .get()
            )
        );
        let rsp = execute_with_password_sessions(&mut tpm, &cmd(hierarchy), 1, b"owner").unwrap();
        flush_context(&mut tpm, rsp.object_handle).unwrap();

        // Unbound and bound HMAC sessions.
        for bind in [Handle::RH_NULL, Handle::RH_OWNER] {
            let bind_auth: &[u8] = if bind == Handle::RH_NULL {
                &[]
            } else {
                b"owner"
            };
            let mut session = start_auth_session(
                &mut tpm,
                Handle::RH_NULL,
                bind,
                bind_auth,
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            )
            .unwrap();
            assert_eq!(authorized_entity(hierarchy), Handle::RH_OWNER);
            let name = hierarchy.0.to_be_bytes();
            let rsp = execute_with_hmac_sessions(
                &mut tpm,
                &cmd(hierarchy),
                &[&name],
                std::slice::from_mut(&mut session),
                &[b"owner"],
            )
            .unwrap_or_else(|rc| panic!("HMAC session bound to {bind:?}: {rc:#x}"));
            // The session (without continueSession) ended with the command.
            flush_context(&mut tpm, rsp.object_handle).unwrap();
        }
    }

    // The base hierarchy's authPolicy: an empty policy (a fresh policy session's digest).
    let set_policy = SetPrimaryPolicy {
        auth_handle: Handle::RH_OWNER,
        auth_policy: Tpm2bDigest::from_bytes(&[0; 32]).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    execute_with_password_sessions(&mut tpm, &set_policy, 1, b"owner").unwrap();
    for hierarchy in [FW_OWNER, svn(Handle::RH_SVN_OWNER_BASE, 4)] {
        let start = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[7; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let session = execute_with_password_sessions(&mut tpm, &start, 0, &[]).unwrap();
        let mut command = vec![];
        let mut params = crate::_common::marshal_to_vec(&cmd(hierarchy).in_sensitive);
        params.extend(crate::_common::marshal_to_vec(&cmd(hierarchy).in_public));
        params.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // outsideInfo, creationPCR
        let mut auth = session.session_handle.0.to_be_bytes().to_vec();
        auth.extend_from_slice(&[0, 0, 0, 0, 0]); // nonce, attributes, hmac
        command.extend(build(0x8002, 0x131, &[hierarchy.0], Some(&auth), &params));
        let rsp = tpm.send_command(0, &command);
        assert_eq!(rc_of(&rsp), 0, "policy authorization of {hierarchy:?}");
        let handle = Handle(u32::from_be_bytes(rsp[10..14].try_into().unwrap()));
        flush_context(&mut tpm, handle).unwrap();
    }
}

/// `firmwareLimited`/`svnLimited` (Part 2, TPMA_OBJECT Bit[8]/Bit[9], "Creation": "May only be
/// SET if ... *fixedTPM* is SET in *template* [and] *firmwareLimited* (*svnLimited*) is SET in
/// the object's parent", where "For a Primary Object in a Firmware-limited (an SVN-limited)
/// hierarchy, the parent is considered to have *firmwareLimited* (*svnLimited*) SET"); any other
/// combination is `TPM_RC_ATTRIBUTES + P2`.
#[test]
fn limited_attributes_need_a_limited_parent() {
    let mut tpm = Tpm::new();
    let fw = TpmaObject::FIRMWARE_LIMITED;
    let sv = TpmaObject::SVN_LIMITED;
    let attributes = rc_p(TpmRc::ATTRIBUTES, 2);
    let svn4 = svn(Handle::RH_SVN_OWNER_BASE, 4);
    // Primary Objects.
    for (hierarchy, extra, ok) in [
        (Handle::RH_OWNER, fw, false),
        (Handle::RH_OWNER, sv, false),
        (FW_OWNER, fw, true),
        (FW_NULL, fw, true),
        (FW_OWNER, sv, false),
        (svn4, sv, true),
        (svn4, fw, false),
        (FW_OWNER, TpmaObject::empty(), true),
        (svn4, TpmaObject::empty(), true),
    ] {
        let result = create_primary(&mut tpm, hierarchy, storage_template(extra));
        match result {
            Ok((handle, _)) => {
                assert!(ok, "{hierarchy:?} {extra:?}");
                flush_context(&mut tpm, handle).unwrap();
            }
            Err(rc) => {
                assert!(!ok, "{hierarchy:?} {extra:?}: {rc:#x}");
                assert_eq!(rc, attributes);
            }
        }
        let result = create_loaded(&mut tpm, hierarchy, storage_template(extra));
        assert_eq!(result.is_ok(), ok, "CreateLoaded {hierarchy:?} {extra:?}");
        if let Ok((handle, _)) = result {
            flush_context(&mut tpm, handle).unwrap();
        }
    }
    // fixedTPM is required.
    let mut not_fixed = get_ecc_signing_key_template();
    not_fixed.object_attributes |= fw;
    assert_eq!(
        create_primary(&mut tpm, FW_OWNER, not_fixed),
        Err(attributes)
    );

    // Ordinary objects: the parent's attribute counts, not its hierarchy. (One parent at a time:
    // TPM2_Create needs an object slot of its own.)
    for (hierarchy, parent_extra, cases) in [
        (
            FW_OWNER,
            fw,
            [(fw, true), (sv, false), (TpmaObject::empty(), true)],
        ),
        (
            FW_OWNER,
            TpmaObject::empty(),
            [(fw, false), (sv, false), (TpmaObject::empty(), true)],
        ),
        (
            svn4,
            sv,
            [(sv, true), (fw, false), (TpmaObject::empty(), true)],
        ),
    ] {
        let (parent, _) =
            create_primary(&mut tpm, hierarchy, storage_template(parent_extra)).unwrap();
        for (extra, ok) in cases {
            let result = create(&mut tpm, parent, fixed_signing_template(extra), &[], &[]);
            assert_eq!(
                result.as_ref().err().copied(),
                (!ok).then_some(attributes),
                "Create under a {parent_extra:?} parent: {extra:?}"
            );
            let result = create_loaded(&mut tpm, parent, fixed_signing_template(extra));
            assert_eq!(
                result.as_ref().err().copied(),
                (!ok).then_some(attributes),
                "CreateLoaded under a {parent_extra:?} parent: {extra:?}"
            );
            if let Ok((handle, _)) = result {
                flush_context(&mut tpm, handle).unwrap();
            }
        }
        flush_context(&mut tpm, parent).unwrap();
    }
}

/// Descendants of a limited Primary Object stay in its hierarchy (Part 1, "EvictControl of
/// objects in firmware-limited and SVN-limited hierarchies": "Objects in a firmware-limited or
/// SVN-limited hierarchy (including objects without *firmwareLimited/svnLimited* SET)"): their
/// saved contexts carry the limited hierarchy (and are protected by its proof), and so do the
/// creation tickets of `TPM2_CreatePrimary` and `TPM2_Create` (Part 2, TPMT_TK_CREATION:
/// "the hierarchy containing *name*"; the TCG references use the base hierarchy for
/// `TPM2_Create`, which the differential tests fix). Both tickets are accepted by
/// `TPM2_CertifyCreation`, and a ticket relabeled with the base hierarchy is rejected.
#[test]
fn descendants_stay_in_the_limited_hierarchy() {
    let mut tpm = Tpm::new();
    for (base, fw, svn_base) in HIERARCHIES {
        for hierarchy in [fw, svn(svn_base, 5)] {
            let primary = try_create_primary_in(
                &mut tpm,
                hierarchy,
                storage_template(TpmaObject::empty()),
                &[],
            )
            .unwrap();
            let (parent, primary_rsp) = primary;
            assert_eq!(primary_rsp.creation_ticket.hierarchy(), hierarchy);

            let child = create(
                &mut tpm,
                parent,
                fixed_signing_template(TpmaObject::empty()),
                &[],
                &[],
            )
            .unwrap();
            assert_eq!(child.creation_ticket.hierarchy(), hierarchy);
            let key = load(&mut tpm, parent, child.out_private, child.out_public).unwrap();

            let context = context_save(&mut tpm, key);
            assert_eq!(context.hierarchy, hierarchy);
            flush_context(&mut tpm, key).unwrap();
            let key = context_load(&mut tpm, context).unwrap();
            let context = context_save(&mut tpm, parent);
            assert_eq!(context.hierarchy, hierarchy);

            for (object, creation_hash, ticket) in [
                (
                    parent,
                    primary_rsp.creation_hash,
                    primary_rsp.creation_ticket,
                ),
                (key, child.creation_hash, child.creation_ticket),
            ] {
                let cmd = CertifyCreation {
                    sign_handle: Handle::RH_NULL,
                    object_handle: object,
                    qualifying_data: Tpm2bData::default(),
                    creation_hash,
                    in_scheme: None,
                    creation_ticket: ticket,
                };
                execute_with_password_sessions(&mut tpm, &cmd, 1, &[])
                    .unwrap_or_else(|rc| panic!("CertifyCreation in {hierarchy:?}: {rc:#x}"));
                // The same digest for the base hierarchy is not a ticket of this TPM.
                let relabeled = CertifyCreation {
                    creation_ticket: TpmtTkCreation::Creation(base, *ticket.digest()),
                    ..cmd
                };
                assert_eq!(
                    execute_with_password_sessions(&mut tpm, &relabeled, 1, &[]).err(),
                    Some(rc_p(TpmRc::TICKET, 4)),
                    "{hierarchy:?} relabeled {base:?}"
                );
            }
            flush_context(&mut tpm, key).unwrap();
            flush_context(&mut tpm, parent).unwrap();
        }
    }
}

/// The `TPM2_PolicySecret` and `TPM2_PolicySigned` auth tickets of an object in a limited
/// hierarchy are tickets of that hierarchy (TPM 2.0 Part 2, TPMT_TK_AUTH: "hierarchy of the
/// object used to produce the ticket"; the TCG references use the base hierarchy, which the
/// differential tests fix), which `TPM2_PolicyTicket` accepts, while the same digest relabeled
/// with the base hierarchy is rejected (`TPM_RC_TICKET + P5`).
#[test]
#[allow(deprecated)]
fn auth_tickets_of_limited_hierarchies() {
    let mut tpm = Tpm::new();
    let start = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[3; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    for (base, hierarchy) in [
        (Handle::RH_OWNER, FW_OWNER),
        (Handle::RH_NULL, FW_NULL),
        (
            Handle::RH_ENDORSEMENT,
            svn(Handle::RH_SVN_ENDORSEMENT_BASE, 6),
        ),
    ] {
        let (parent, _) =
            create_primary(&mut tpm, hierarchy, storage_template(TpmaObject::empty())).unwrap();
        let (key, key_name) = create_loaded(
            &mut tpm,
            parent,
            fixed_signing_template(TpmaObject::empty()),
        )
        .unwrap();

        // TPM2_PolicySecret with the key's authValue.
        let session = execute_with_password_sessions(&mut tpm, &start, 0, &[]).unwrap();
        let secret = PolicySecret {
            auth_handle: key,
            policy_session: session.session_handle,
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: -1,
        };
        let rsp = execute_with_password_sessions(&mut tpm, &secret, 1, &[]).unwrap();
        assert_eq!(rsp.policy_ticket.hierarchy(), hierarchy);

        // TPM2_PolicySigned with a signature of the key over nonceTPM || expiration.
        let session2 = execute_with_password_sessions(&mut tpm, &start, 0, &[]).unwrap();
        // aHash = SHA-256(nonceTPM || expiration).
        let a_hash = policy_signed_digest(session2.nonce_tpm.get_buffer(), -1);
        let sign = Sign {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(leak_bytes(&a_hash)).unwrap(),
            in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
            validation: TpmtTkHashcheck::default(),
        };
        let buf: &'static mut [u8; 4096] = Box::leak(Box::new([0u8; 4096]));
        let signature = execute_sign(&mut tpm, &sign, 1, &[], buf)
            .unwrap()
            .signature;
        let signed = policy_signed_with_nonce(
            &mut tpm,
            key,
            session2.session_handle,
            session2.nonce_tpm,
            -1,
            signature,
        )
        .unwrap();
        assert_eq!(signed.policy_ticket.hierarchy(), hierarchy);

        for (timeout, ticket) in [
            (rsp.timeout, rsp.policy_ticket),
            (signed.timeout, signed.policy_ticket),
        ] {
            let relabeled = match ticket {
                TpmtTkAuth::Secret(_, digest) => TpmtTkAuth::Secret(base, digest),
                TpmtTkAuth::Signed(_, digest) => TpmtTkAuth::Signed(base, digest),
            };
            let s = execute_with_password_sessions(&mut tpm, &start, 0, &[]).unwrap();
            assert_eq!(
                policy_ticket(
                    &mut tpm,
                    s.session_handle,
                    timeout.get_buffer(),
                    &[],
                    key_name.as_slice(),
                    relabeled
                ),
                Err(rc_p(TpmRc::TICKET, 5)),
                "{hierarchy:?} ticket relabeled {base:?}"
            );
            policy_ticket(
                &mut tpm,
                s.session_handle,
                timeout.get_buffer(),
                &[],
                key_name.as_slice(),
                ticket,
            )
            .unwrap_or_else(|rc| panic!("PolicyTicket in {hierarchy:?}: {rc:#x}"));
            flush_context(&mut tpm, s.session_handle).unwrap();
        }
        for handle in [session.session_handle, session2.session_handle, key, parent] {
            flush_context(&mut tpm, handle).unwrap();
        }
    }
}

/// Objects in a firmware-limited or SVN-limited hierarchy, including descendants without
/// `firmwareLimited`/`svnLimited`, cannot be made persistent: TPM 2.0 Part 3, TPM2_EvictControl:
/// "The TPM shall return `TPM_RC_ATTRIBUTES` if it is in the hierarchy of `TPM_RH_NULL` or a
/// firmware-limited or SVN-limited hierarchy" (`+ H2`; the TCG references return
/// `TPM_RC_HIERARCHY`, which the differential tests fix).
#[test]
fn evict_control_rejects_limited_objects() {
    let mut tpm = Tpm::new();
    for (auth, hierarchy, persistent) in [
        (Handle::RH_OWNER, FW_OWNER, 0x8100_0010),
        (Handle::RH_OWNER, FW_ENDORSEMENT, 0x8101_0010),
        (Handle::RH_PLATFORM, FW_PLATFORM, 0x8180_0010),
        (
            Handle::RH_OWNER,
            svn(Handle::RH_SVN_OWNER_BASE, 0),
            0x8100_0011,
        ),
        (
            Handle::RH_PLATFORM,
            svn(Handle::RH_SVN_PLATFORM_BASE, 9),
            0x8180_0011,
        ),
        (Handle::RH_OWNER, FW_NULL, 0x8100_0012),
    ] {
        let (primary, _) =
            create_primary(&mut tpm, hierarchy, storage_template(TpmaObject::empty())).unwrap();
        let (child, _) = create_loaded(
            &mut tpm,
            primary,
            fixed_signing_template(TpmaObject::empty()),
        )
        .unwrap();
        for object in [primary, child] {
            assert_eq!(
                evict_control(&mut tpm, auth, object, Handle(persistent)),
                Err(rc_h(TpmRc::ATTRIBUTES, 2)),
                "{hierarchy:?}"
            );
        }
        flush_context(&mut tpm, child).unwrap();
        flush_context(&mut tpm, primary).unwrap();
    }
}

/// `TPM2_VerifySignature` of a key in a limited hierarchy produces a ticket of that hierarchy
/// with its proof, also for `TPM_RH_FW_NULL` and the SVN-limited NULL hierarchies (TPM 2.0 Part 3:
/// only "If the key is in the NULL hierarchy" is the ticket a NULL ticket), which
/// `TPM2_PolicyAuthorize` accepts and checks against that proof.
#[test]
#[allow(deprecated)]
fn verified_tickets_of_limited_hierarchies() {
    let mut tpm = Tpm::new();
    let approved_policy = [0u8; 32];
    let a_hash = Sha256::digest(approved_policy);
    for hierarchy in [
        FW_OWNER,
        FW_NULL,
        svn(Handle::RH_SVN_NULL_BASE, 3),
        svn(Handle::RH_SVN_ENDORSEMENT_BASE, 10),
    ] {
        let (signer, signer_name) = create_ecc_signing_key(&mut tpm, hierarchy, false);
        let digest = Tpm2bDigest::from_bytes(leak_bytes(&a_hash)).unwrap();
        let sign = Sign {
            key_handle: signer,
            digest,
            in_scheme: None,
            validation: TpmtTkHashcheck::default(),
        };
        let mut buf = [0u8; 4096];
        let signature = execute_sign(&mut tpm, &sign, 1, &[], &mut buf)
            .unwrap()
            .signature;
        let verify = VerifySignature {
            key_handle: signer,
            digest,
            signature,
        };
        let ticket = execute_with_password_sessions(&mut tpm, &verify, 0, &[])
            .unwrap()
            .validation;
        assert_eq!(ticket.hierarchy(), hierarchy);
        assert_eq!(
            ticket.digest().get_size(),
            64,
            "a real ticket (SHA-512 HMAC)"
        );

        let start = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[1; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let session = execute_with_password_sessions(&mut tpm, &start, 0, &[]).unwrap();
        let authorize = PolicyAuthorize {
            policy_session: session.session_handle,
            approved_policy: Tpm2bDigest::from_bytes(&approved_policy).unwrap(),
            policy_ref: Tpm2bNonce::default(),
            key_sign: signer_name,
            check_ticket: ticket,
        };
        execute_with_password_sessions(&mut tpm, &authorize, 0, &[])
            .unwrap_or_else(|rc| panic!("PolicyAuthorize with a {hierarchy:?} ticket: {rc:#x}"));
        flush_context(&mut tpm, session.session_handle).unwrap();
        flush_context(&mut tpm, signer).unwrap();
    }
}

/// `TPM2_Hash` makes a hash-check ticket for any `TPMI_RH_HIERARCHY+`, including the limited
/// hierarchies (with their proofs; only `TPM_RH_NULL` gets a NULL ticket), which a restricted
/// signing key of that hierarchy accepts in `TPM2_Sign`; an unavailable limited hierarchy fails
/// with its error (`TPM_RC_SVN_LIMITED`, as the ticket needs its proof).
#[test]
#[allow(deprecated)]
fn hash_check_tickets_of_limited_hierarchies() {
    let mut tpm = Tpm::new();
    for hierarchy in [FW_OWNER, FW_NULL, svn(Handle::RH_SVN_PLATFORM_BASE, 1)] {
        let hash = Hash {
            data: Tpm2bMaxBuffer::from_bytes(b"limited").unwrap(),
            hash_alg: TpmiAlgHash::Sha256,
            hierarchy,
        };
        let rsp = tpm.execute(hash).unwrap();
        assert_eq!(rsp.validation.hierarchy(), hierarchy);
        assert_eq!(rsp.validation.digest().get_size(), 64);

        let (signer, _) = create_ecc_signing_key(&mut tpm, hierarchy, true);
        let sign = Sign {
            key_handle: signer,
            digest: rsp.out_hash,
            in_scheme: None,
            validation: rsp.validation,
        };
        let mut buf = [0u8; 4096];
        execute_sign(&mut tpm, &sign, 1, &[], &mut buf)
            .unwrap_or_else(|rc| panic!("Sign with a {hierarchy:?} ticket: {rc:#x}"));
        flush_context(&mut tpm, signer).unwrap();
    }
    let hash = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"limited").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: svn(Handle::RH_SVN_OWNER_BASE, CURRENT_SVN + 1),
    };
    assert_eq!(
        tpm.execute(hash).err().map(crate::_common::rc_of_error),
        Some(TpmRc::SVN_LIMITED.to_rc().get())
    );
}

/// `TPM2_LoadExternal` takes a limited `hierarchy` for a public-only object if the hierarchy is
/// available (else `TPM_RC_HIERARCHY + P3`); an object with a sensitive area must be in
/// `TPM_RH_NULL` itself (`TPM_RC_HIERARCHY + P3` for `TPM_RH_FW_NULL`); and `firmwareLimited`/
/// `svnLimited` must be CLEAR (TPM 2.0 Part 2, TPMA_OBJECT, "External: shall be CLEAR";
/// `TPM_RC_ATTRIBUTES + P2`, which the TCG references only check with a sensitive area). A key
/// loaded in a limited hierarchy verifies with tickets of that hierarchy.
#[test]
#[allow(deprecated)]
fn load_external_in_limited_hierarchies() {
    let mut tpm = Tpm::new();
    let (signer, _) = create_ecc_signing_key(&mut tpm, Handle::RH_NULL, false);
    let public = crate::_common::read_public(&mut tpm, signer)
        .unwrap()
        .out_public
        .0;
    let digest = Tpm2bDigest::from_bytes(&[0x5A; 32]).unwrap();
    let sign = Sign {
        key_handle: signer,
        digest,
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let mut buf = [0u8; 4096];
    let signature = execute_sign(&mut tpm, &sign, 1, &[], &mut buf)
        .unwrap()
        .signature;
    let mut external = public;
    external
        .object_attributes
        .remove(TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT);
    for hierarchy in [FW_OWNER, FW_NULL, svn(Handle::RH_SVN_ENDORSEMENT_BASE, 2)] {
        let key = load_external(&mut tpm, external, None, hierarchy).unwrap();
        let verify = VerifySignature {
            key_handle: key,
            digest,
            signature,
        };
        let ticket = execute_with_password_sessions(&mut tpm, &verify, 0, &[])
            .unwrap()
            .validation;
        assert_eq!(ticket.hierarchy(), hierarchy);
        flush_context(&mut tpm, key).unwrap();
    }
    assert_eq!(
        load_external(
            &mut tpm,
            external,
            None,
            svn(Handle::RH_SVN_OWNER_BASE, CURRENT_SVN + 1)
        ),
        Err(rc_p(TpmRc::HIERARCHY, 3))
    );
    set_hierarchy_enabled(&mut tpm, Handle::RH_ENDORSEMENT, false);
    assert_eq!(
        load_external(&mut tpm, external, None, FW_ENDORSEMENT),
        Err(rc_p(TpmRc::HIERARCHY, 3))
    );
    for extra in [TpmaObject::FIRMWARE_LIMITED, TpmaObject::SVN_LIMITED] {
        let mut limited = external;
        limited.object_attributes |= extra;
        for hierarchy in [Handle::RH_NULL, FW_OWNER] {
            assert_eq!(
                load_external(&mut tpm, limited, None, hierarchy),
                Err(rc_p(TpmRc::ATTRIBUTES, 2)),
                "{extra:?} in {hierarchy:?}"
            );
        }
    }
    // An external object with a sensitive area is in TPM_RH_NULL only (checked before the
    // sensitive area is validated).
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(&[1; 32]).unwrap()),
    };
    assert_eq!(
        load_external(&mut tpm, external, Some(sensitive), FW_NULL),
        Err(rc_p(TpmRc::HIERARCHY, 3))
    );
}

/// The TPM_CAP_HANDLES list of permanent handles includes the firmware-limited hierarchies and
/// the SVN 0 handle of each SVN-limited hierarchy (TPM 2.0 Part 3, TPM2_GetCapability: "only the
/// handles associated with SVN 0 are returned"), and TPM_CAP_AUTH_POLICIES reports the base
/// hierarchy's policy for each limited hierarchy but those of `TPM_RH_NULL` (which has none).
#[test]
fn capabilities_list_limited_hierarchies() {
    let mut tpm = Tpm::new();
    let handles = |tpm: &mut Tpm, from: u32| -> Vec<u32> {
        let rsp = tpm
            .execute(GetCapability {
                capability: TpmCap::Handles,
                property: from,
                property_count: 64,
            })
            .unwrap();
        match rsp.capability_data {
            TpmsCapabilityData::Handles(list) => list.as_ref().iter().map(|h| h.0).collect(),
            other => panic!("{other:?}"),
        }
    };
    let limited = [
        0x4000_0140,
        0x4000_0141,
        0x4000_0142,
        0x4000_0143,
        0x4001_0000,
        0x4002_0000,
        0x4003_0000,
        0x4004_0000,
    ];
    assert_eq!(handles(&mut tpm, 0x4000_0140), limited);
    assert!(handles(&mut tpm, 0x4000_0000).ends_with(&limited));
    assert_eq!(handles(&mut tpm, 0x4001_0001), limited[5..]);
    assert_eq!(handles(&mut tpm, 0x4004_0001), Vec::<u32>::new());

    let policy = [0xA5; 32];
    assert_eq!(set_primary_policy(&mut tpm, Handle::RH_OWNER, &policy), 0);
    let rsp = tpm
        .execute(GetCapability {
            capability: TpmCap::AuthPolicies,
            property: 0x4000_0140,
            property_count: 64,
        })
        .unwrap();
    let TpmsCapabilityData::AuthPolicies(list) = rsp.capability_data else {
        panic!("{:?}", rsp.capability_data);
    };
    let reported: Vec<(u32, Option<TpmtHa>)> = list
        .as_ref()
        .iter()
        .map(|p| (p.handle.0, p.policy_hash))
        .collect();
    let owner_policy = Some(TpmtHa::Sha256(&policy));
    assert_eq!(
        reported,
        [
            (0x4000_0140, owner_policy),
            (0x4000_0141, None),
            (0x4000_0142, None),
            (0x4001_0000, owner_policy),
            (0x4002_0000, None),
            (0x4003_0000, None),
        ]
    );
}

/// `TPM_PT_FIRMWARE_SVN` and `TPM_PT_FIRMWARE_MAX_SVN` report the firmware's current and maximum
/// SVN (TPM 2.0 Part 2, TPM_PT).
#[test]
fn firmware_svn_properties() {
    let mut tpm = Tpm::new();
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::FIRMWARE_SVN), 10);
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::FIRMWARE_MAX_SVN), 255);
}

/// An attestation signed by a key of a limited hierarchy is obfuscated like one signed in its
/// base hierarchy (TPM 2.0 Part 2, TPMS_ATTEST: *resetCount*, *restartCount* and
/// *firmwareVersion* are obfuscated unless the signing key is in the Endorsement or Platform
/// hierarchy).
#[test]
fn attestation_obfuscation_follows_the_base_hierarchy() {
    let mut tpm = Tpm::new();
    let plain_firmware_version = 1u64 << 32;
    for (hierarchy, obfuscated) in [
        (FW_ENDORSEMENT, false),
        (svn(Handle::RH_SVN_PLATFORM_BASE, 2), false),
        (FW_OWNER, true),
        (FW_NULL, true),
    ] {
        let (signer, _) = create_ecc_signing_key(&mut tpm, hierarchy, false);
        let cmd = Certify {
            object_handle: signer,
            sign_handle: signer,
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        };
        let mut buf = [0u8; 4096];
        let rsp = execute_certify(&mut tpm, &cmd, 2, &[], &mut buf).unwrap();
        let attest = rsp.certify_info.0;
        assert_eq!(
            attest.firmware_version != plain_firmware_version,
            obfuscated,
            "{hierarchy:?}"
        );
        flush_context(&mut tpm, signer).unwrap();
    }
}

/// Like the base hierarchies, the limited hierarchies cannot authorize `TPM2_HierarchyControl`,
/// whose `authHandle` is a `TPMI_RH_BASE_HIERARCHY` (TPM 2.0 Part 3, TPM2_HierarchyControl:
/// "TPMI_RH_BASE_HIERARCHY | @authHandle"; Part 2, Table "Definition of (TPM_HANDLE)
/// TPMI_RH_BASE_HIERARCHY Type": "TPM_RH_OWNER", "TPM_RH_PLATFORM", "TPM_RH_ENDORSEMENT",
/// "#TPM_RC_VALUE"), so a limited hierarchy there fails to unmarshal (`TPM_RC_VALUE + H1`).
#[test]
fn hierarchy_control_rejects_limited_hierarchies() {
    let mut tpm = Tpm::new();
    for handle in [FW_OWNER, FW_PLATFORM, svn(Handle::RH_SVN_PLATFORM_BASE, 1)] {
        let mut params = Handle::RH_OWNER.0.to_be_bytes().to_vec(); // enable
        params.push(0); // state: NO
        let cmd = build(0x8002, 0x0000_0121, &[handle.0], Some(&PW_SESSION), &params);
        assert_eq!(
            rc_of(&tpm.send_command(0, &cmd)),
            rc_h(TpmRc::VALUE, 1),
            "{handle:?}"
        );
    }
}

/// A `TPM2_ContextLoad` blob whose protected part (after the integrity value) only holds the
/// size of the sequence fingerprint (8 or 9 bytes) still reaches the integrity check, like the
/// TCG reference ("Make sure that the context blob has enough space for the fingerprint."), so an
/// unavailable SVN-limited `hierarchy` fails with its unavailable proof (`TPM_RC_SVN_LIMITED`),
/// and a short blob of an available hierarchy fails the integrity check
/// (`TPM_RC_INTEGRITY + P1`). Found by the `diff_conversation` fuzzer.
#[test]
fn short_context_blob_of_unavailable_hierarchy_fails_with_svn_limited() {
    let mut tpm = Tpm::new();
    let context_load = |hierarchy: u32, protected_len: usize| {
        let mut params = 1u64.to_be_bytes().to_vec(); // sequence
        params.extend_from_slice(&0x8000_0000u32.to_be_bytes()); // savedHandle
        params.extend_from_slice(&hierarchy.to_be_bytes());
        let mut blob = (64u16).to_be_bytes().to_vec(); // integrity (SHA-512)
        blob.extend_from_slice(&[0x11; 64]);
        blob.extend_from_slice(&vec![0x22; protected_len]);
        let mut sized = (blob.len() as u16).to_be_bytes().to_vec();
        sized.extend_from_slice(&blob);
        params.extend_from_slice(&sized);
        build(0x8001, 0x0000_0161, &[], None, &params)
    };
    let unavailable: [(u32, Fmt1); 2] = [
        (
            svn(Handle::RH_SVN_OWNER_BASE, CURRENT_SVN + 1).0,
            TpmRc::SVN_LIMITED,
        ),
        (Handle::SVN_NULL_LAST.0, TpmRc::SVN_LIMITED),
    ];
    for protected_len in [8, 9] {
        for (handle, rc) in unavailable {
            let cmd = context_load(handle, protected_len);
            assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc.get());
        }
        for handle in [Handle::RH_OWNER, FW_OWNER, svn(Handle::RH_SVN_NULL_BASE, 0)] {
            let cmd = context_load(handle.0, protected_len);
            assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_p(TpmRc::INTEGRITY, 1));
        }
    }
    // Fewer bytes than the fingerprint fail before the integrity check.
    let cmd = context_load(Handle::SVN_NULL_LAST.0, 7);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_p(TpmRc::SIZE, 1));
}

/// `TPM2_CertifyCreation` recomputes the creation ticket for the ticket's hierarchy before it
/// compares it (TPM 2.0 Part 3, TPM2_CertifyCreation: "The TPM will validate that the ticket was
/// produced by the TPM"), so an unavailable SVN-limited ticket hierarchy fails with
/// `TPM_RC_SVN_LIMITED`, and an available limited one with a forged digest with
/// `TPM_RC_TICKET + P4`.
#[test]
fn certify_creation_ticket_of_limited_hierarchy() {
    let mut tpm = Tpm::new();
    let (object, _) = crate::_common::try_create_owner_primary(
        &mut tpm,
        crate::_common::get_ecc_signing_key_template(),
    )
    .expect("signing key");
    for (handle, rc) in [
        (
            svn(Handle::RH_SVN_OWNER_BASE, CURRENT_SVN + 1),
            TpmRc::SVN_LIMITED.to_rc().get(),
        ),
        (FW_OWNER, rc_p(TpmRc::TICKET, 4)),
        (
            svn(Handle::RH_SVN_NULL_BASE, CURRENT_SVN),
            rc_p(TpmRc::TICKET, 4),
        ),
    ] {
        let mut params = vec![0, 0]; // qualifyingData
        params.extend_from_slice(&[0, 0]); // creationHash
        params.extend_from_slice(&[0x00, 0x10]); // inScheme: TPM_ALG_NULL
        params.extend_from_slice(&[0x80, 0x21]); // creationTicket: TPM_ST_CREATION
        params.extend_from_slice(&handle.0.to_be_bytes());
        params.extend_from_slice(&[0, 0]); // empty digest
        let cmd = build(
            0x8002,
            0x0000_014A,
            &[Handle::RH_NULL.0, object.0],
            Some(&PW_SESSION),
            &params,
        );
        assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc, "{handle:?}");
    }
}

/// `TPM2_PolicyAuthorize` recomputes the verification ticket with the proof of the ticket's
/// hierarchy before it compares it (TCG reference: `TicketComputeVerified()` ->
/// `HierarchyGetProof()`), so an SVN-limited ticket hierarchy beyond the firmware's SVN fails
/// with `TPM_RC_SVN_LIMITED` instead of `TPM_RC_VALUE` on the ticket. Found by differential
/// fuzzing.
#[test]
fn policy_authorize_ticket_of_unavailable_hierarchy_fails() {
    let response_code = |rsp: &[u8]| u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    let mut tpm = testing::tpm::Tpm::with_seed(testing::seed::ReferenceSeed {
        pid: 4242,
        realtime_ms: 1000000,
    });

    // Round 0: TPM2_CreatePrimary.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x02, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x01, 0x31, 0x40, 0x00, 0x00, 0x07,
            0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x23, 0x00, 0x0b, 0x00, 0x04, 0x00,
            0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    assert_eq!(response_code(&rsp), 0x0);

    // Round 1: TPM2_ChangeEPS.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x02, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x01, 0x24, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80,
            0x21, 0x40, 0x00, 0x00, 0x07, 0x00, 0x40, 0x5f, 0x23, 0x3c, 0x95, 0x0a, 0x53, 0x68,
            0x7c, 0x43, 0xc2, 0x38, 0x05, 0xed, 0xdd, 0xff, 0xb2, 0xfa, 0x74, 0xb0, 0x0c, 0xea,
            0x6a, 0x52, 0xa1, 0xfd, 0xcb, 0x77, 0x4b, 0x1a, 0x94, 0x4f, 0xac, 0x15, 0x61, 0xf7,
            0x46, 0xbd, 0x44, 0xc4, 0xd9, 0x4f, 0xda, 0x0c, 0xdd, 0x09, 0xb2, 0x96, 0x0d, 0xe5,
            0x8f, 0x32, 0x6b, 0x76, 0x6f, 0xcb, 0x25, 0xe6, 0x35, 0xe0, 0xf5, 0x07, 0x8e, 0xc5,
            0xf9,
        ],
    );
    assert_eq!(response_code(&rsp), 0x184);

    // Round 2: TPM2_FlushContext.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x65, 0x80, 0x00, 0x00, 0x00,
        ],
    );
    assert_eq!(response_code(&rsp), 0x0);

    // Round 3: TPM2_StartAuthSession.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07,
            0x40, 0x00, 0x00, 0x07, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00,
            0x0b,
        ],
    );
    assert_eq!(response_code(&rsp), 0x0);

    // Round 4: TPM2_PolicyAuthorize with a ticket of the SVN-limited Endorsement hierarchy of
    // SVN 11 (`0x4002000B`), beyond the firmware's SVN 10.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x01, 0x6a, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x0b, 0x37, 0x67,
            0x57, 0x64, 0x3b, 0x60, 0x75, 0x98, 0x42, 0xfa, 0x13, 0x62, 0x70, 0xa9, 0x38, 0xb9,
            0x45, 0xf2, 0xc8, 0x22, 0x5f, 0x6d, 0x5c, 0x70, 0x68, 0x9a, 0xa6, 0xb6, 0xf4, 0xb7,
            0xe5, 0x1d, 0x80, 0x22, 0x40, 0x02, 0x00, 0x0b, 0x00, 0x40, 0x00, 0x00, 0x11, 0x81,
            0x02, 0x00, 0x81, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x23,
            0x00, 0x0b, 0x00, 0x04, 0x00, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0x18, 0x00, 0x2a,
            0x01, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x3c, 0x81, 0x00, 0x01, 0x81, 0xb6, 0xc6, 0xa0, 0x8c, 0x5a, 0x84,
            0x0e, 0x00, 0x00, 0x00,
        ],
    );
    assert_eq!(response_code(&rsp), TpmRc::SVN_LIMITED.to_rc().get());
}
