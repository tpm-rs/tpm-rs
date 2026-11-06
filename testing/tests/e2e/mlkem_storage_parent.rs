//! Restricted ML-KEM decryption keys as storage parents and protectors (TPM 2.0 v185, ML-KEM
//! Labeled KEM: `seed = KDFa(nameAlg, K, label, ciphertext, publicKey, digestBits)`, the
//! encrypted secret is the ML-KEM ciphertext): children are created and loaded,
//! TPM2_MakeCredential/TPM2_ActivateCredential round-trip and accept client-made credentials,
//! TPM2_Import accepts client-made duplicates, TPM2_Duplicate wraps to an ML-KEM new parent,
//! and an ML-KEM key salts TPM2_StartAuthSession; tampered or mis-sized encrypted secrets are
//! rejected.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{ActivateCredential, Create, Import, MakeCredential};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bIdObject,
    Tpm2bName, Tpm2bPrivate, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiMlkemParms,
    TpmlPcrSelection, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSensitive, TpmtSigScheme,
    TpmuSensitiveComposite,
};

/// The credential protected in this file.
const CREDENTIAL: &[u8] = b"post-quantum credential";

/// Creates a primary ML-KEM storage key; returns its handle and public area.
fn mlkem_parent(sim: &mut Tpm, parameter_set: TpmiMlkemParms) -> (Handle, TpmtPublic<'static>) {
    create_primary_returning_public(sim, mlkem_storage_public(parameter_set), &[])
}

/// Template of an ECDSA P-256 signing key.
fn ecdsa_template() -> TpmtPublic<'static> {
    ecc_template(
        base_attrs() | TpmaObject::SIGN_ENCRYPT,
        Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
    )
}

/// TPM2_ActivateCredential of `credential_blob`/`secret` for the object `activate` protected by
/// `key`; returns the credential or the response code.
fn activate_credential(
    sim: &mut Tpm,
    activate: Handle,
    key: Handle,
    credential_blob: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, u32> {
    execute_with_password_sessions(
        sim,
        &ActivateCredential {
            activate_handle: activate,
            key_handle: key,
            credential_blob: Tpm2bIdObject::from_bytes(leak_bytes(credential_blob)).unwrap(),
            secret: Tpm2bEncryptedSecret::from_bytes(leak_bytes(secret)).unwrap(),
        },
        2,
        &[],
    )
    .map(|rsp| rsp.cert_info.get_buffer().to_vec())
}

/// A client-made credential for the object named `object_name`, protected by the ML-KEM key
/// `protector` (Labeled KEM "IDENTITY" and the outer wrapper keyed by its seed); returns
/// `(credentialBlob, secret)`.
fn client_credential(protector: &TpmtPublic<'_>, object_name: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (seed, ciphertext) = mlkem_labeled_encapsulate(protector, b"IDENTITY");
    let mut inner = (CREDENTIAL.len() as u16).to_be_bytes().to_vec();
    inner.extend_from_slice(CREDENTIAL);
    let blob = outer_wrap_with_seed(
        protector.name_alg.unwrap(),
        AES128_CFB,
        &seed,
        object_name,
        &inner,
    );
    (blob, ciphertext)
}

/// An ML-KEM storage key of every parameter set is a parent: an ECDSA child is created under
/// it, loads and signs.
#[test]
fn storage_parent_creates_and_loads_children() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (parent, _) = mlkem_parent(&mut sim, parameter_set);
        let (private, public) = create_child(&mut sim, parent, ecdsa_template(), b"");
        let (child, _) = load_child(&mut sim, parent, private, public);
        sign_unwrap(
            &mut sim,
            child,
            &[0x33; 32],
            TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
        );
        flush_context(&mut sim, child).unwrap();
        flush_context(&mut sim, parent).unwrap();
    }
}

/// An ML-KEM storage key is a parent of ML-KEM children (an ML-KEM storage key under an
/// ML-KEM storage key, and an ML-KEM decryption key under that).
#[test]
fn storage_parent_hierarchy_of_mlkem_keys() {
    let mut sim = Tpm::new();
    let (root, _) = mlkem_parent(&mut sim, TpmiMlkemParms::Mlkem1024);
    let (private, public) = create_child(
        &mut sim,
        root,
        mlkem_storage_public(TpmiMlkemParms::Mlkem768),
        b"",
    );
    let (intermediate, _) = load_child(&mut sim, root, private, public);
    let (private, public) = create_child(
        &mut sim,
        intermediate,
        mlkem_decryption_public(TpmiMlkemParms::Mlkem512),
        b"",
    );
    load_child(&mut sim, intermediate, private, public);
}

/// TPM2_MakeCredential with an ML-KEM protector of every parameter set returns an ML-KEM
/// ciphertext as the secret, and TPM2_ActivateCredential recovers the credential.
#[test]
fn make_and_activate_credential_round_trip() {
    let mut sim = Tpm::new();
    let (object, _) = create_primary_returning_public(&mut sim, ecdsa_template(), &[]);
    let object_name = read_public_name(&mut sim, object);
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (protector, _) = mlkem_parent(&mut sim, parameter_set);
        let rsp = run_command(
            &mut sim,
            MakeCredential {
                handle: protector,
                credential: Tpm2bDigest::from_bytes(CREDENTIAL).unwrap(),
                object_name,
            },
        )
        .unwrap();
        assert_eq!(rsp.secret.get_size() as usize, parameter_set.ct_bytes());
        assert_eq!(
            activate_credential(
                &mut sim,
                object,
                protector,
                rsp.credential_blob.get_buffer(),
                rsp.secret.get_buffer(),
            )
            .unwrap(),
            CREDENTIAL,
            "{parameter_set:?}"
        );
        flush_context(&mut sim, protector).unwrap();
    }
}

/// TPM2_ActivateCredential recovers a credential made client-side with the ML-KEM Labeled KEM
/// ("IDENTITY") to the protector's encapsulation key.
#[test]
fn activate_credential_accepts_client_credential() {
    let mut sim = Tpm::new();
    let (object, _) = create_primary_returning_public(&mut sim, ecdsa_template(), &[]);
    let object_name = read_public_name(&mut sim, object);
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (protector, public) = mlkem_parent(&mut sim, parameter_set);
        let (blob, secret) = client_credential(&public, object_name.get_buffer());
        assert_eq!(
            activate_credential(&mut sim, object, protector, &blob, &secret).unwrap(),
            CREDENTIAL,
            "{parameter_set:?}"
        );
        flush_context(&mut sim, protector).unwrap();
    }
}

/// TPM2_ActivateCredential with a tampered ML-KEM ciphertext decapsulates to another seed
/// (implicit rejection), so the integrity check fails with TPM_RC_INTEGRITY + P1; a ciphertext
/// of the wrong size fails with TPM_RC_PARMS + P2 (secret).
#[test]
fn activate_credential_rejects_bad_secrets() {
    let mut sim = Tpm::new();
    let (object, _) = create_primary_returning_public(&mut sim, ecdsa_template(), &[]);
    let object_name = read_public_name(&mut sim, object);
    let (protector, public) = mlkem_parent(&mut sim, TpmiMlkemParms::Mlkem768);
    let (blob, secret) = client_credential(&public, object_name.get_buffer());
    let mut tampered = secret.clone();
    tampered[0] ^= 0x80;
    assert_eq!(
        activate_credential(&mut sim, object, protector, &blob, &tampered),
        Err(TpmRc::INTEGRITY.with(Position::parameter(1)).get())
    );
    assert_eq!(
        activate_credential(
            &mut sim,
            object,
            protector,
            &blob,
            &secret[..secret.len() - 1]
        ),
        Err(TpmRc::PARMS.with(Position::parameter(2)).get())
    );
    // The untampered secret still works.
    assert_eq!(
        activate_credential(&mut sim, object, protector, &blob, &secret).unwrap(),
        CREDENTIAL
    );
}

/// TPM2_Import under an ML-KEM storage parent accepts a duplicate made client-side (Labeled KEM
/// "DUPLICATE" seed, outer wrapper, no inner wrapper) of an ECC key, which then loads with the
/// same Name and signs.
#[test]
fn import_accepts_client_duplicate() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (parent, parent_public) = mlkem_parent(&mut sim, parameter_set);
        let public = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
        let name = public_name(&public);
        let sensitive = TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::default(),
            sensitive: TpmuSensitiveComposite::Ecc(
                tpm2::Tpm2bEccParameter::from_bytes(ECC_D).unwrap(),
            ),
        };
        let sensitive = marshal_to_vec(&sensitive);
        let mut inner = (sensitive.len() as u16).to_be_bytes().to_vec();
        inner.extend_from_slice(&sensitive);
        let (seed, ciphertext) = mlkem_labeled_encapsulate(&parent_public, b"DUPLICATE");
        let duplicate = outer_wrap_with_seed(TpmiAlgHash::Sha256, AES128_CFB, &seed, &name, &inner);
        let rsp = execute_with_password_sessions(
            &mut sim,
            &Import {
                parent_handle: parent,
                encryption_key: Tpm2bData::default(),
                object_public: Tpm2b(public),
                duplicate: Tpm2bPrivate::from_bytes(leak_bytes(&duplicate)).unwrap(),
                in_sym_seed: Tpm2bEncryptedSecret::from_bytes(leak_bytes(&ciphertext)).unwrap(),
                symmetric_alg: None,
            },
            1,
            &[],
        )
        .unwrap_or_else(|rc| panic!("{parameter_set:?}: Import failed: {rc:#x}"));
        let (child, loaded_name) = load_child(&mut sim, parent, rsp.out_private, Tpm2b(public));
        assert_eq!(loaded_name, name);
        sign_unwrap(
            &mut sim,
            child,
            &[0x44; 32],
            TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
        );
        flush_context(&mut sim, child).unwrap();
        flush_context(&mut sim, parent).unwrap();
    }
}

/// TPM2_Duplicate to an ML-KEM new parent (outer wrapper only) returns an ML-KEM ciphertext as
/// outSymSeed, and TPM2_Import under that parent loads the object with the same Name.
#[test]
fn duplicate_to_mlkem_parent_and_import() {
    let mut sim = Tpm::new();
    let (new_parent, _) = mlkem_parent(&mut sim, TpmiMlkemParms::Mlkem1024);
    let (object, object_public) =
        create_primary_returning_public(&mut sim, duplicable_ecdsa_template(), &[]);
    let object_name = read_public_name(&mut sim, object);
    let rsp = duplicate(&mut sim, object, new_parent, None)
        .unwrap_or_else(|rc| panic!("Duplicate failed: {rc:#x}"));
    assert_eq!(rsp.out_sym_seed.get_size(), 1568);
    let imported = execute_with_password_sessions(
        &mut sim,
        &Import {
            parent_handle: new_parent,
            encryption_key: Tpm2bData::default(),
            object_public: Tpm2b(object_public),
            duplicate: rsp.duplicate,
            in_sym_seed: rsp.out_sym_seed,
            symmetric_alg: None,
        },
        1,
        &[],
    )
    .unwrap_or_else(|rc| panic!("Import failed: {rc:#x}"));
    let (_, name) = load_child(
        &mut sim,
        new_parent,
        imported.out_private,
        Tpm2b(object_public),
    );
    assert_eq!(name, object_name.get_buffer());
}

/// An ECDSA signing key that can be duplicated with a PolicyCommandCode(TPM_CC_Duplicate)
/// policy (fixedTPM and fixedParent CLEAR).
fn duplicable_ecdsa_template() -> TpmtPublic<'static> {
    let mut template = ecdsa_template();
    template
        .object_attributes
        .remove(TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT);
    template.auth_policy = Tpm2bDigest::from_bytes(leak_bytes(&policy_command_code_digest(
        tpm2::TpmCc::Duplicate,
    )))
    .unwrap();
    template
}

/// The SHA-256 policy digest of PolicyCommandCode(`code`) on a fresh session.
fn policy_command_code_digest(code: tpm2::TpmCc) -> Vec<u8> {
    sha256(&[
        &[0u8; 32],
        &tpm2::TpmCc::PolicyCommandCode.code().to_be_bytes(),
        &code.code().to_be_bytes(),
    ])
}

/// TPM2_StartAuthSession salted by an ML-KEM key of every parameter set (Labeled KEM "SECRET")
/// yields the session key the client derives from its salt: the session authorizes TPM2_Create
/// under the ML-KEM parent with an HMAC.
#[test]
fn salted_session_with_mlkem_key() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (parent, public) = mlkem_parent(&mut sim, parameter_set);
        let session = start_mlkem_salted_session(&mut sim, parent, &public)
            .unwrap_or_else(|rc| panic!("{parameter_set:?}: StartAuthSession failed: {rc:#x}"));
        create_with_session(&mut sim, parent, session.clone())
            .unwrap_or_else(|rc| panic!("{parameter_set:?}: Create failed: {rc:#x}"));
        flush_context(&mut sim, session.session_handle).unwrap();
        flush_context(&mut sim, parent).unwrap();
    }
}

/// TPM2_Create of an ECDSA key under `parent` (empty authValue) authorized by `session`.
fn create_with_session(sim: &mut Tpm, parent: Handle, session: ActiveSession) -> Result<(), u32> {
    let cmd = Create {
        parent_handle: parent,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(ecdsa_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let parent_name: Tpm2bName = read_public_name(sim, parent);
    execute_with_hmac_sessions(
        sim,
        &cmd,
        &[parent_name.get_buffer()],
        &mut [session],
        &[&[]],
    )
    .map(|_| ())
}

/// A tampered ML-KEM encrypted salt decapsulates to another salt (implicit rejection): the
/// session starts, but the client's HMAC fails with TPM_RC_BAD_AUTH + S1 (the parent is noDA);
/// an encrypted salt of the wrong size fails with TPM_RC_VALUE + P2 (TPM2_StartAuthSession reports
/// every failure to recover the salt as TPM_RC_VALUE).
#[test]
fn salted_session_rejects_bad_encrypted_salt() {
    let mut sim = Tpm::new();
    let (parent, public) = mlkem_parent(&mut sim, TpmiMlkemParms::Mlkem512);
    let (salt, mut ciphertext) = mlkem_labeled_encapsulate(&public, b"SECRET");
    assert_eq!(
        start_salted_session_with_salt(&mut sim, parent, &salt, &ciphertext[..700]).map(|_| ()),
        Err(TpmRc::VALUE.with(Position::parameter(2)).get())
    );
    ciphertext[5] ^= 0x01;
    let session = start_salted_session_with_salt(&mut sim, parent, &salt, &ciphertext).unwrap();
    assert_eq!(
        create_with_session(&mut sim, parent, session),
        Err(TpmRc::BAD_AUTH.with(Position::session(1)).get())
    );
}
