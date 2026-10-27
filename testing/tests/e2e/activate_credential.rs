//! TPM2_ActivateCredential: credential blob integrity, key handle and protector key type checks.

use crate::_common::{
    AES128_CFB, build_pw_cmd, command_rc, create_and_load, ecc_sign_template, exec_command,
    execute_with_hmac_sessions, execute_with_password_sessions, get_ecc_ek_template,
    get_ecc_sign_restricted_template, get_ecc_srk_template, leak_bytes,
    load_stripped_ecc_storage_key, owner_srk, pw, rc_h, rc_of, rc_p, read_public, rsa_public, run,
    start_auth_session, storage_attrs, try_create_owner_primary,
};
use testing::tpm::Tpm;
use tpm2::commands::{ActivateCredential, CreatePrimary, MakeCredential, PolicySecret};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bIdObject,
    Tpm2bName, Tpm2bSensitiveData, TpmSe, TpmaObject, TpmiAlgHash, TpmsSensitiveCreate, TpmtPublic,
};

/// ActivateCredential of a credential blob with a flipped byte (EK policy session) fails with TPM_RC_INTEGRITY.
#[test]
fn corrupted_credential_blob_integrity() {
    let mut sim = Tpm::new();

    // 1. Create ECC EK under Endorsement Hierarchy
    let ek_pub = get_ecc_ek_template();
    let in_public = tpm2::Tpm2b(ek_pub);
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let create_primary_ek = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let ek_resp = execute_with_password_sessions(&mut sim, &create_primary_ek, 1, &[])
        .expect("could not generate EK");

    // 2. Create ECC SRK under Owner Hierarchy
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let srk_resp = execute_with_password_sessions(&mut sim, &create_primary_srk, 1, &[])
        .expect("could not generate SRK");

    // 3. MakeCredential
    let secret = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let mc = MakeCredential {
        handle: ek_resp.object_handle,
        credential: secret,
        object_name: srk_resp.name,
    };
    let mc_resp =
        execute_with_password_sessions(&mut sim, &mc, 0, &[]).expect("MakeCredential failed");

    // Corrupt the credential blob (flip a byte)
    let mut corrupted_blob_bytes = mc_resp.credential_blob.get_buffer().to_vec();
    if corrupted_blob_bytes.len() > 10 {
        corrupted_blob_bytes[10] ^= 0xFF;
    }
    let corrupted_blob = tpm2::Tpm2bIdObject::from_bytes(&corrupted_blob_bytes).unwrap();

    // 4. ActivateCredential with corrupted blob
    // Policy session to satisfy EK policy
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start policy session failed");

    let policy_secret_cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_secret_cmd, 1, &[])
        .expect("PolicySecret failed");

    let hmac_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start HMAC session failed");

    let ac_cmd = ActivateCredential {
        activate_handle: srk_resp.object_handle,
        key_handle: ek_resp.object_handle,
        credential_blob: corrupted_blob,
        secret: mc_resp.secret,
    };

    let mut sessions = [hmac_session, active_session];
    let res = execute_with_hmac_sessions(
        &mut sim,
        &ac_cmd,
        &[srk_resp.name.get_buffer(), ek_resp.name.get_buffer()], // Names
        &mut sessions,
        &[&[], &[]],
    );

    // C ActivateCredential.c:69-70 adds RC_ActivateCredential_credentialBlob
    // (P1) to the CredentialToSecret INTEGRITY error.
    assert_eq!(
        res.err().unwrap(),
        TpmRc::INTEGRITY.with(Position::parameter(1)).get()
    );
}

/// ActivateCredential with a non-existent key handle fails with TPM_RC_REFERENCE_H1.
#[test]
fn missing_key_handle_rejected() {
    let mut sim = Tpm::new();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let srk_resp = execute_with_password_sessions(&mut sim, &create_primary_srk, 1, &[])
        .expect("could not generate SRK");

    // 2. Call ActivateCredential with invalid key handle
    let ac_cmd = ActivateCredential {
        activate_handle: srk_resp.object_handle,
        key_handle: Handle::TRANSIENT_LAST, // Invalid handle
        credential_blob: tpm2::Tpm2bIdObject::default(),
        secret: tpm2::Tpm2bEncryptedSecret::default(),
    };
    let res = execute_with_password_sessions(&mut sim, &ac_cmd, 0, &[]);
    assert_eq!(res.err().unwrap(), TpmRc::REFERENCE_H1.get());
}

/// ActivateCredential with a sign-only key fails with TPM_RC_TYPE + H2.
#[test]
fn sign_only_key_rejected() {
    let mut sim = Tpm::new();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create a key that is restricted sign-only (not decrypt)
    let protector_template = get_ecc_sign_restricted_template();
    let in_public_p = tpm2::Tpm2b(protector_template);
    let create_primary_p = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_p,
        ..Default::default()
    };
    let p_resp = execute_with_password_sessions(&mut sim, &create_primary_p, 1, &[])
        .expect("could not generate key");

    // 2. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let srk_resp = execute_with_password_sessions(&mut sim, &create_primary_srk, 1, &[])
        .expect("could not generate SRK");

    // 3. Call ActivateCredential
    let ac_cmd = ActivateCredential {
        activate_handle: srk_resp.object_handle,
        key_handle: p_resp.object_handle, // Sign key as decryption key
        credential_blob: tpm2::Tpm2bIdObject::default(),
        secret: tpm2::Tpm2bEncryptedSecret::default(),
    };
    // Both activateHandle (ADMIN) and keyHandle (USER) need a session. C
    // ActivateCredential.c:41-44 rejects a non-decrypt key with TYPE+H2.
    let res = execute_with_password_sessions(&mut sim, &ac_cmd, 2, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::TYPE.with(Position::handle(2)).get()
    );
}

/// Make/ActivateCredential work with an ECC protector whose x has a stripped leading zero; credential size, integrity and key-type errors.
#[test]
fn stripped_ecc_protector_and_error_codes() {
    let mut sim = Tpm::new();
    // ECC protector whose public x coordinate has a stripped leading zero byte; it is imported
    // with its private key (d = 379) so that it can be used on both sides.
    let srk = owner_srk(&mut sim);
    let ecc_ek = load_stripped_ecc_storage_key(&mut sim, srk);
    let ek_name = read_public(&mut sim, ecc_ek).unwrap().name;
    let mc = |sim: &mut Tpm, handle: Handle, cred: &[u8], name: Tpm2bName<'static>| {
        run(
            sim,
            &MakeCredential {
                handle,
                credential: Tpm2bDigest::from_bytes(leak_bytes(cred)).unwrap(),
                object_name: name,
            },
            0,
        )
    };
    let made = mc(&mut sim, ecc_ek, &[1; 16], ek_name)
        .expect("stripped ECC coordinate must be accepted by MakeCredential");
    // The credential size is validated against the key's nameAlg.
    assert_eq!(
        mc(&mut sim, ecc_ek, &[1; 33], ek_name).unwrap_err(),
        rc_p(TpmRc::SIZE, 1)
    );
    // ActivateCredential with the same key (activateHandle = the key itself).
    let activated = run(
        &mut sim,
        &ActivateCredential {
            activate_handle: ecc_ek,
            key_handle: ecc_ek,
            credential_blob: made.credential_blob,
            secret: made.secret,
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
    let ac = |sim: &mut Tpm, key: Handle, blob: &[u8], secret: &[u8]| {
        command_rc(
            sim,
            &ActivateCredential {
                activate_handle: signer,
                key_handle: key,
                credential_blob: Tpm2bIdObject::from_bytes(leak_bytes(blob)).unwrap(),
                secret: Tpm2bEncryptedSecret::from_bytes(leak_bytes(secret)).unwrap(),
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
    let made = run(
        &mut sim,
        &MakeCredential {
            handle: srk,
            credential: Tpm2bDigest::from_bytes(&[5; 20]).unwrap(),
            object_name: signer_name,
        },
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

/// ActivateCredential with a symmetric protector key fails with TPM_RC_TYPE on keyHandle.
///
/// `TPM2_ActivateCredential` with a symmetric protector key fails with
/// `TPM_RC_TYPE` on `keyHandle`.
#[test]
fn symmetric_protector_rejected() {
    let mut sim = Tpm::new();

    // 1. Target object (to activate credential)
    let (target, _) = try_create_owner_primary(
        &mut sim,
        rsa_public(
            TpmiAlgHash::Sha256,
            TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::FIXED_PARENT
                | TpmaObject::FIXED_TPM,
            &[],
            None,
        ),
    )
    .unwrap();

    // 2. A symmetric key as protector key
    let (protector_sym, _) = try_create_owner_primary(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: storage_attrs(),
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
        },
    )
    .unwrap();

    // 3. Call ActivateCredential
    let res = exec_command(
        &mut sim,
        &ActivateCredential {
            activate_handle: target,
            key_handle: protector_sym,
            credential_blob: Tpm2bIdObject::default(),
            secret: Tpm2bEncryptedSecret::default(),
        },
        &[pw(), pw()],
    );
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(2)).get()));
}

/// MakeCredential and ActivateCredential protect the credential in CFB mode even when the
/// protector's public area names another mode (here AES-128 CTR): the credential round-trips.
/// `tpm-rs` used the protector's mode and failed with `TPM_RC_FAILURE` (found by differential
/// fuzzing). TPM 2.0 Part 1, "Credential Protection": "encIdentity := CFB_ekSymAlg (symKey, 0,
/// CV)", where "CFB_ekSymAlg | is symmetric encryption in CFB mode using the symmetric algorithm
/// of the key serving as "EK"".
#[test]
fn credential_round_trips_under_ctr_mode_protector() {
    let mut sim = Tpm::new();
    let mut template = get_ecc_srk_template();
    if let PublicParmsAndId::Ecc(parms, _) = &mut template.parms_and_id {
        parms.symmetric = Some(tpm2::TpmtSymDefObject {
            alg: tpm2::AlgSym::Aes128,
            mode: Some(tpm2::TpmiAlgSymMode::Cipher(tpm2::TpmiAlgCipherMode::Ctr)),
        });
    }
    let key = execute_with_password_sessions(
        &mut sim,
        &CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: tpm2::Tpm2b(template),
            ..Default::default()
        },
        1,
        &[],
    )
    .expect("CreatePrimary failed");

    let credential = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let made = execute_with_password_sessions(
        &mut sim,
        &MakeCredential {
            handle: key.object_handle,
            credential,
            object_name: key.name,
        },
        0,
        &[],
    )
    .expect("MakeCredential failed");

    let activated = execute_with_password_sessions(
        &mut sim,
        &ActivateCredential {
            activate_handle: key.object_handle,
            key_handle: key.object_handle,
            credential_blob: made.credential_blob,
            secret: made.secret,
        },
        2,
        &[],
    )
    .expect("ActivateCredential failed");
    assert_eq!(activated.cert_info.get_buffer(), b"Secrets!!!");
}

/// A credentialBlob whose `integrityHMAC` is one octet larger than the largest digest of the TPM
/// is `TPM_RC_SIZE + RC_ActivateCredential_credentialBlob`: the integrity value is unmarshaled as
/// a `TPM2B_DIGEST` (TPM 2.0 Part 2, Table "Definition of TPM2B_DIGEST Structure":
/// "buffer[size]{:sizeof(TPMU_HA)}" and "#TPM_RC_SIZE"), before it is compared with the expected
/// HMAC (`TPM_RC_INTEGRITY`).
#[test]
fn integrity_larger_than_largest_digest_is_size_error() {
    const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
    const LARGEST_DIGEST: usize = 64;
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let name = read_public(&mut sim, srk).expect("ReadPublic").name;
    let made = execute_with_password_sessions(
        &mut sim,
        &MakeCredential {
            handle: srk,
            credential: Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap(),
            object_name: name,
        },
        0,
        &[],
    )
    .expect("MakeCredential failed");
    // Replace the integrity HMAC of the valid blob by LARGEST_DIGEST + 1 octets.
    let blob = made.credential_blob.get_buffer();
    let integrity_len = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    let mut forged = ((LARGEST_DIGEST + 1) as u16).to_be_bytes().to_vec();
    forged.extend_from_slice(&[0x5a; LARGEST_DIGEST + 1]);
    forged.extend_from_slice(&blob[2 + integrity_len..]);
    let secret = made.secret.get_buffer();
    let mut params = (forged.len() as u16).to_be_bytes().to_vec();
    params.extend_from_slice(&forged);
    params.extend_from_slice(&(secret.len() as u16).to_be_bytes());
    params.extend_from_slice(secret);
    let cmd = build_pw_cmd(TPM_CC_ACTIVATE_CREDENTIAL, &[srk.0, srk.0], 2, &params);
    assert_eq!(rc_of(&sim.send_command(0, &cmd)), rc_p(TpmRc::SIZE, 1));
}

/// A credentialBlob whose size is one octet larger than `sizeof(TPMS_ID_OBJECT)` is
/// `TPM_RC_SIZE + RC_ActivateCredential_credentialBlob` before its octets are read, even when
/// the command is too short to hold them (TPM 2.0 Part 2, Table "Definition of TPM2B_ID_OBJECT
/// Structure": "credential[size]{:sizeof(TPMS_ID_OBJECT)}"; a `TPMS_ID_OBJECT` is two
/// `TPM2B_DIGEST`s).
#[test]
fn credential_blob_larger_than_id_object_is_size_error() {
    const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
    const SIZEOF_TPMS_ID_OBJECT: usize = 2 * (2 + 64);
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    // credentialBlob.size = sizeof(TPMS_ID_OBJECT) + 1, followed by only four octets.
    let mut params = ((SIZEOF_TPMS_ID_OBJECT + 1) as u16).to_be_bytes().to_vec();
    params.extend_from_slice(&[0x01, 0x00, 0x28, 0x00]);
    let cmd = build_pw_cmd(TPM_CC_ACTIVATE_CREDENTIAL, &[srk.0, srk.0], 2, &params);
    assert_eq!(rc_of(&sim.send_command(0, &cmd)), rc_p(TpmRc::SIZE, 1));
}
