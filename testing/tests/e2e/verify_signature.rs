//! TPM2_VerifySignature: signature/scheme validation and verification tickets.

use crate::_common::{
    CC_VERIFY_SIGNATURE, CLIENT_CRYPTO, CONTEXT_INTEGRITY_DIGEST_SIZE, ECC_D, ECC_X, ECC_Y, RSA_N,
    base_attrs, create_primary_returning_public, create_primary_with_auth_in,
    create_primary_with_data_handle, ecc_storage_template_derived, ecc_template, execute_sign,
    execute_with_password_sessions, flush_context, hmac_key_and_signature, keyed_hash_public,
    leak_bytes, load_external_public, make_ecc_public_area, make_keyed_hash_public_area,
    make_rsa_public_area, marshal_to_vec, random_key, rc_at, read_public_name,
    rsa_public_with_symmetric, sdo_user, send_key_command, sha256_array, sign, start_auth_session,
    verify_hmac_params, verify_signature,
};
use sha2::{Digest as _, Sha256};
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, LoadExternal, PolicyAuthorize};
#[allow(deprecated)]
use tpm2::commands::{Sign, VerifySignature};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmCc, TpmSe, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits,
    TpmlPcrSelection, TpmsRsaParms, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtRsaScheme,
    TpmtSensitive, TpmtSigScheme, TpmtSignature, TpmtTkHashcheck, TpmuSensitiveComposite, *,
};

/// ECC signature errors: invalid ECDSA values are `TPM_RC_SIGNATURE + RC_P2`, and an ECDAA
/// signature can't be verified (`TPM_RC_SCHEME + RC_P2`, as in `CryptEccValidateSignature`).
#[test]
fn ecc_signature_errors_and_ecdaa_rejected() {
    let mut sim = Tpm::new();
    let key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let digest: &'static [u8] = leak_bytes(&[0x33; 32]);
    let good = sign(&mut sim, key, b"", digest, None).expect("ECDSA sign failed");
    verify_signature(&mut sim, key, digest, good).expect("valid ECDSA must verify");

    // The same (r, s) presented as an ECDAA signature must be rejected with SCHEME + P2.
    let (r, s) = match &good {
        TpmtSignature::Ecdsa(sig) => (sig.signature_r, sig.signature_s),
        _ => unreachable!(),
    };
    let ecdaa = TpmtSignature::Ecdaa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: r,
        signature_s: s,
    });
    assert_eq!(
        verify_signature(&mut sim, key, digest, ecdaa).unwrap_err(),
        rc_at(TpmRc::SCHEME, Position::parameter(2))
    );

    // r == 0 -> TPM_RC_SIGNATURE + RC_P2 (not RC_H2).
    let zero_r = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: Tpm2bEccParameter::default(),
        signature_s: s,
    });
    assert_eq!(
        verify_signature(&mut sim, key, digest, zero_r).unwrap_err(),
        rc_at(TpmRc::SIGNATURE, Position::parameter(2))
    );
}

/// Signature validation errors carry `RC_VerifySignature_signature` (parameter 2); a key
/// without `sign` is `TPM_RC_ATTRIBUTES + RC_H1`.
#[test]
fn hmac_signature_error_positions() {
    let mut sim = Tpm::new();
    let digest: &'static [u8] = leak_bytes(&[0x22; 32]);
    let (key, signature) = hmac_key_and_signature(&mut sim, Handle::RH_OWNER, digest);

    // Wrong HMAC value -> TPM_RC_SIGNATURE + RC_P2.
    let bad_sig = match signature {
        TpmtSignature::Hmac(ha) => {
            let mut bytes = ha.digest().to_vec();
            bytes[0] ^= 1;
            TpmtSignature::Hmac(TpmtHa::new(ha.hash_alg(), leak_bytes(&bytes)).unwrap())
        }
        _ => unreachable!(),
    };
    assert_eq!(
        verify_signature(&mut sim, key, digest, bad_sig).unwrap_err(),
        rc_at(TpmRc::SIGNATURE, Position::parameter(2))
    );

    // ECDSA signature for an HMAC key -> TPM_RC_SCHEME + RC_P2.
    let ecdsa = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
        signature_s: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
    });
    assert_eq!(
        verify_signature(&mut sim, key, digest, ecdsa).unwrap_err(),
        rc_at(TpmRc::SCHEME, Position::parameter(2))
    );

    // A decrypt-only key is not a signing key -> TPM_RC_ATTRIBUTES + RC_H1.
    let storage = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_storage_template_derived(),
        b"",
    );
    let ecdsa = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
        signature_s: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
    });
    assert_eq!(
        verify_signature(&mut sim, storage, digest, ecdsa).unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

/// HMAC-key tickets must be real `TicketComputeVerified` tickets: one produced over
/// `aHash = H(approvedPolicy || policyRef)` is accepted by TPM2_PolicyAuthorize.
#[test]
fn hmac_ticket_accepted_by_policy_authorize() {
    let mut sim = Tpm::new();

    // Fresh policy session: policyDigest is all zeros; approve exactly that digest.
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let approved: &'static [u8] = leak_bytes(&[0u8; 32]);
    let a_hash: &'static [u8] = leak_bytes(&sha256_array(approved));

    let (key, signature) = hmac_key_and_signature(&mut sim, Handle::RH_OWNER, a_hash);
    let ticket = verify_signature(&mut sim, key, a_hash, signature).expect("verify failed");
    match &ticket {
        TpmtTkVerified::Verified(h, d) => {
            assert_eq!(*h, Handle::RH_OWNER);
            assert_eq!(d.get_size() as usize, CONTEXT_INTEGRITY_DIGEST_SIZE);
            assert_ne!(d.get_buffer(), a_hash, "ticket must not be the raw digest");
        }
        _ => panic!("unexpected ticket tag"),
    }

    let key_name = read_public_name(&mut sim, key);
    let cmd = PolicyAuthorize {
        policy_session: session.session_handle,
        approved_policy: Tpm2bDigest::from_bytes(approved).unwrap(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: key_name,
        check_ticket: ticket,
    };
    execute_with_password_sessions(&mut sim, &cmd, 0, &[])
        .expect("PolicyAuthorize must accept the HMAC-key ticket");
}

/// An HMAC key in the NULL hierarchy yields the NULL ticket (empty digest).
#[test]
fn null_hierarchy_hmac_key_yields_null_ticket() {
    let mut sim = Tpm::new();
    let digest: &'static [u8] = leak_bytes(&[0x11; 32]);
    let (key, signature) = hmac_key_and_signature(&mut sim, Handle::RH_NULL, digest);
    let ticket = verify_signature(&mut sim, key, digest, signature).unwrap();
    match ticket {
        TpmtTkVerified::Verified(h, d) => {
            assert_eq!(h, Handle::RH_NULL);
            assert_eq!(d.get_size(), 0);
        }
        _ => panic!("unexpected ticket tag"),
    }
}

/// VerifySignature with a TPM_ALG_NULL signature fails with SCHEME+P2.
#[test]
fn verify_null_signature_scheme_rejected() {
    let mut sim = Tpm::new();

    // An RSASSA signing key.
    let key_handle = create_primary_with_data_handle(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SENSITIVE_DATA_ORIGIN,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits(2048),
                    exponent: 65537,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        },
        &[],
    );

    // Prepare VerifySignature command with raw TPM_ALG_NULL signature selector
    let digest = Tpm2bDigest::from_bytes(&[2u8; 32]).unwrap();
    let null_sig: Option<TpmtSignature> = None;
    let mut params = marshal_to_vec(&digest);
    params.extend_from_slice(&marshal_to_vec(&null_sig));

    let mut request = Vec::new();
    request.extend_from_slice(&0x8001u16.to_be_bytes()); // tag
    request.extend_from_slice(&(14 + params.len() as u32).to_be_bytes()); // size
    request.extend_from_slice(&0x00000177u32.to_be_bytes()); // cc VerifySignature
    request.extend_from_slice(&key_handle.0.to_be_bytes());
    request.extend_from_slice(&params);

    let mut response = [0u8; 1024];
    let response = sim.transact(&request, &mut response).unwrap();
    let error_code = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(
        error_code,
        TpmRc::SCHEME.with(Position::parameter(2)).get(),
        "VerifySignature should reject TPM_ALG_NULL signature with TPM_RC_SCHEME + TPM_RC_P + TPM_RC_2"
    );
}

/// Raw TPM2_VerifySignature with a keyed-hash key accepts a client-computed HMAC signature.
#[test]
fn verify_signature_accepts_hmac_signature() {
    let mut sim = Tpm::new();

    // A KeyedHash signing key whose HMAC key is the (client-chosen) sensitive data.
    let hmac_key = random_key();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        keyed_hash_public(TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH, &[]),
        hmac_key,
    );

    let mut hmac_buf = [0u8; 64];
    let expected_ha = tpm2::crypto::hmac(
        CLIENT_CRYPTO,
        TpmiAlgHash::Sha256,
        hmac_key,
        b"digest12",
        &mut hmac_buf,
    )
    .unwrap();
    let hmac: [u8; 32] = expected_ha.digest().try_into().unwrap();

    let error_code = send_key_command(
        &mut sim,
        CC_VERIFY_SIGNATURE,
        key,
        false,
        &verify_hmac_params(&hmac),
    );
    assert_eq!(
        error_code, 0,
        "VerifySignature command failed using a KeyedHash object handle! error_code = 0x{:08X}",
        error_code
    );
}

/// Raw TPM2_VerifySignature and TPM2_PolicySigned with a TPM_ALG_NULL signature fail with TPM_RC_SCHEME on the signature parameter.
#[test]
fn verify_signature_and_policy_signed_reject_null_sig_alg() {
    use crate::test_utils::{RespHeader, start_auth_session};
    use tpm2::{TpmSe, Unmarshal};

    let mut sim = Tpm::new();

    // Load a public signing key for testing VerifySignature and PolicySigned
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let load_rsp = sim.execute(load_cmd).unwrap();
    let key_handle = load_rsp.object_handle;

    // 1. Raw VerifySignature with TPM_ALG_NULL (0x0010) signature parameter -> TPM_RC_SCHEME + P + 2
    let mut verify_cmd_bytes = [0u8; 64];
    let mut offset = 0;
    verify_cmd_bytes[offset..offset + 2].copy_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
    offset += 2;
    let size_pos = offset;
    offset += 4;
    verify_cmd_bytes[offset..offset + 4]
        .copy_from_slice(&u32::from(TpmCc::VerifySignature).to_be_bytes());
    offset += 4;
    verify_cmd_bytes[offset..offset + 4].copy_from_slice(&key_handle.0.to_be_bytes()); // keyHandle
    offset += 4;
    verify_cmd_bytes[offset..offset + 2].copy_from_slice(&4u16.to_be_bytes()); // digest size = 4
    offset += 2;
    verify_cmd_bytes[offset..offset + 4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // digest
    offset += 4;
    verify_cmd_bytes[offset..offset + 2].copy_from_slice(&0x0010u16.to_be_bytes()); // signature = TPM_ALG_NULL
    offset += 2;
    verify_cmd_bytes[size_pos..size_pos + 4].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut resp_buf = [0u8; 256];
    sim.transact(&verify_cmd_bytes[..offset], &mut resp_buf)
        .unwrap();
    let mut resp_slice = &resp_buf[..];
    let resp_header = RespHeader::unmarshal(&mut resp_slice).unwrap();
    assert_eq!(
        resp_header.rc,
        TpmRc::SCHEME.with(Position::parameter(2)).get(),
        "VerifySignature with TPM_ALG_NULL signature must return TPM_RC_SCHEME + TPM_RC_P + TPM_RC_2"
    );

    // 2. Raw PolicySigned with TPM_ALG_NULL (0x0010) auth parameter -> TPM_RC_SCHEME + P + 5
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut ps_cmd_bytes = [0u8; 64];
    let mut offset = 0;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
    offset += 2;
    let size_pos = offset;
    offset += 4;
    ps_cmd_bytes[offset..offset + 4].copy_from_slice(&u32::from(TpmCc::PolicySigned).to_be_bytes());
    offset += 4;
    ps_cmd_bytes[offset..offset + 4].copy_from_slice(&key_handle.0.to_be_bytes()); // authObject
    offset += 4;
    ps_cmd_bytes[offset..offset + 4].copy_from_slice(&trial_session.session_handle.0.to_be_bytes()); // policySession
    offset += 4;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // nonceTPM (empty)
    offset += 2;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // cpHashA (empty)
    offset += 2;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // policyRef (empty)
    offset += 2;
    ps_cmd_bytes[offset..offset + 4].copy_from_slice(&0i32.to_be_bytes()); // expiration = 0
    offset += 4;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0x0010u16.to_be_bytes()); // auth = TPM_ALG_NULL
    offset += 2;
    ps_cmd_bytes[size_pos..size_pos + 4].copy_from_slice(&(offset as u32).to_be_bytes());

    sim.transact(&ps_cmd_bytes[..offset], &mut resp_buf)
        .unwrap();
    let mut resp_slice = &resp_buf[..];
    let resp_header = RespHeader::unmarshal(&mut resp_slice).unwrap();
    assert_eq!(
        resp_header.rc,
        TpmRc::SCHEME.with(Position::parameter(5)).get(),
        "PolicySigned with TPM_ALG_NULL auth must return TPM_RC_SCHEME + TPM_RC_P + TPM_RC_5"
    );

    flush_context(&mut sim, trial_session.session_handle).unwrap();
    flush_context(&mut sim, key_handle).unwrap();
}

/// TPM2_VerifySignature fails for a decrypt-only key (ATTRIBUTES), an ECDSA signature for RSA (SCHEME) and a mismatched hash (SIGNATURE).
#[test]
#[allow(deprecated)]
fn verify_signature_rejects_decrypt_only_key_and_mismatched_signature() {
    let mut sim = Tpm::new();

    // 1. Create a sign/verify key
    let in_public_sign = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_sign_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public_sign),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let sign_create_rsp = execute_with_password_sessions(
        &mut sim,
        &create_sign_cmd,
        1, // CreatePrimary needs authorization of the hierarchy (C: AUTH_MISSING otherwise)
        &[],
    )
    .expect("CreatePrimary sign key failed");
    let sign_key_handle = sign_create_rsp.object_handle;

    // 2. Create a decrypt-only key
    let in_public_decrypt = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_decrypt_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public_decrypt),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let decrypt_create_rsp = execute_with_password_sessions(
        &mut sim,
        &create_decrypt_cmd,
        1, // CreatePrimary needs authorization of the hierarchy (C: AUTH_MISSING otherwise)
        &[],
    )
    .expect("CreatePrimary decrypt key failed");
    let decrypt_key_handle = decrypt_create_rsp.object_handle;

    // 3. Sign a digest with the signing key
    let data_to_sign = b"migrationpains";
    let digest = Sha256::digest(data_to_sign);
    let sign_cmd = Sign {
        key_handle: sign_key_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let sign_resp =
        execute_sign(&mut sim, &sign_cmd, 1, &[], &mut resp_buffer).expect("Sign failed");

    // 4. Attempt to verify signature with the decryption-only key
    let verify_cmd = VerifySignature {
        key_handle: decrypt_key_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: sign_resp.signature,
    };
    let res = execute_with_password_sessions(&mut sim, &verify_cmd, 0, &[]);
    assert!(
        res.is_err(),
        "VerifySignature should fail when key lacks SIGN attribute"
    );
    let err = res.err().unwrap();
    // VerifySignature.c: TPM_RCS_ATTRIBUTES + RC_VerifySignature_keyHandle.
    assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::handle(1)).get());

    // 5. Attempt to verify with a mismatched signature scheme type (e.g. ECDSA signature)
    let verify_cmd_mismatched = VerifySignature {
        key_handle: sign_key_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: TpmtSignature::Ecdsa(TpmsSignatureEcc {
            hash: TpmiAlgHash::Sha256,
            signature_r: Tpm2bEccParameter::default(),
            signature_s: Tpm2bEccParameter::default(),
        }),
    };
    let res_mismatched = execute_with_password_sessions(&mut sim, &verify_cmd_mismatched, 0, &[]);
    assert!(
        res_mismatched.is_err(),
        "VerifySignature should fail with mismatched scheme (ECDSA on RSA key)"
    );
    let err_mismatched = res_mismatched.err().unwrap();
    // CryptRsaValidateSignature: a non-RSA signature is TPM_RC_SCHEME, + RC_VerifySignature_signature.
    assert_eq!(
        err_mismatched,
        TpmRc::SCHEME.with(Position::parameter(2)).get()
    );

    // 6. Attempt to verify with a mismatched hash algorithm in signature (SHA1 vs key's SHA256)
    let mut signature_mismatched_hash = sign_resp.signature;
    match &mut signature_mismatched_hash {
        TpmtSignature::Rsassa(rsassa) => {
            rsassa.hash = TpmiAlgHash::Sha1;
        }
        _ => panic!("Expected RSASSA signature"),
    }
    let verify_cmd_mismatched_hash = VerifySignature {
        key_handle: sign_key_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: signature_mismatched_hash,
    };
    let res_mismatched_hash =
        execute_with_password_sessions(&mut sim, &verify_cmd_mismatched_hash, 0, &[]);
    assert!(
        res_mismatched_hash.is_err(),
        "VerifySignature should fail with mismatched hash algorithm"
    );
    let err_mismatched_hash = res_mismatched_hash.err().unwrap();
    // CryptRsaValidateSignature: RSASSA decoding with the wrong hash fails -> TPM_RC_SIGNATURE,
    // + RC_VerifySignature_signature.
    assert_eq!(
        err_mismatched_hash,
        TpmRc::SIGNATURE.with(Position::parameter(2)).get(),
        "Expected TPM_RC_SIGNATURE + P2, got {}",
        err_mismatched_hash
    );

    // Cleanup keys
    flush_context(&mut sim, sign_key_handle).unwrap();
    flush_context(&mut sim, decrypt_key_handle).unwrap();
}

/// Raw TPM2_VerifySignature with a decrypt-only RSA primary fails with TPM_RC_ATTRIBUTES.
#[test]
fn verify_signature_rejects_decrypt_only_key_raw() {
    let mut sim = Tpm::new();
    // Key has DECRYPT but lacks SIGN_ENCRYPT
    let (key, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::DECRYPT | sdo_user(), None),
        &[],
    );

    let error_code = send_key_command(
        &mut sim,
        CC_VERIFY_SIGNATURE,
        key,
        false,
        &verify_hmac_params(&[0u8; 32]),
    );
    assert_eq!(
        error_code,
        0x00000182, // TPM_RC_ATTRIBUTES + RC_VerifySignature_keyHandle (VerifySignature.c)
        "Expected TPM_RC_ATTRIBUTES + H1 (0x182) for verify signature with key lacking SIGN_ENCRYPT! error_code = 0x{:08X}",
        error_code
    );
}

/// Test VerifySignature fails with TPM_RC_ATTRIBUTES if key lacks SIGN_ENCRYPT.
#[test]
#[allow(deprecated)]
fn verify_signature_rejects_key_without_sign() {
    let mut sim = Tpm::new();

    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::DECRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let load_rsp = sim.execute(load_cmd).unwrap();

    let verify_cmd = VerifySignature {
        key_handle: load_rsp.object_handle,
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        signature: TpmtSignature::Rsassa(tpm2::TpmsSignatureRsa {
            hash: TpmiAlgHash::Sha256,
            sig: tpm2::Tpm2bPublicKeyRsa::default(),
        }),
    };
    let res = sim.execute(verify_cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    // VerifySignature.c: TPM_RCS_ATTRIBUTES + RC_VerifySignature_keyHandle.
    assert_eq!(err.get(), TpmRc::ATTRIBUTES.with(Position::handle(1)).get());

    flush_context(&mut sim, load_rsp.object_handle).unwrap();
}

/// Test VerifySignature fails with TPM_RC_HANDLE if KeyedHash key is public-only.
#[test]
#[allow(deprecated)]
fn verify_signature_rejects_public_only_hmac_key() {
    let mut sim = Tpm::new();

    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None, // public-only
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let load_rsp = sim.execute(load_cmd).unwrap();

    let verify_cmd = VerifySignature {
        key_handle: load_rsp.object_handle,
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        signature: TpmtSignature::Rsassa(tpm2::TpmsSignatureRsa {
            hash: TpmiAlgHash::Sha256,
            sig: tpm2::Tpm2bPublicKeyRsa::default(),
        }),
    };
    let res = sim.execute(verify_cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    // CryptValidateSignature: TPM_RCS_HANDLE, + RC_VerifySignature_signature.
    assert_eq!(err.get(), TpmRc::HANDLE.with(Position::parameter(2)).get());

    flush_context(&mut sim, load_rsp.object_handle).unwrap();
}

/// Raw TPM2_VerifySignature with a public-only keyed-hash key from LoadExternal fails with TPM_RC_HANDLE.
#[test]
fn verify_signature_rejects_public_only_hmac_key_raw() {
    let mut sim = Tpm::new();

    // KeyedHash key with SIGN_ENCRYPT loaded without its sensitive area (public-only)
    let key = load_external_public(
        &mut sim,
        keyed_hash_public(TpmaObject::SIGN_ENCRYPT, leak_bytes(&[0x11; 32])),
    );

    let error_code = send_key_command(
        &mut sim,
        CC_VERIFY_SIGNATURE,
        key,
        false,
        &verify_hmac_params(&[0u8; 32]),
    );
    assert_eq!(
        error_code,
        0x000002CB, // TPM_RC_HANDLE + RC_VerifySignature_signature (CryptValidateSignature)
        "Expected TPM_RC_HANDLE + P2 (0x2CB) for public-only KeyedHash! error_code = 0x{:08X}",
        error_code
    );
}

/// 13. Test VerifySignature with unsupported scheme (non-Null signature).
///
/// Expected: TPM_RC_SCHEME.
#[test]
#[allow(deprecated)]
fn verify_signature_rejects_unsupported_scheme() {
    let mut sim = Tpm::new();

    // Load ECC key
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let load_rsp = sim.execute(load_cmd).unwrap();

    let verify_cmd = VerifySignature {
        key_handle: load_rsp.object_handle,
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        signature: TpmtSignature::Sm2(tpm2::TpmsSignatureEcc {
            hash: TpmiAlgHash::Sha256,
            signature_r: Tpm2bEccParameter::default(),
            signature_s: Tpm2bEccParameter::default(),
        }),
    };
    let res = sim.execute(verify_cmd);
    assert!(
        res.is_err(),
        "VerifySignature should fail for non-Null signature schemes"
    );
    let err = res.err().unwrap();
    // VerifySignature.c: RcSafeAddToResult(TPM_RC_SCHEME, RC_VerifySignature_signature).
    assert_eq!(err.get(), TpmRc::SCHEME.with(Position::parameter(2)).get());

    flush_context(&mut sim, load_rsp.object_handle).unwrap();
}
