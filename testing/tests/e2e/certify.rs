//! TPM2_Certify: handle and signer checks, signing schemes (incl. ECDAA and HMAC) and qualified-
//! name reporting.

use crate::_common::Connection;
use crate::_common::{
    AES128_CFB, CmdHeader, RespHeader, base_attributes, certify, create_non_signing_key_rsa,
    create_primary, create_primary_full, create_primary_in, create_primary_with_auth,
    create_signing_key_ecc, create_signing_key_ecc_with_unique, ecc_sign_template_with_scheme,
    ecdsa_template, exec_pws, execute_certify, execute_with_password_sessions,
    execute_with_password_sessions_status, flush_context, hmac_sign_template, make_template,
    marshal_to_slice, marshal_to_vec, qualified_name, rsa_template, rsassa_signer_template,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{Certify, Commit, CreateLoaded, CreatePrimary};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmCc, TpmEccCurve, TpmaObject, TpmaSession,
    TpmiAlgHash, TpmiRsaKeyBits, TpmiStCommandTag, TpmlPcrSelection, TpmsAuthCommand, TpmsEccParms,
    TpmsEccPoint, TpmsRsaParms, TpmsSchemeEcdaa, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic,
    TpmtRsaScheme, TpmtSigScheme, TpmtSignature, TpmuAttest, Unmarshal,
};
use tpm2_platform_linux::PlatformCryptoProvider;

/// TPM2_Certify with one instead of two auth sessions fails with TPM_RC_AUTH_MISSING
#[test]
fn certify_rejects_missing_authorization() {
    let mut sim = Tpm::new();
    let (obj_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 0);
    let (ak_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 1);

    let certify_cmd = Certify {
        object_handle: obj_handle,
        sign_handle: ak_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Provide only 1 authorization session instead of 2
    let resp = execute_with_password_sessions_status(&mut sim, &certify_cmd, 1, &[]);
    // Expect TPM_RC_AUTH_MISSING (0x125)
    assert_eq!(resp.err(), Some(0x125));

    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_Certify with a decrypt-only RSA signHandle fails
#[test]
fn certify_rejects_non_signing_key() {
    let mut sim = Tpm::new();
    let (obj_handle, _) = create_signing_key_ecc(&mut sim, &[]);
    let (non_sign_handle, _) = create_non_signing_key_rsa(&mut sim);

    let certify_cmd = Certify {
        object_handle: obj_handle,
        sign_handle: non_sign_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let resp = execute_with_password_sessions_status(&mut sim, &certify_cmd, 2, &[]);
    assert!(resp.is_err());

    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, non_sign_handle).unwrap();
}

/// Raw TPM2_Certify with 67-byte qualifyingData fails with TPM_RC_SIZE + P1
#[test]
fn certify_rejects_oversized_qualifying_data() {
    let mut sim = Tpm::new();
    let (obj_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 0);
    let (ak_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 1);

    // Construct raw transaction bytes:
    let mut cmd_buffer = [0u8; 4096];
    let mut cmd_header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: TpmCc::Certify,
    };
    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    written += marshal_to_slice(&obj_handle, &mut cmd_buffer[written..]);
    written += marshal_to_slice(&ak_handle, &mut cmd_buffer[written..]);

    // 2 password sessions
    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buffer = [0u8; 1024];
    let mut auth_written = 0;
    for _ in 0..2 {
        auth_written += marshal_to_slice(&(auth_cmd), &mut auth_buffer[auth_written..]);
    }
    written += marshal_to_slice(&(auth_written as u32), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
    written += auth_written;

    // Parameters:
    // qualifying_data: size 67 (exceeds max size 66), followed by 67 bytes of zero
    let size_67 = 67u16;
    written += marshal_to_slice(&(size_67), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + 67].fill(0);
    written += 67;
    // in_scheme: Null
    let in_scheme: Option<TpmtSigScheme> = None;
    written += marshal_to_slice(&(in_scheme), &mut cmd_buffer[written..]);

    // Update size in header
    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 4096];
    sim.transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();

    assert_eq!(resp_header.rc, 0x1D5); // TPM_RC_SIZE + TPM_RC_P + TPM_RC_1 (0x1D5) because parameter 1 unmarshal failed

    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_Certify with an ECDSA signer and an RSASSA inScheme fails with TPM_RC_SCHEME + P2
#[test]
fn certify_rejects_rsassa_scheme_for_ecc_key() {
    let mut sim = Tpm::new();
    let (obj_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 0);
    let (ak_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 1);

    // Signer key is ECC (ECDSA), but we request RSASSA signature scheme!
    let certify_cmd = Certify {
        object_handle: obj_handle,
        sign_handle: ak_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };

    let resp = execute_with_password_sessions_status(&mut sim, &certify_cmd, 2, &[]);
    assert!(resp.is_err());
    let err = resp.err().unwrap();
    // TPM_RC_SCHEME + RC_Certify_inScheme (P2).
    assert_eq!(err, 0x2D2);

    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_Certify with a non-existent objectHandle fails with TPM_RC_REFERENCE_H0
#[test]
fn certify_rejects_unloaded_object() {
    let mut sim = Tpm::new();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let certify_cmd = Certify {
        object_handle: Handle(0x8000000E),
        sign_handle: ak_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use non-existent object handle 0x80ffffff (handle 1)

    let resp = execute_with_password_sessions_status(&mut sim, &certify_cmd, 2, &[]);
    // SPEC EXPECTS: TPM_RC_REFERENCE_Hx for invalid transient object_handle (ReferenceH0 = 2320)
    assert_eq!(resp.err(), Some(2320));

    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_Certify with a non-existent signHandle fails with TPM_RC_REFERENCE_H1
#[test]
fn certify_rejects_unloaded_sign_key() {
    let mut sim = Tpm::new();
    let (obj_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let certify_cmd = Certify {
        object_handle: obj_handle,
        sign_handle: Handle(0x8000000E),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use non-existent sign handle 0x8000000E (handle 2)

    let resp = execute_with_password_sessions_status(&mut sim, &certify_cmd, 2, &[]);
    // SPEC EXPECTS: TPM_RC_REFERENCE_Hx for invalid transient sign_handle (ReferenceH1 = 2321)
    assert_eq!(resp.err(), Some(2321));

    flush_context(&mut sim, obj_handle).unwrap();
}

/// TPM2_Certify attestation signature verifies with the signer key and SHA-256 but not with SHA-1 or another key
#[test]
fn certify_signature_verifies_only_with_signer_and_hash() {
    let mut sim = Tpm::new();
    let auth = b"password";

    // Setup primary key template (RSA, SHA256, restricted, sign/encrypt)
    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::RESTRICTED,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let pcr_selection = TpmlPcrSelection::from_slice(&[]).unwrap();

    // Create primary signer key
    let create_signer_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        creation_pcr: pcr_selection,
        ..Default::default()
    };
    let signer_rsp = execute_with_password_sessions(&mut sim, &create_signer_cmd, 1, &[]).unwrap();
    let signer_handle = signer_rsp.object_handle;

    // Create another signer key with a different template unique area to ensure it generates a different key
    let mut other_pub_area = pub_area;
    other_pub_area.parms_and_id = PublicParmsAndId::Rsa(
        rsa_parms,
        Tpm2bPublicKeyRsa::from_bytes(&[1u8; 256]).unwrap(),
    );
    let other_in_public = tpm2::Tpm2b(other_pub_area);

    let create_other_signer_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"wrongpwd").unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: other_in_public,
        creation_pcr: pcr_selection,
        ..Default::default()
    };
    let other_signer_rsp =
        execute_with_password_sessions(&mut sim, &create_other_signer_cmd, 1, &[]).unwrap();
    let other_signer_handle = other_signer_rsp.object_handle;

    let mut subject_pub_area = pub_area;
    subject_pub_area.parms_and_id = PublicParmsAndId::Rsa(
        rsa_parms,
        Tpm2bPublicKeyRsa::from_bytes(&[2u8; 256]).unwrap(),
    );
    let subject_in_public = tpm2::Tpm2b(subject_pub_area);

    // Create primary subject key
    let create_subject_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: subject_in_public,
        creation_pcr: pcr_selection,
        ..Default::default()
    };
    let subject_rsp_handles =
        execute_with_password_sessions(&mut sim, &create_subject_cmd, 1, &[]).unwrap();
    let subject_handle = subject_rsp_handles.object_handle;

    let original_buffer = b"test nonce";

    // Call Certify
    let certify_cmd = Certify {
        object_handle: subject_handle,
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::from_bytes(original_buffer).unwrap(),
        in_scheme: None,
    };

    let mut resp_buffer = [0u8; 4096];
    let certify_rsp = execute_certify(&mut sim, &certify_cmd, 2, auth, &mut resp_buffer).unwrap();

    let certify_info = certify_rsp.certify_info.0;
    let mut attest_buf = [0u8; 1024];
    let attest_len = marshal_to_slice(&certify_info, &mut attest_buf);
    let attest_bytes = &attest_buf[..attest_len];

    let provider = PlatformCryptoProvider;
    use tpm2::crypto::Asymmetric;
    let mut sha256_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest_sha256 = tpm2::crypto::hash(
        &provider,
        tpm2::TpmiAlgHash::Sha256,
        attest_bytes,
        &mut sha256_buf,
    )
    .unwrap();
    let mut sha1_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest_sha1 = tpm2::crypto::hash(
        &provider,
        tpm2::TpmiAlgHash::Sha1,
        attest_bytes,
        &mut sha1_buf,
    )
    .unwrap();

    let pub_struct = signer_rsp.out_public.0;
    let other_pub_struct = other_signer_rsp.out_public.0;

    if let (PublicParmsAndId::Rsa(_, rsa_unique), PublicParmsAndId::Rsa(_, other_rsa_unique)) =
        (pub_struct.parms_and_id, other_pub_struct.parms_and_id)
    {
        let (sig_alg, sig_bytes) = match &certify_rsp.signature {
            Some(TpmtSignature::Rsassa(rsa_sig)) => {
                assert_eq!(rsa_sig.hash, tpm2::TpmiAlgHash::Sha256);
                (tpm2::Alg::RSASSA, rsa_sig.sig.get_buffer())
            }
            _ => panic!("Expected RSASSA signature"),
        };

        // 1. Correct verification should pass
        let verify_res =
            provider.verify_inner(sig_alg, rsa_unique.get_buffer(), digest_sha256, sig_bytes);
        assert_eq!(verify_res, Ok(true));

        // 2. Verification with incorrect hash algorithm (SHA1 instead of SHA256) should fail
        let verify_res_wrong_hash =
            provider.verify_inner(sig_alg, rsa_unique.get_buffer(), digest_sha1, sig_bytes);
        assert_eq!(verify_res_wrong_hash, Ok(false));

        // 3. Verification with wrong key (other signer key) should fail
        let verify_res_wrong_key = provider.verify_inner(
            sig_alg,
            other_rsa_unique.get_buffer(),
            digest_sha256,
            sig_bytes,
        );
        assert_eq!(verify_res_wrong_key, Ok(false));

        // 4. Verification with modified attestation data should fail
        let mut modified_attest_bytes = attest_bytes.to_vec();
        modified_attest_bytes[0] ^= 0xFF; // Modify a byte
        let mut mod_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
        let modified_digest = tpm2::crypto::hash(
            &provider,
            tpm2::TpmiAlgHash::Sha256,
            &modified_attest_bytes,
            &mut mod_buf,
        )
        .unwrap();
        let verify_res_modified_attest =
            provider.verify_inner(sig_alg, rsa_unique.get_buffer(), modified_digest, sig_bytes);
        assert_eq!(verify_res_modified_attest, Ok(false));
    } else {
        panic!("Expected RSA public parameters");
    }

    // Flush keys
    flush_context(&mut sim, subject_handle).unwrap();
    flush_context(&mut sim, signer_handle).unwrap();
    flush_context(&mut sim, other_signer_handle).unwrap();
}

/// Certify with an ECDAA key (consuming a Commit) yields empty qualifiedSigner/extraData/qualifiedName and an ECDAA signature.
///
/// `TPM2_Certify` with an ECDAA signing key (consuming a `TPM2_Commit`) produces an anonymous
/// attestation: empty qualifiedSigner, extraData and qualifiedName.
#[test]
fn ecdaa_certify_is_anonymous() {
    let mut sim = Tpm::new();

    let (certified_handle, certified_name) = create_primary(&mut sim, ecdsa_template());

    let (signer_handle, _) = create_primary(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: base_attributes() | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: None,
                    scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                        hash_alg: TpmiAlgHash::Sha256,
                        count: 0,
                    })),
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                TpmsEccPoint::default(),
            ),
        },
    );

    // ECDAA signing consumes an outstanding TPM2_Commit (C CryptGenerateR checks the commit
    // array, TPM_RC_VALUE otherwise).
    let commit = exec_pws(
        &mut sim,
        &Commit {
            sign_handle: signer_handle,
            ..Default::default()
        },
        &[&[]],
    )
    .unwrap_or_else(|rc| panic!("TPM2_Commit failed: {rc:#x}"));

    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::from_bytes(&[0x11, 0x22]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: commit.counter,
        })),
    };
    let resp = exec_pws(&mut sim, &cmd, &[&[], &[]])
        .expect("TPM2_Certify with TPMS_SCHEME_ECDAA must succeed");

    let attest = resp.certify_info.0;
    // Per TPM 2.0 Part 3 spec for ECDAA (anonymous signing):
    // qualified_signer, extra_data, and certified object's qualified_name must be empty
    assert_eq!(attest.qualified_signer.get_buffer(), &[]);
    assert_eq!(attest.extra_data.get_buffer(), &[]);
    if let TpmuAttest::Certify(info) = attest.attested {
        assert_eq!(info.qualified_name.get_buffer(), &[]);
        assert_eq!(info.name.get_buffer(), &certified_name[..]);
    } else {
        panic!("Expected TpmuAttest::Certify");
    }

    // Verify signature is ECDAA variant
    match resp.signature {
        Some(tpm2::TpmtSignature::Ecdaa(sig)) => {
            assert_eq!(sig.hash, TpmiAlgHash::Sha256);
            assert_eq!(sig.signature_r.get_buffer().len(), 32);
            assert_eq!(sig.signature_s.get_buffer().len(), 32);
        }
        _ => panic!("Expected Some(TpmtSignature::Ecdaa)"),
    }
}

/// An ECDAA Certify consumes the Commit count: reuse or a never-committed count fails with VALUE.
///
/// An ECDAA attestation consumes the `TPM2_Commit` commitment: the same `count` cannot be used
/// for a second signature (`CryptGenerateR`/`CryptEndCommit`), and a count that was never
/// committed is rejected with a bare `TPM_RC_VALUE`.
#[test]
fn ecdaa_commit_consumed_once() {
    let mut sim = Tpm::new();
    let key = create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template_with_scheme(Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 0,
        }))),
    );
    let commit = Commit {
        sign_handle: key,
        p1: tpm2::Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: tpm2::Tpm2bEccParameter::default(),
    };
    let commit_rsp =
        execute_with_password_sessions(&mut sim, &commit, 1, &[]).expect("Commit failed");
    let scheme = |count| {
        Some(TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count,
        }))
    };

    // A count that was never committed.
    assert_eq!(
        certify(
            &mut sim,
            key,
            key,
            scheme(commit_rsp.counter.wrapping_add(1))
        )
        .err(),
        Some(0x084)
    );
    let rsp = certify(&mut sim, key, key, scheme(commit_rsp.counter))
        .expect("Certify with a fresh ECDAA commitment failed");
    assert!(matches!(rsp.signature, Some(TpmtSignature::Ecdaa(_))));
    // Reusing the commitment must fail (TPM_RC_VALUE).
    assert_eq!(
        certify(&mut sim, key, key, scheme(commit_rsp.counter)).err(),
        Some(0x084)
    );
}

/// Certify with missing object/sign handles (REFERENCE_H0/H1) or a non-signing/symmetric signer (TPM_RC_KEY + RC_H2)
#[test]
fn handle_and_signer_key_errors() {
    let mut sim = Tpm::new();

    // Certified object (password [0x11, 0x22])
    let certified_handle = create_primary_with_auth(
        &mut sim,
        rsa_template(TpmaObject::SIGN_ENCRYPT, None),
        &[0x11, 0x22],
    );
    let certified_auth: &[u8] = &[0x11, 0x22];
    let empty_auth: &[u8] = &[];

    let cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        ..Default::default()
    };

    // 1. Certified object invalid handle -> should fail with TpmRc::REFERENCE_H0
    let missing = Handle(0x80000009);
    assert_ne!(missing, certified_handle);
    let cmd = Certify {
        object_handle: missing,          // Non-existent
        sign_handle: Handle(0x40000007), // RH_NULL
        ..cmd
    };
    // Since 0x80000009 is non-existent, its auth is empty. Provide empty hmac.
    let res = exec_pws(&mut sim, &cmd, &[empty_auth]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // 2. Sign key invalid handle -> should fail with TpmRc::REFERENCE_H1
    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: missing, // Non-existent
        ..cmd
    };
    // Provide correct hmac for certified_handle, and empty hmac for non-existent sign key.
    let res = exec_pws(&mut sim, &cmd, &[certified_auth, empty_auth]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H1.get()));

    // 3. A signer key that is NOT a signing key (lacks SIGN_ENCRYPT attribute)
    let bad_signer =
        create_primary_with_auth(&mut sim, rsa_template(TpmaObject::DECRYPT, None), &[]);
    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: bad_signer,
        ..cmd
    };
    let res = exec_pws(&mut sim, &cmd, &[certified_auth, empty_auth]);
    // TPM_RC_KEY + RC_Certify_signHandle (H2).
    assert_eq!(res.err(), Some(0x29C));
    flush_context(&mut sim, bad_signer).unwrap();

    // 4. A signer key that has incorrect key type (Symmetric key instead of Asymmetric key)
    let sym_signer = create_primary_with_auth(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: base_attributes() | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
        },
        &[],
    );
    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: sym_signer,
        ..cmd
    };
    let res = exec_pws(&mut sim, &cmd, &[certified_auth, empty_auth]);
    // TPM_RC_KEY + RC_Certify_signHandle (H2).
    assert_eq!(res.err(), Some(0x29C));
}

/// An HMAC key signs Certify output as HMAC(key, H(attest)).
///
/// An HMAC key signs `TPM2_Certify` output as `HMAC(key, H(attest))` (`CryptHmacSign`).
#[test]
fn hmac_key_signs_certify() {
    let mut sim = Tpm::new();
    let key_bits: &'static [u8] = b"0123456789abcdef0123456789abcdef";
    let (_, key) = create_primary_full(&mut sim, Handle::RH_OWNER, hmac_sign_template(), key_bits);

    let rsp = certify(&mut sim, key, key, None).expect("Certify with an HMAC key failed");
    let attest_bytes = marshal_to_vec(&rsp.certify_info.0);
    let digest = Sha256::digest(&attest_bytes);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key_bits).unwrap();
    mac.update(&digest);
    let expected = mac.finalize().into_bytes();

    match rsp.signature {
        Some(TpmtSignature::Hmac(ha)) => assert_eq!(ha.digest(), expected.as_slice()),
        other => panic!("expected an HMAC signature, got {other:?}"),
    }
}

/// Certify reports signer QN and certified object Name/QN accumulated owner -> parent -> child.
///
/// The attestation reports the signer's qualified Name and the certified object's Name and
/// qualified Name, where qualified Names accumulate along the hierarchy (owner -> storage
/// parent -> certified child).
#[test]
#[allow(deprecated)]
fn qualified_names_accumulate_along_hierarchy() {
    let mut sim = Tpm::new();

    // Restricted RSASSA-SHA256 signing primary key.
    let (signer_handle, signer_name) = create_primary(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: base_attributes()
                | TpmaObject::RESTRICTED
                | TpmaObject::SIGN_ENCRYPT,
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
        },
    );

    // Storage parent (primary) and the certified object (its child).
    let (parent_handle, parent_name) = create_primary(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: base_attributes() | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: Some(AES128_CFB),
                    scheme: None,
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                TpmsEccPoint::default(),
            ),
        },
    );
    let create = CreateLoaded {
        parent_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Default::default(),
        }),
        in_public: make_template(&ecdsa_template()),
    };
    let created = execute_with_password_sessions(&mut sim, &create, 1, &[])
        .unwrap_or_else(|rc| panic!("TPM2_CreateLoaded failed: {rc:#x}"));
    let certified_handle = created.object_handle;
    let certified_name = created.name.get_buffer().to_vec();

    let owner_qn = Handle::RH_OWNER.0.to_be_bytes();
    let signer_qn = qualified_name(&owner_qn, &signer_name);
    let parent_qn = qualified_name(&owner_qn, &parent_name);
    let certified_qn = qualified_name(&parent_qn, &certified_name);

    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::from_bytes(&[99, 100]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };

    let resp = exec_pws(&mut sim, &cmd, &[&[], &[]]).unwrap();
    let attest = resp.certify_info.0;
    assert_eq!(attest.qualified_signer.get_buffer(), &signer_qn[..]);
    assert_eq!(attest.extra_data.get_buffer(), &[99, 100]);

    if let TpmuAttest::Certify(cert_info) = attest.attested {
        assert_eq!(cert_info.name.get_buffer(), &certified_name[..]);
        assert_eq!(cert_info.qualified_name.get_buffer(), &certified_qn[..]);
    } else {
        panic!("Expected TpmuAttest::Certify");
    }
}

/// Certify resolves NULL scheme to the key scheme, rejects mismatching schemes (TPM_RC_SCHEME + RC_P2), accepts a restricted signer
#[test]
fn signer_scheme_selection() {
    let mut sim = Tpm::new();

    let certified_handle =
        create_primary_with_auth(&mut sim, rsa_template(TpmaObject::SIGN_ENCRYPT, None), &[]);

    // 1. Signer key with fixed scheme RSASSA SHA256
    let signer_handle = create_primary_with_auth(&mut sim, rsassa_signer_template(), &[]);

    // 1.1 Requesting Null scheme should resolve to fixed scheme (RSASSA SHA256) -> Success
    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let resp = exec_pws(&mut sim, &cmd, &[&[], &[]]).expect("Certify with Null scheme failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));

    // 1.2 Requesting RSAPSS scheme should fail since key scheme is fixed to RSASSA -> TpmRc::SCHEME
    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256)),
    };
    let res = exec_pws(&mut sim, &cmd, &[&[], &[]]);
    // TPM_RC_SCHEME + RC_Certify_inScheme (P2).
    assert_eq!(res.err(), Some(0x2D2));

    // 1.3 Requesting RSASSA SHA384 (different hash) should fail -> TpmRc::SCHEME
    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha384)),
    };
    let res = exec_pws(&mut sim, &cmd, &[&[], &[]]);
    // TPM_RC_SCHEME + RC_Certify_inScheme (P2).
    assert_eq!(res.err(), Some(0x2D2));
    flush_context(&mut sim, signer_handle).unwrap();

    // 2. Restricted signer key
    let restricted_signer = create_primary_with_auth(
        &mut sim,
        rsa_template(
            TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED,
            Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        ),
        &[],
    );

    // 2.1 Restricted key scheme hash MUST match name_alg (SHA256) -> Success
    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: restricted_signer,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let resp = exec_pws(&mut sim, &cmd, &[&[], &[]]).expect("Certify with restricted key failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));
}
