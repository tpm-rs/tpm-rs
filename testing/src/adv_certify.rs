#![forbid(unsafe_code)]

use crate::test_utils::*;
use tpm2::commands::{
    Certify, CertifyCreation, CertifyCreationHandles, CertifyHandles, CreatePrimary,
    CreatePrimaryHandles, NVCertify, NVCertifyHandles, NVDefineSpace, NVDefineSpaceHandles,
    NVWrite, NVWriteHandles,
};
use tpm2::{Handle, TpmNt};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmaNv, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmlPcrSelection,
    TpmsNvPublic, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic, TpmtRsaScheme, TpmtSigScheme,
    TpmtSignature, TpmtTkCreation, TpmuAttest,
};
use tpm2_platform_linux::PlatformCryptoProvider;
use tpm2_simulator::create_simulator;

#[test]
fn test_certify_adversarial_signatures() {
    let mut sim = create_simulator!();
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
        in_sensitive,
        in_public,
        creation_pcr: pcr_selection,
        ..Default::default()
    };
    let create_signer_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (signer_rsp, signer_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_signer_cmd, create_signer_handles, 0, &[])
            .unwrap();
    let signer_handle = signer_rsp_handles.object_handle;

    // Create another signer key with a different template unique area to ensure it generates a different key
    let mut other_pub_area = pub_area;
    other_pub_area.parms_and_id = PublicParmsAndId::Rsa(
        rsa_parms,
        Tpm2bPublicKeyRsa::from_bytes(&[1u8; 256]).unwrap(),
    );
    let other_in_public = tpm2::Tpm2b(other_pub_area);

    let create_other_signer_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"wrongpwd").unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: other_in_public,
        creation_pcr: pcr_selection,
        ..Default::default()
    };
    let (other_signer_rsp, other_signer_rsp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_other_signer_cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        0,
        &[],
    )
    .unwrap();
    let other_signer_handle = other_signer_rsp_handles.object_handle;

    let mut subject_pub_area = pub_area;
    subject_pub_area.parms_and_id = PublicParmsAndId::Rsa(
        rsa_parms,
        Tpm2bPublicKeyRsa::from_bytes(&[2u8; 256]).unwrap(),
    );
    let subject_in_public = tpm2::Tpm2b(subject_pub_area);

    // Create primary subject key
    let create_subject_cmd = CreatePrimary {
        in_sensitive,
        in_public: subject_in_public,
        creation_pcr: pcr_selection,
        ..Default::default()
    };
    let create_subject_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_subject_rsp, subject_rsp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_subject_cmd,
        create_subject_handles,
        0,
        &[],
    )
    .unwrap();
    let subject_handle = subject_rsp_handles.object_handle;

    let original_buffer = b"test nonce";

    // Call Certify
    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::from_bytes(original_buffer).unwrap(),
        in_scheme: None,
    };
    let certify_handles = CertifyHandles {
        object_handle: subject_handle,
        sign_handle: signer_handle,
    };

    let mut resp_buffer = [0u8; 4096];
    let (certify_rsp, _) = execute_certify(
        &mut sim,
        &certify_cmd,
        certify_handles,
        2,
        auth,
        &mut resp_buffer,
    )
    .unwrap();

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
        assert!(verify_res.is_ok());

        // 2. Verification with incorrect hash algorithm (SHA1 instead of SHA256) should fail
        let verify_res_wrong_hash =
            provider.verify_inner(sig_alg, rsa_unique.get_buffer(), digest_sha1, sig_bytes);
        assert!(verify_res_wrong_hash.is_err());

        // 3. Verification with wrong key (other signer key) should fail
        let verify_res_wrong_key = provider.verify_inner(
            sig_alg,
            other_rsa_unique.get_buffer(),
            digest_sha256,
            sig_bytes,
        );
        assert!(verify_res_wrong_key.is_err());

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
        assert!(verify_res_modified_attest.is_err());
    } else {
        panic!("Expected RSA public parameters");
    }

    // Flush keys
    flush_context(&mut sim, subject_handle).unwrap();
    flush_context(&mut sim, signer_handle).unwrap();
    flush_context(&mut sim, other_signer_handle).unwrap();
}

#[test]
fn test_certify_creation_adversarial() {
    let mut sim = create_simulator!();

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
            | TpmaObject::RESTRICTED
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let pcr_selection = TpmlPcrSelection::from_slice(&[]).unwrap();
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    // Create primary key on Endorsement hierarchy
    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        creation_pcr: pcr_selection,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (create_rsp, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 0, &[]).unwrap();
    let object_handle = create_rsp_handles.object_handle;

    let in_scheme = Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256));

    // 1. Correct ticket should pass
    let certify_creation_cmd = CertifyCreation {
        qualifying_data: Tpm2bData::default(),
        creation_hash: create_rsp.creation_hash,
        in_scheme,
        creation_ticket: create_rsp.creation_ticket,
    };
    let certify_creation_handles = CertifyCreationHandles {
        sign_handle: object_handle,
        object_handle,
    };
    let res = execute_with_password_sessions_status(
        &mut sim,
        &certify_creation_cmd,
        certify_creation_handles,
        1,
        &[],
    );
    assert!(res.is_ok());

    // 3. Bad ticket hierarchy (e.g. Owner instead of Endorsement) should fail with TPM_RC_TICKET
    let bad_hierarchy_ticket =
        TpmtTkCreation::Creation(Handle::RH_OWNER, *create_rsp.creation_ticket.digest());
    let certify_creation_cmd_bad_hierarchy = CertifyCreation {
        creation_ticket: bad_hierarchy_ticket,
        ..certify_creation_cmd.clone()
    };
    let res_bad_hierarchy = execute_with_password_sessions_status(
        &mut sim,
        &certify_creation_cmd_bad_hierarchy,
        certify_creation_handles,
        1,
        &[],
    );
    assert_eq!(res_bad_hierarchy.err(), Some(0x0a0));

    // 4. Bad ticket digest should fail with TPM_RC_TICKET
    let mut bad_digest = create_rsp.creation_ticket.digest().get_buffer().to_vec();
    if !bad_digest.is_empty() {
        bad_digest[0] ^= 0xFF; // Modify a byte of digest
    }
    let bad_digest_ticket = TpmtTkCreation::Creation(
        create_rsp.creation_ticket.hierarchy(),
        Tpm2bDigest::from_bytes(&bad_digest).unwrap(),
    );
    let certify_creation_cmd_bad_digest = CertifyCreation {
        creation_ticket: bad_digest_ticket,
        ..certify_creation_cmd.clone()
    };
    let res_bad_digest = execute_with_password_sessions_status(
        &mut sim,
        &certify_creation_cmd_bad_digest,
        certify_creation_handles,
        1,
        &[],
    );
    assert_eq!(res_bad_digest.err(), Some(0x0a0));

    flush_context(&mut sim, object_handle).unwrap();
}

#[test]
fn test_nv_certify_adversarial() {
    let mut sim = create_simulator!();

    // Setup signer primary template (RSA, SHA256, restricted, sign/encrypt)
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
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_signer_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_signer_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_signer_rsp, signer_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_signer_cmd, create_signer_handles, 0, &[])
            .unwrap();
    let signer_handle = signer_rsp_handles.object_handle;

    // Define NV Space (size 4)
    let nv_index_val = 0x0180000F;
    let mut attributes = TpmaNv::OWNERWRITE
        | TpmaNv::OWNERREAD
        | TpmaNv::AUTHWRITE
        | TpmaNv::AUTHREAD
        | TpmaNv::NO_DA;
    attributes.set_type(TpmNt::Ordinary);

    let nv_public_struct = TpmsNvPublic {
        nv_index: Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 4,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);

    let nv_define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let nv_define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &nv_define_cmd, nv_define_handles, 1, &[]).unwrap();

    // Write to NV Space
    let data_to_write = &[0x01, 0x02, 0x03, 0x04];
    let nv_write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(data_to_write).unwrap(),
        offset: 0,
    };
    let nv_write_handles = NVWriteHandles {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &nv_write_cmd, nv_write_handles, 1, &[]).unwrap();

    // 1. Write out of bounds should fail (TPM_RC_SIZE = 0x095)
    let nv_write_bad = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0x05]).unwrap(),
        offset: 4, // offset 4 is out of bounds for size 4 space (range 0..3)
    };
    let res_write_bad =
        execute_with_password_sessions(&mut sim, &nv_write_bad, nv_write_handles, 1, &[]);
    assert_eq!(res_write_bad.err(), Some(0x146));

    // 2. Call NVCertify with correct offset and size (offset 1, size 2)
    let nv_certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::from_bytes(b"nonce").unwrap(),
        in_scheme: None,
        size: 2,
        offset: 1,
    };
    let nv_certify_handles = NVCertifyHandles {
        sign_handle: signer_handle,
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
    };
    let mut resp_buffer = [0u8; 4096];
    let (nv_certify_rsp, _) = execute_nv_certify(
        &mut sim,
        &nv_certify_cmd,
        nv_certify_handles,
        2,
        &[],
        &mut resp_buffer,
    )
    .unwrap();

    let certify_info = nv_certify_rsp.certify_info.0;
    if let TpmuAttest::Nv(nv_cert_info) = certify_info.attested {
        assert_eq!(nv_cert_info.offset, 1);
        assert_eq!(nv_cert_info.nv_contents.get_buffer(), &[0x02, 0x03]);
    } else {
        panic!("Expected NV certify info");
    }

    // 3. Call NVCertify with size out of bounds should fail (TPM_RC_NV_RANGE = 0x146)
    let nv_certify_bad = NVCertify {
        size: 3,
        offset: 2, // 2 + 3 = 5 > 4 (data_size)
        ..nv_certify_cmd.clone()
    };
    let res_certify_bad = execute_with_password_sessions_status(
        &mut sim,
        &nv_certify_bad,
        nv_certify_handles,
        2,
        &[],
    );
    assert_eq!(res_certify_bad.err(), Some(0x146));

    // Flush key
    flush_context(&mut sim, signer_handle).unwrap();
}
