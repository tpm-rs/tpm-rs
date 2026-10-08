#![forbid(unsafe_code)]

use crate::test_utils::*;
use tpm2::commands::{
    Certify, CertifyCreation, CertifyCreationHandles, CertifyHandles, CreatePrimary,
    CreatePrimaryHandles, NVCertify, NVCertifyHandles, NVDefineSpace, NVDefineSpaceHandles,
    NVReadPublic, NVReadPublicHandles, NVWrite, NVWriteHandles,
};
use tpm2::{Handle, TpmNt};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmaNv, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmlPcrSelection,
    TpmsNvPublic, TpmsPcrSelection, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic, TpmtRsaScheme,
    TpmtSigScheme, TpmtSignature, TpmuAttest,
};
use tpm2_platform_linux::{LinuxRng, PlatformCryptoProvider};
use tpm2_simulator::{Simulator, create_simulator};

// Original Go test: certify_test.go - TestCertify
#[test]
fn test_certify() {
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

    let mut pcr_select = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];
    pcr_select[0] |= 1 << 7;
    let tpms_pcr_selection = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &pcr_select[..3]).unwrap();
    let pcr_selection = TpmlPcrSelection::from_slice(&[tpms_pcr_selection]).unwrap();

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

    // Create primary subject key
    let mut subject_pub_area = pub_area;
    if let PublicParmsAndId::Rsa(rsa_parms, _) = subject_pub_area.parms_and_id {
        subject_pub_area.parms_and_id = PublicParmsAndId::Rsa(
            rsa_parms,
            Tpm2bPublicKeyRsa::from_bytes(b"subject key").unwrap(),
        );
    }
    let subject_in_public = tpm2::Tpm2b(subject_pub_area);

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

    // Verification
    let certify_info = certify_rsp.certify_info.0;
    assert_eq!(certify_info.extra_data.get_buffer(), original_buffer);

    let mut attest_buf = [0u8; 1024];
    let attest_len = marshal_to_slice(&certify_info, &mut attest_buf);
    let attest_bytes = &attest_buf[..attest_len];

    // Compute SHA256 hash of attestation data
    let provider = PlatformCryptoProvider;
    use tpm2::crypto::Asymmetric;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(
        &provider,
        tpm2::TpmiAlgHash::Sha256,
        attest_bytes,
        &mut digest_buf,
    )
    .unwrap();

    // Verify signature
    let pub_struct = signer_rsp.out_public.0;
    if let PublicParmsAndId::Rsa(_, rsa_unique) = pub_struct.parms_and_id {
        let (sig_alg, sig_bytes) = match &certify_rsp.signature {
            Some(TpmtSignature::Rsassa(rsa_sig)) => {
                assert_eq!(rsa_sig.hash, tpm2::TpmiAlgHash::Sha256);
                (tpm2::Alg::RSASSA, rsa_sig.sig.get_buffer())
            }
            Some(TpmtSignature::Rsapss(rsa_sig)) => {
                assert_eq!(rsa_sig.hash, tpm2::TpmiAlgHash::Sha256);
                (tpm2::Alg::RSAPSS, rsa_sig.sig.get_buffer())
            }
            _ => panic!("Expected RSA signature"),
        };

        let verify_res = provider.verify_inner(sig_alg, rsa_unique.get_buffer(), digest, sig_bytes);
        assert!(
            verify_res.is_ok(),
            "Signature verification failed: {:?}",
            verify_res
        );
    } else {
        panic!("Expected RSA public parameters");
    }

    // Flush keys
    flush_context(&mut sim, subject_handle).unwrap();
    flush_context(&mut sim, signer_handle).unwrap();
}

// Original Go test: certify_test.go - TestCreateAndCertifyCreation
#[test]
fn test_create_and_certify_creation() {
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

    let mut pcr_select = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];
    pcr_select[0] |= 1 << 7;
    let tpms_pcr_selection = TpmsPcrSelection::new(TpmiAlgHash::Sha1, &pcr_select[..3]).unwrap();
    let pcr_selection = TpmlPcrSelection::from_slice(&[tpms_pcr_selection]).unwrap();

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

    // Call CertifyCreation
    let in_scheme = Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256));
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
    let mut resp_buffer = [0u8; 4096];
    let (certify_creation_rsp, _) = execute_certify_creation(
        &mut sim,
        &certify_creation_cmd,
        certify_creation_handles,
        1,
        &[],
        &mut resp_buffer,
    )
    .unwrap();

    // Verification
    let certify_info = certify_creation_rsp.certify_info.0;
    if let TpmuAttest::Creation(creation_info) = certify_info.attested {
        assert_eq!(
            creation_info.object_name.get_buffer(),
            create_rsp.name.get_buffer()
        );
    } else {
        panic!("Expected creation attestation info");
    }

    let mut attest_buf = [0u8; 1024];
    let attest_len = marshal_to_slice(&certify_info, &mut attest_buf);
    let attest_bytes = &attest_buf[..attest_len];

    // Compute SHA256 hash
    let provider = PlatformCryptoProvider;
    use tpm2::crypto::Asymmetric;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(
        &provider,
        tpm2::TpmiAlgHash::Sha256,
        attest_bytes,
        &mut digest_buf,
    )
    .unwrap();

    // Verify signature
    let pub_struct = create_rsp.out_public.0;
    if let PublicParmsAndId::Rsa(_, rsa_unique) = pub_struct.parms_and_id {
        let (sig_alg, sig_bytes) = match &certify_creation_rsp.signature {
            Some(TpmtSignature::Rsassa(rsa_sig)) => {
                assert_eq!(rsa_sig.hash, tpm2::TpmiAlgHash::Sha256);
                (tpm2::Alg::RSASSA, rsa_sig.sig.get_buffer())
            }
            Some(TpmtSignature::Rsapss(rsa_sig)) => {
                assert_eq!(rsa_sig.hash, tpm2::TpmiAlgHash::Sha256);
                (tpm2::Alg::RSAPSS, rsa_sig.sig.get_buffer())
            }
            _ => panic!("Expected RSA signature"),
        };

        let verify_res = provider.verify_inner(sig_alg, rsa_unique.get_buffer(), digest, sig_bytes);
        assert!(
            verify_res.is_ok(),
            "Signature verification failed: {:?}",
            verify_res
        );
    } else {
        panic!("Expected RSA public parameters");
    }

    // Flush key
    flush_context(&mut sim, object_handle).unwrap();
}

// Original Go test: certify_test.go - TestNVCertify
#[test]
fn test_nv_certify() {
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

    // Use empty password for the signer to allow unified password session executing
    let create_signer_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_signer_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (signer_rsp, signer_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_signer_cmd, create_signer_handles, 0, &[])
            .unwrap();
    let signer_handle = signer_rsp_handles.object_handle;

    // Define NV Space
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

    // Get NV Name
    let nv_read_pub_cmd = NVReadPublic {};
    let nv_read_pub_handles = NVReadPublicHandles {
        nv_index: Handle(nv_index_val),
    };
    let (nv_read_pub_rsp, _) =
        execute_with_password_sessions(&mut sim, &nv_read_pub_cmd, nv_read_pub_handles, 0, &[])
            .unwrap();
    let _nv_name = nv_read_pub_rsp.nv_name;

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
    // Authorized with NV Index auth (empty)
    execute_with_password_sessions(&mut sim, &nv_write_cmd, nv_write_handles, 1, &[]).unwrap();

    // Call NVCertify
    let qualifying_data = b"nonce";
    let nv_certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::from_bytes(qualifying_data).unwrap(),
        in_scheme: None,
        size: 0,
        offset: 0,
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

    // Verification
    let certify_info = nv_certify_rsp.certify_info.0;
    assert_eq!(certify_info.extra_data.get_buffer(), qualifying_data);

    let mut attest_buf = [0u8; 1024];
    let attest_len = marshal_to_slice(&certify_info, &mut attest_buf);
    let attest_bytes = &attest_buf[..attest_len];

    // Compute SHA256 hash
    let provider = PlatformCryptoProvider;
    use tpm2::crypto::Asymmetric;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(
        &provider,
        tpm2::TpmiAlgHash::Sha256,
        attest_bytes,
        &mut digest_buf,
    )
    .unwrap();

    // Verify signature
    let pub_struct = signer_rsp.out_public.0;
    if let PublicParmsAndId::Rsa(_, rsa_unique) = pub_struct.parms_and_id {
        let (sig_alg, sig_bytes) = match &nv_certify_rsp.signature {
            Some(TpmtSignature::Rsassa(rsa_sig)) => {
                assert_eq!(rsa_sig.hash, tpm2::TpmiAlgHash::Sha256);
                (tpm2::Alg::RSASSA, rsa_sig.sig.get_buffer())
            }
            Some(TpmtSignature::Rsapss(rsa_sig)) => {
                assert_eq!(rsa_sig.hash, tpm2::TpmiAlgHash::Sha256);
                (tpm2::Alg::RSAPSS, rsa_sig.sig.get_buffer())
            }
            _ => panic!("Expected RSA signature"),
        };

        let verify_res = provider.verify_inner(sig_alg, rsa_unique.get_buffer(), digest, sig_bytes);
        assert!(
            verify_res.is_ok(),
            "Signature verification failed: {:?}",
            verify_res
        );
    } else {
        panic!("Expected RSA public parameters");
    }

    // Flush key
    flush_context(&mut sim, signer_handle).unwrap();
}
