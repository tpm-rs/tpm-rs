#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::Alg;
use tpm2::commands::{
    Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, NVDefineSpace,
    NVDefineSpaceHandles, NVWrite, NVWriteHandles, PolicyAuthorizeNV, PolicyAuthorizeNVHandles,
    PolicyCommandCode, PolicyCommandCodeHandles, PolicyGetDigest, PolicyGetDigestHandles, PolicyOR,
    PolicyORHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve, TpmNt, TpmSe};
use tpm2_simulator::{Simulator, create_simulator};

fn get_ecc_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

// ==========================================
// 1. TPM2_Create Stress Tests
// ==========================================

fn create_parent_key(sim: &mut Simulator) -> Handle {
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle(0x40000001), // Owner hierarchy
    };
    let primary_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(tpm2::TpmtSymDefObject::Aes128(Some(
                    tpm2::TpmiAlgSymMode::CFB,
                ))),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_sensitive = tpm2::Tpm2b(tpm2::TpmsSensitiveCreate {
        user_auth: tpm2::Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        in_sensitive,
        in_public: tpm2::Tpm2b(primary_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let (_, resp_handles) =
        execute_with_password_sessions(sim, &cp_cmd, cp_handles, 1, &[]).unwrap();
    resp_handles.object_handle
}

#[test]
fn test_create_primary_success() {
    let mut sim = create_simulator!();
    let parent_handle = create_parent_key(&mut sim);
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_template();
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = Create {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreateHandles { parent_handle };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(res.is_ok(), "Create failed: {:?}", res.err());
}

#[test]
fn test_create_non_existent_parent() {
    let mut sim = create_simulator!();
    let t_sens = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let in_public = tpm2::Tpm2b(get_ecc_template());
    let cmd = Create {
        in_sensitive: t_sens,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreateHandles {
        parent_handle: Handle(0x80000005), // non-existent transient handle
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    // Should return ReferenceH0 error since parent doesn't exist
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));
}

#[test]
fn test_create_invalid_attributes() {
    let mut sim = create_simulator!();
    let parent_handle = create_parent_key(&mut sim);
    let t_sens = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let mut pub_area = get_ecc_template();
    // fixedTPM without fixedParent (violates TPM rules)
    pub_area.object_attributes = TpmaObject::FIXED_TPM;
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = Create {
        in_sensitive: t_sens,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreateHandles { parent_handle };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    // Should fail with Attributes error for Parameter 2 (inPublic)
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get())
    );
}

#[test]
fn test_create_unsupported_name_alg() {
    let mut sim = create_simulator!();
    let parent_handle = create_parent_key(&mut sim);
    let t_sens = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let mut pub_area = get_ecc_template();
    pub_area.name_alg = Some(TpmiAlgHash::Sm3_256); // unsupported hash alg for name
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = Create {
        in_sensitive: t_sens,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreateHandles { parent_handle };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    // Should fail with Value error
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));
}

// ==========================================
// 2. TPM2_PolicyOR Stress Tests
// ==========================================

#[test]
fn test_policy_or_trial_session() {
    let mut sim = create_simulator!();
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let digest1 = Tpm2bDigest::from_bytes(&[1; 32]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[2; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();

    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyOR on Trial session failed: {:?}",
        res.err()
    );
}

#[test]
fn test_policy_or_policy_session_success() {
    let mut sim = create_simulator!();
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Get current policy digest (starts at zero digest)
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: active_session.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();
    let current_digest = get_digest_rsp.policy_digest;

    // Use current_digest in the list
    let digest2 = Tpm2bDigest::from_bytes(&[2; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[current_digest, digest2]).unwrap();

    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyOR on Policy session failed: {:?}",
        res.err()
    );
}

#[test]
fn test_policy_or_policy_session_mismatch() {
    let mut sim = create_simulator!();
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Digests in list do not match current zero digest
    let digest1 = Tpm2bDigest::from_bytes(&[1; 32]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[2; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();

    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    // Should return Value error since current digest is not in list
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));
}

#[test]
fn test_policy_or_empty_list() {
    let mut sim = create_simulator!();
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let p_hash_list = TpmlDigest::from_slice(&[]).unwrap();
    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    // Empty list should fail with Size error on parameter 1 according to spec
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(tpm2::errors::Position::parameter(1)).get())
    );
}

// ==========================================
// 3. TPM2_PolicyAuthorizeNV Stress Tests
// ==========================================

#[test]
fn test_policy_authorize_nv_success() {
    let mut sim = create_simulator!();

    // 1. Setup policy session
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // 2. Call PolicyCommandCode to change digest to non-zero
    let pcc_cmd = PolicyCommandCode {
        code: TpmCc::Unseal,
    };
    let pcc_handles = PolicyCommandCodeHandles {
        policy_session: active_session.session_handle,
    };
    execute_with_password_sessions(&mut sim, &pcc_cmd, pcc_handles, 0, &[]).unwrap();

    // Get current policy digest
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: active_session.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();
    let target_digest = get_digest_rsp.policy_digest;

    // 3. Define NV Index
    let nv_index_val: u32 = 0x01800003;
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
        data_size: 34, // 2 bytes alg ID + 32 bytes SHA256 digest
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

    // 4. Write TPMT_HA (SHA256 alg ID + digest) to NV Index
    let mut data_to_write = [0u8; 34];
    data_to_write[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    data_to_write[2..34].copy_from_slice(target_digest.get_buffer());

    let nv_write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&data_to_write).unwrap(),
        offset: 0,
    };
    let nv_write_handles = NVWriteHandles {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &nv_write_cmd, nv_write_handles, 1, &[]).unwrap();

    // 5. Call PolicyAuthorizeNV
    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(res.is_ok(), "PolicyAuthorizeNV failed: {:?}", res.err());
}

#[test]
fn test_policy_authorize_nv_mismatch_digest() {
    let mut sim = create_simulator!();

    // 1. Setup policy session
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // 2. Define NV Index
    let nv_index_val: u32 = 0x01800004;
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
        data_size: 34,
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

    // 3. Write wrong digest to NV Index
    let mut data_to_write = [0u8; 34];
    data_to_write[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    data_to_write[2..34].copy_from_slice(&[0xff; 32]); // incorrect digest

    let nv_write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&data_to_write).unwrap(),
        offset: 0,
    };
    let nv_write_handles = NVWriteHandles {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &nv_write_cmd, nv_write_handles, 1, &[]).unwrap();

    // 4. Call PolicyAuthorizeNV (should fail because digests don't match)
    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));
}
