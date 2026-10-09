#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::Alg;
use tpm2::commands::{
    Create, CreateHandles, CreateLoaded, CreateLoadedHandles, NVDefineSpace, NVDefineSpaceHandles,
    NVWrite, NVWriteHandles, PolicyAuthorizeNV, PolicyAuthorizeNVHandles, PolicyGetDigest,
    PolicyGetDigestHandles, PolicyOR, PolicyORHandles,
};
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2::{Handle, TpmCc, TpmEccCurve, TpmSe};
use tpm2_simulator::{Simulator, create_simulator};

fn get_ecc_signing_key_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT, // Not decrypt, not restricted
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

fn write_digest_to_nv(sim: &mut Simulator<'_>, nv_index_val: u32, alg: TpmiAlgHash, digest: &[u8]) {
    let mut data = Vec::new();
    data.extend_from_slice(&Alg::from(alg).id().to_be_bytes());
    data.extend_from_slice(digest);

    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&data).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(sim, &write_cmd, write_handles, 1, &[]).unwrap();
}

#[test]
fn test_create_invalid_parent() {
    let mut sim = create_simulator!();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_signing_key_template();
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = Create {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreateHandles {
        parent_handle: Handle(0x80000099), // Invalid transient handle
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: Create succeeded with invalid parent handle!"
    );
}

#[test]
fn test_create_non_decrypt_parent() {
    let mut sim = create_simulator!();

    // 1. Create a non-decrypt key under Owner
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_signing_key_template();
    let in_public_template = crate::test_utils::make_template(&pub_area);

    let load_cmd = CreateLoaded {
        in_sensitive,
        in_public: in_public_template,
    };
    let load_handles = CreateLoadedHandles {
        parent_handle: Handle::RH_OWNER,
    };
    let (_, rsp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]).unwrap();
    let bad_parent_handle = rsp_handles.object_handle;

    // 2. Try to create a new key under this non-decrypt parent
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = Create {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreateHandles {
        parent_handle: bad_parent_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: Create succeeded using a non-decrypt / non-parent key as parent!"
    );
}

#[test]
fn test_policy_or_empty_list() {
    let mut sim = create_simulator!();

    // Start a Trial session
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

    let p_hash_list = TpmlDigest::from_slice(&[]).unwrap(); // Empty list!
    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: trial_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyOR succeeded with an empty digest list! Spec requires size >= 2."
    );
}

#[test]
fn test_policy_or_single_list() {
    let mut sim = create_simulator!();

    // Start a Trial session
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

    let digest = Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest]).unwrap(); // Single element!
    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: trial_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyOR succeeded with a single digest list! Spec requires size >= 2."
    );
}

#[test]
fn test_policy_or_working_flow() {
    let mut sim = create_simulator!();

    // Start Policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Initial policy digest is Zero Digest (32 bytes of 0)
    let zero_digest = Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap();
    let dummy_digest = Tpm2bDigest::from_bytes(&[1u8; 32]).unwrap();

    // 1. Call PolicyOR with list containing zero_digest and dummy_digest. Should succeed.
    let p_hash_list = TpmlDigest::from_slice(&[zero_digest, dummy_digest]).unwrap();
    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyOR failed with valid digest list containing current digest"
    );

    // 2. Call PolicyOR again. The current digest is now: hash(zero_digest || TPM_CC_PolicyOR || pHashList)
    // If we call PolicyOR with a list NOT containing this new digest, it should fail.
    let bad_list = TpmlDigest::from_slice(&[zero_digest, dummy_digest]).unwrap();
    let cmd_bad = PolicyOR {
        p_hash_list: bad_list,
    };
    let res_bad = execute_with_password_sessions(&mut sim, &cmd_bad, handles, 0, &[]);
    assert!(
        res_bad.is_err(),
        "BUG/Anomaly: PolicyOR did not fail when current digest is missing from list"
    );
}

#[test]
fn test_policy_authorize_nv_unwritten() {
    let mut sim = create_simulator!();

    // Define NV space, but do NOT write to it.
    let nv_index_val = 0x01600001;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, define_handles, 1, &[]).unwrap();

    // Start Policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    // Execute PolicyAuthorizeNV. Should fail because NV space is unwritten.
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyAuthorizeNV succeeded on an unwritten NV index!"
    );
}

#[test]
fn test_policy_authorize_nv_wrong_hash() {
    let mut sim = create_simulator!();

    // Define NV index
    let nv_index_val = 0x01600002;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(
        &mut sim,
        &define_cmd,
        NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .unwrap();

    // Write SHA1 digest (different hash alg from session's SHA256)
    write_digest_to_nv(&mut sim, nv_index_val, TpmiAlgHash::Sha1, &[0u8; 20]);

    // Start Policy session with SHA256
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyAuthorizeNV succeeded with incorrect hash algorithm in NV index!"
    );
}

#[test]
fn test_policy_authorize_nv_wrong_digest() {
    let mut sim = create_simulator!();

    // Define NV index
    let nv_index_val = 0x01600003;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(
        &mut sim,
        &define_cmd,
        NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .unwrap();

    // Write a dummy SHA256 digest (e.g. all 1s, which differs from session's zero digest)
    write_digest_to_nv(&mut sim, nv_index_val, TpmiAlgHash::Sha256, &[1u8; 32]);

    // Start Policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyAuthorizeNV succeeded with mismatching digest in NV index!"
    );
}

#[test]
fn test_policy_authorize_nv_working_flow() {
    let mut sim = create_simulator!();

    // Define NV index
    let nv_index_val = 0x01600004;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(
        &mut sim,
        &define_cmd,
        NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .unwrap();

    // Initial policy digest is Zero Digest (32 bytes of 0)
    let zero_digest = [0u8; 32];
    write_digest_to_nv(&mut sim, nv_index_val, TpmiAlgHash::Sha256, &zero_digest);

    // Start Policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    // Should succeed because NV digest matches session's zero digest!
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(
        res.is_ok(),
        "PolicyAuthorizeNV failed with correct matching digest and authorization: {:?}",
        res.err()
    );
}

#[test]
fn test_policy_or_trial_digest_update() {
    let mut sim = create_simulator!();

    // Start a Trial session
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

    let digest1 = Tpm2bDigest::from_bytes(&[1u8; 32]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[2u8; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();
    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: trial_session.session_handle,
    };

    execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]).unwrap();

    // Verify policy digest is updated to H(0 || TPM_CC_PolicyOR || p_hash_list)
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: trial_session.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Zero digest (32 bytes)
    hasher.update([0u8; 32]);
    // TPM_CC_PolicyOR
    hasher.update((TpmCc::PolicyOR.code()).to_be_bytes());
    // Concatenated raw digests from p_hash_list
    for digest in p_hash_list.digests() {
        hasher.update(digest.get_buffer());
    }
    let expected_digest = hasher.finalize();

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        expected_digest.as_slice()
    );
}

#[test]
fn test_policy_authorize_nv_trial_session() {
    let mut sim = create_simulator!();

    // Define NV space, but do NOT write to it.
    let nv_index_val = 0x01600005;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, define_handles, 1, &[]).unwrap();

    // Start a Trial session
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

    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: trial_session.session_handle,
    };

    // Execute PolicyAuthorizeNV. Should succeed because it is a Trial session
    // even though the NV Index has not been written yet!
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(
        res.is_ok(),
        "PolicyAuthorizeNV failed on Trial session: {:?}",
        res.err()
    );

    // Verify trial session digest: H(zero_digest || TPM_CC_PolicyAuthorizeNV || nvIndex->Name)
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: trial_session.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();

    // Let's compute the expected digest
    // nvIndex->Name is sha256(public_info_marshalled) prefixed with AlgId::SHA256 (0x000b)
    let mut nv_pub_buf = [0u8; 1024];
    let nv_pub_struct = define_cmd.public_info.0;
    let nv_pub_len = marshal_to_slice(&nv_pub_struct, &mut nv_pub_buf);

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&nv_pub_buf[..nv_pub_len]);
    let nv_name_digest = hasher.finalize();

    let mut nv_name = Vec::new();
    nv_name.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    nv_name.extend_from_slice(&nv_name_digest);

    let mut hasher2 = Sha256::new();
    // Zero digest (32 bytes)
    hasher2.update([0u8; 32]);
    // TPM_CC_PolicyAuthorizeNV
    hasher2.update((TpmCc::PolicyAuthorizeNV.code()).to_be_bytes());
    // nvIndex->Name
    hasher2.update(&nv_name);
    let expected_digest = hasher2.finalize();

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        expected_digest.as_slice()
    );
}

#[test]
fn test_policy_authorize_nv_insufficient_size() {
    let mut sim = create_simulator!();

    // Define NV space with size 10 (less than 34)
    let nv_index_val = 0x01600006;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 10,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, define_handles, 1, &[]).unwrap();

    // Write a truncated TPMT_HA (SHA-256 algorithm ID + 8 digest bytes) so the index is
    // initialized; C TPMT_HA_Unmarshal then fails with TPM_RC_INSUFFICIENT (an all-zero algorithm
    // ID would be TPM_RC_HASH instead).
    let mut truncated_ha = [0u8; 10];
    truncated_ha[..2].copy_from_slice(&[0x00, 0x0B]);
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&truncated_ha).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // Start Policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    // Should return Insufficient error because 10 < 34
    assert_eq!(res.err(), Some(TpmRc::INSUFFICIENT.get()));
}

#[test]
fn test_policy_authorize_nv_no_read_privilege() {
    let mut sim = create_simulator!();

    // Define NV space with OWNERWRITE but NOT OWNERREAD (i.e. no read privilege for owner)
    let nv_index_val = 0x01600007;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD, // No OWNERREAD!
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, define_handles, 1, &[]).unwrap();

    // Write some data (SHA256 alg ID + 32-byte zero digest)
    let mut data = Vec::new();
    data.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    data.extend_from_slice(&[0u8; 32]);
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&data).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // Start Policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    // Should fail with NvAuthorization error because OWNERREAD is not set
    assert_eq!(res.err(), Some(TpmRc::NV_AUTHORIZATION.get()));
}

fn get_ecc_decrypt_parent_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED, // decrypt and restricted parent key
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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

fn create_ecc_parent_key(sim: &mut Simulator<'_>) -> Handle {
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_decrypt_parent_template();
    let in_public_template = crate::test_utils::make_template(&pub_area);

    let load_cmd = CreateLoaded {
        in_sensitive,
        in_public: in_public_template,
    };
    let load_handles = CreateLoadedHandles {
        parent_handle: Handle::RH_OWNER,
    };
    let (_, rsp_handles) =
        execute_with_password_sessions(sim, &load_cmd, load_handles, 1, &[]).unwrap();
    rsp_handles.object_handle
}

#[test]
fn test_create_parent_hierarchy() {
    let mut sim = create_simulator!();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_signing_key_template();
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = Create {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreateHandles {
        parent_handle: Handle::RH_OWNER, // Hierarchy handle!
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    // parentHandle is TPMI_DH_OBJECT, so C rejects RH_OWNER at handle unmarshal
    // with TPM_RC_VALUE + H1 (0x184).
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get()),
        "BUG: Create succeeded (or failed with wrong error) when using RH_OWNER directly as parent!"
    );
}

#[test]
fn test_policy_or_mismatch_sizes() {
    let mut sim = create_simulator!();

    // Start a Trial session
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

    // Elements with different sizes: 20 bytes (SHA1) and 32 bytes (SHA256)
    let digest1 = Tpm2bDigest::from_bytes(&[1u8; 20]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[2u8; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();
    let cmd = PolicyOR { p_hash_list };
    let handles = PolicyORHandles {
        policy_session: trial_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_ok(),
        "Trial session should succeed when digest sizes are mismatching"
    );

    // Policy session should fail with Value
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let handles_policy = PolicyORHandles {
        policy_session: policy_session.session_handle,
    };
    let res_policy = execute_with_password_sessions(&mut sim, &cmd, handles_policy, 0, &[]);
    // TPM_RCS_VALUE + RC_PolicyOR_pHashList (C PolicyOR.c).
    assert_eq!(
        res_policy.err(),
        Some(0x1C4),
        "Policy session should fail with Value (+RC_P1) when digest sizes are mismatching"
    );
}

#[test]
fn test_policy_authorize_nv_endorsement_handle() {
    let mut sim = create_simulator!();

    let nv_index_val = 0x01600008;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, define_handles, 1, &[]).unwrap();

    // Write some data (SHA256 alg ID + 32-byte zero digest)
    let mut data = Vec::new();
    data.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    data.extend_from_slice(&[0u8; 32]);
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&data).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // Start Policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cmd = PolicyAuthorizeNV {};
    let handles = PolicyAuthorizeNVHandles {
        auth_handle: Handle::RH_ENDORSEMENT, // Invalid auth handle type!
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get()),
        "BUG: PolicyAuthorizeNV succeeded (or failed with wrong error) with RHEndorsement auth handle!"
    );
}

#[test]
fn test_create_unsupported_name_alg_sm3256() {
    let mut sim = create_simulator!();
    let parent_handle = create_ecc_parent_key(&mut sim);

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let mut pub_area = get_ecc_signing_key_template();
    pub_area.name_alg = Some(TpmiAlgHash::Sm3_256); // unsupported hash alg for name!
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = Create {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreateHandles { parent_handle };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    // C TPMI_ALG_HASH unmarshal of nameAlg in inPublic returns TPM_RC_HASH,
    // reported as HASH+P2 (0x2C3).
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(tpm2::errors::Position::parameter(2)).get()),
        "BUG: Create succeeded (or failed with wrong error) with unsupported name alg SM3256!"
    );
}
