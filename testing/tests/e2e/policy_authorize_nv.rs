//! TPM2_PolicyAuthorizeNV: policies stored in NV indices and handle/digest validation.

use crate::_common::*;
use tpm2::commands::{
    NVDefineSpace, NVWrite, PolicyAuthorizeNV, PolicyCommandCode, PolicyGetDigest,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Handle, Tpm2bAuth, Tpm2bDigest, TpmCc, TpmNt, TpmSe, TpmaNv, TpmiAlgHash, TpmsNvPublic, *,
};
use tpm2_simulator::create_simulator;

/// PolicyAuthorizeNV fails when the NV index holds a SHA-1 digest for a SHA-256 session
#[test]
fn digest_hash_alg_mismatch_rejected() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

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

    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyAuthorizeNV succeeded with incorrect hash algorithm in NV index!"
    );
}

/// PolicyAuthorizeNV fails when the stored digest differs from the session's policy digest
#[test]
fn digest_value_mismatch_rejected() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

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

    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyAuthorizeNV succeeded with mismatching digest in NV index!"
    );
}

/// PolicyAuthorizeNV with RH_ENDORSEMENT as authHandle is TPM_RC_VALUE
#[test]
fn endorsement_auth_handle_rejected() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

    // Write some data (SHA256 alg ID + 32-byte zero digest)
    let mut data = Vec::new();
    data.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    data.extend_from_slice(&[0u8; 32]);
    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&data).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

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

    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle::RH_ENDORSEMENT, // Invalid auth handle type!
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get()),
        "BUG: PolicyAuthorizeNV succeeded (or failed with wrong error) with RHEndorsement auth handle!"
    );
}

/// PolicyAuthorizeNV succeeds when the stored digest matches the session's policy digest
#[test]
fn matching_digest_succeeds() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

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

    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    // Should succeed because NV digest matches session's zero digest!
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(
        res.is_ok(),
        "PolicyAuthorizeNV failed with correct matching digest and authorization: {:?}",
        res.err()
    );
}

/// PolicyAuthorizeNV succeeds when the index holds the current policy digest as TPMT_HA.
#[test]
fn matching_nv_digest_succeeds() {
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
        policy_session: active_session.session_handle,
        code: TpmCc::Unseal,
    };
    execute_with_password_sessions(&mut sim, &pcc_cmd, 0, &[]).unwrap();

    // Get current policy digest
    let get_digest_cmd = PolicyGetDigest {
        policy_session: active_session.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &nv_define_cmd, 1, &[]).unwrap();

    // 4. Write TPMT_HA (SHA256 alg ID + digest) to NV Index
    let mut data_to_write = [0u8; 34];
    data_to_write[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    data_to_write[2..34].copy_from_slice(target_digest.get_buffer());

    let nv_write_cmd = NVWrite {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&data_to_write).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &nv_write_cmd, 1, &[]).unwrap();

    // 5. Call PolicyAuthorizeNV
    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(res.is_ok(), "PolicyAuthorizeNV failed: {:?}", res.err());
}

/// PolicyAuthorizeNV fails with VALUE when the index holds a different digest.
#[test]
fn mismatching_nv_digest_rejected() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &nv_define_cmd, 1, &[]).unwrap();

    // 3. Write wrong digest to NV Index
    let mut data_to_write = [0u8; 34];
    data_to_write[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    data_to_write[2..34].copy_from_slice(&[0xff; 32]); // incorrect digest

    let nv_write_cmd = NVWrite {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&data_to_write).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &nv_write_cmd, 1, &[]).unwrap();

    // 4. Call PolicyAuthorizeNV (should fail because digests don't match)
    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));
}

/// PolicyAuthorizeNV with owner auth on an index without OWNERREAD is TPM_RC_NV_AUTHORIZATION
#[test]
fn owner_without_read_rejected() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

    // Write some data (SHA256 alg ID + 32-byte zero digest)
    let mut data = Vec::new();
    data.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    data.extend_from_slice(&[0u8; 32]);
    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&data).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

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

    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    // Should fail with NvAuthorization error because OWNERREAD is not set
    assert_eq!(res.err(), Some(TpmRc::NV_AUTHORIZATION.get()));
}

/// PolicyAuthorizeNV accepts a policy-authorized index; a wrong owner password fails with BAD_AUTH+S1.
#[test]
fn policy_authorized_index_and_bad_owner_auth() {
    // The handler no longer re-verifies authorization (the engine does, with properly positioned
    // errors), so an index authorized by a policy session is no longer rejected for lacking
    // TPMA_NV_AUTHREAD.
    let mut sim = create_simulator!();
    let index = 0x0150_0026;
    define_policy_read_authorize_index(&mut sim, index);
    let target =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_authorize_nv_with_policy_auth(&mut sim, index, target).unwrap();

    // A wrong owner password is rejected with a session-positioned error.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let owner_index = 0x0150_0027;
    define_nv_empty_policy(&mut sim, owner_index, nv_attrs(TpmaNv::OWNERREAD), 34);
    let err = execute_with_password_sessions(
        &mut sim,
        &PolicyAuthorizeNV {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(owner_index),
            policy_session: s,
        },
        1,
        b"wrong",
    )
    .map(|_| ())
    .unwrap_err();
    // The owner is DA-exempt (C IsDAExempted), so the failure is TPM_RC_BAD_AUTH + RC_S1.
    assert_eq!(err, TpmRc::BAD_AUTH.with(Position::session(1)).get());
}

/// PolicyAuthorizeNV: complete TPMT_HA of wrong hash is HASH, truncated is INSUFFICIENT, wrong authHandle, undefined index HANDLE+H2.
#[test]
fn tpmt_ha_unmarshal_and_error_positions() {
    let mut sim = create_simulator!();
    // A complete SHA-256 TPMT_HA with a SHA-384 session: TPM_RC_HASH, not TPM_RC_INSUFFICIENT.
    let index = 0x0150_0023;
    define_nv_empty_policy(&mut sim, index, nv_attrs(TpmaNv::OWNERREAD), 34);
    let mut tpmt_ha = vec![0x00, 0x0B];
    tpmt_ha.extend_from_slice(&[0; 32]);
    write_nv_owner(&mut sim, index, &tpmt_ha);
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha384).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle::RH_OWNER, index, s),
        Err(TpmRc::HASH.get())
    );

    // A truncated SHA-256 TPMT_HA with a SHA-1 session: TPM_RC_INSUFFICIENT, not TPM_RC_HASH.
    let short = 0x0150_0024;
    define_nv_empty_policy(&mut sim, short, nv_attrs(TpmaNv::OWNERREAD), 24);
    let mut truncated = vec![0x00, 0x0B];
    truncated.extend_from_slice(&[0; 22]);
    write_nv_owner(&mut sim, short, &truncated);
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha1).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle::RH_OWNER, short, s),
        Err(TpmRc::INSUFFICIENT.get())
    );

    // authHandle is a different NV Index: TPM_RC_NV_AUTHORIZATION.
    let other = 0x0150_0025;
    define_nv_empty_policy(&mut sim, other, nv_attrs(TpmaNv::empty()), 8);
    write_nv_owner(&mut sim, other, &[0; 8]);
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle(other), index, s),
        Err(TpmRc::NV_AUTHORIZATION.get())
    );

    // Undefined nvIndex: TPM_RC_HANDLE + RC_H2.
    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle::RH_OWNER, 0x0150_0098, s),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );
}

/// PolicyAuthorizeNV in a trial session succeeds on an unwritten index and updates the digest with the NV name
#[test]
fn trial_session_skips_index_check() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

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

    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: trial_session.session_handle,
    };

    // Execute PolicyAuthorizeNV. Should succeed because it is a Trial session
    // even though the NV Index has not been written yet!
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(
        res.is_ok(),
        "PolicyAuthorizeNV failed on Trial session: {:?}",
        res.err()
    );

    // Verify trial session digest: H(zero_digest || TPM_CC_PolicyAuthorizeNV || nvIndex->Name)
    let get_digest_cmd = PolicyGetDigest {
        policy_session: trial_session.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

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

/// PolicyAuthorizeNV on an index holding a truncated TPMT_HA fails with TPM_RC_INSUFFICIENT
#[test]
fn truncated_stored_digest_rejected() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

    // Write a truncated TPMT_HA (SHA-256 algorithm ID + 8 digest bytes) so the index is
    // initialized; C TPMT_HA_Unmarshal then fails with TPM_RC_INSUFFICIENT (an all-zero algorithm
    // ID would be TPM_RC_HASH instead).
    let mut truncated_ha = [0u8; 10];
    truncated_ha[..2].copy_from_slice(&[0x00, 0x0B]);
    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&truncated_ha).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

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

    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    // Should return Insufficient error because 10 < 34
    assert_eq!(res.err(), Some(TpmRc::INSUFFICIENT.get()));
}

/// PolicyAuthorizeNV on an unwritten NV index fails in a policy session
#[test]
fn unwritten_index_rejected() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

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

    let cmd = PolicyAuthorizeNV {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        policy_session: policy_session.session_handle,
    };

    // Execute PolicyAuthorizeNV. Should fail because NV space is unwritten.
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyAuthorizeNV succeeded on an unwritten NV index!"
    );
}
