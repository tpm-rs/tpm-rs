//! TPM2_NV_ChangeAuth: ADMIN-role authorization and data preservation.

use crate::_common::{
    define_nv_with_policy_unwrap as define, policy_command_code_active as policy_command_code,
    start_session_active as start_session, *,
};
use tpm2::commands::{NVChangeAuth, NVDefineSpace};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::create_simulator;

/// NV_ChangeAuth with a different authValue size preserves all data of a large index
///
/// NV_ChangeAuth with a different authValue size keeps all data of a large index.
#[test]
fn change_auth_keeps_index_data() {
    let mut sim = create_simulator!();
    let index = 0x0150_0500;
    let size = 1600u16;
    define_change_auth_index(&mut sim, index, size);
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    owner_write(&mut sim, index, 0, &data[..1000]).unwrap();
    owner_write(&mut sim, index, 1000, &data[1000..]).unwrap();

    let name = nv_index_name(&mut sim, index);
    let mut session = start_session(&mut sim, TpmSe::Policy);
    policy_command_code(&mut sim, &session, TpmCc::NVChangeAuth);
    with_session(
        &mut sim,
        &change_auth_cmd(Handle(index), &[0x77; 20]),
        &[&name],
        &mut session,
    )
    .expect("NV_ChangeAuth failed");

    let mut read_back = read_as(&mut sim, Handle::RH_OWNER, index, 0, 1000).unwrap();
    read_back.extend(read_as(&mut sim, Handle::RH_OWNER, index, 1000, size - 1000).unwrap());
    assert_eq!(read_back, data);
}

/// NV_ChangeAuth authorized by an HMAC session fails with TPM_RC_AUTH_TYPE (ADMIN role needs a policy session)
#[test]
fn hmac_session_rejected_for_admin_role() {
    let mut sim = create_simulator!();
    let index = 0x0150_0300;
    define_change_auth_index(&mut sim, index, 8);
    let name = nv_index_name(&mut sim, index);
    let mut session = start_session(&mut sim, TpmSe::HMAC);
    let rc = with_session(
        &mut sim,
        &change_auth_cmd(Handle(index), b"new"),
        &[&name],
        &mut session,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_TYPE.get());
}

/// NV_ChangeAuth authorized with a password session is TPM_RC_AUTH_TYPE
#[test]
fn password_session_rejected() {
    let mut sim = create_simulator!();

    // Define an NV index with authValue="old_pass" and TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE
    let nv_idx = Handle(0x01000030);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = Tpm2b(TpmsNvPublic {
        nv_index: nv_idx,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    });

    let define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::from_bytes(b"old_pass").unwrap(),
        public_info,
    };
    let platform_session = make_auth_session(&[]);
    execute_tpm_command_with_auths(
        &mut sim,
        &define_cmd,
        core::slice::from_ref(&platform_session),
    )
    .expect("Failed to define NV space with old_pass");

    // Call TPM2_NV_ChangeAuth("new_pass") authorized with password session "old_pass"
    // Per TCG spec Section 31.15.2 and CPCTPM_TC2_3_33_15_03, password sessions must be rejected with TPM_RC_AUTH_TYPE
    let change_cmd = NVChangeAuth {
        nv_index: nv_idx,
        new_auth: Tpm2bAuth::from_bytes(b"new_pass").unwrap(),
    };
    let old_auth_session = make_auth_session(b"old_pass");
    let res = execute_tpm_command_with_auths(
        &mut sim,
        &change_cmd,
        core::slice::from_ref(&old_auth_session),
    );
    assert_eq!(res.err(), Some(TpmRc::AUTH_TYPE.get()));
}

/// NV_ChangeAuth: HMAC session is TPM_RC_AUTH_TYPE; a policy session without PolicyCommandCode is TPM_RC_POLICY_FAIL
#[test]
fn policy_without_command_code_rejected() {
    let mut sim = create_simulator!();
    let index = 0x0150_0301;
    // The authPolicy is the empty policy, so a policy session without
    // TPM2_PolicyCommandCode satisfies the digest but not the ADMIN role.
    define(
        &mut sim,
        index,
        OWNER_RW | TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        8,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, index);

    // HMAC sessions can't provide ADMIN authorization of an NV Index.
    let mut hmac = start_session(&mut sim, TpmSe::HMAC);
    let rc = with_session(
        &mut sim,
        &change_auth_cmd(Handle(index), b"x"),
        &[&name],
        &mut hmac,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_TYPE.get());

    // A policy session that never ran TPM2_PolicyCommandCode fails with POLICY_FAIL.
    let mut policy = start_session(&mut sim, TpmSe::Policy);
    let rc = with_session(
        &mut sim,
        &change_auth_cmd(Handle(index), b"x"),
        &[&name],
        &mut policy,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::POLICY_FAIL.with(Position::session(1)).get());
}
