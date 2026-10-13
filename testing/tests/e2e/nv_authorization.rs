//! NV index authorization: owner/platform/index auth, AUTHREAD/AUTHWRITE and policy access.

use crate::_common::{
    define_nv_raw as define_nv, define_nv_with_policy_unwrap as define,
    send_rc_with_auth_entries as rc, start_session_active as start_session,
    start_session_of_type as start, *,
};
use tpm2::commands::*;
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_simulator::create_simulator;

/// Owner/platform authorization without the matching OWNER*/PP* attribute is TPM_RC_NV_AUTHORIZATION
///
/// Owner/platform authorization without the matching attribute is `TPM_RC_NV_AUTHORIZATION`.
#[test]
fn hierarchy_auth_without_attribute_rejected() {
    let mut sim = create_simulator!();
    let ext = 0x0150_0410;
    define(
        &mut sim,
        ext,
        TpmaNv::from(TpmNt::Extend) | OWNER_RW,
        32,
        &[],
    );
    let cmd = NVExtend {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(ext),
        data: Tpm2bMaxNvBuffer::from_bytes(&[1]).unwrap(),
    };
    assert_eq!(
        exec_with_empty_passwords(&mut sim, &cmd, 1).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );

    let bits = 0x0150_0411;
    define(&mut sim, bits, TpmaNv::from(TpmNt::Bits) | OWNER_RW, 8, &[]);
    assert_eq!(
        exec_with_empty_passwords(
            &mut sim,
            &NVSetBits {
                auth_handle: Handle::RH_PLATFORM,
                nv_index: Handle(bits),
                bits: 1
            },
            1
        )
        .unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );

    let locks = 0x0150_0412;
    define(
        &mut sim,
        locks,
        TpmaNv::PPREAD
            | TpmaNv::PPWRITE
            | TpmaNv::AUTHREAD
            | TpmaNv::AUTHWRITE
            | TpmaNv::WRITEDEFINE
            | TpmaNv::READ_STCLEAR,
        8,
        &[],
    );
    assert_eq!(
        exec_with_empty_passwords(
            &mut sim,
            &NVWriteLock {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(locks)
            },
            1
        )
        .unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );
    assert_eq!(
        exec_with_empty_passwords(
            &mut sim,
            &NVReadLock {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(locks)
            },
            1
        )
        .unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );
}

/// NV_Write/NV_Certify with index auth fail on wrong password and succeed with the correct one
#[test]
fn index_password_write_and_certify() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500005;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHWRITE
            | TpmaNv::AUTHREAD
            | TpmaNv::OWNERWRITE
            | TpmaNv::OWNERREAD
            | TpmaNv::NO_DA,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::from_bytes(b"nvpassword").unwrap(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    // 1. Try writing with NV Index auth but incorrect password
    let write_cmd = NVWrite {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 10]).unwrap(),
        offset: 0,
    };
    let res = execute_with_password_sessions(&mut sim, &write_cmd, 1, b"wrongpass");
    match res {
        Err(err) => assert_eq!(err, 0x9A2), // BadAuth for session 1
        Ok(_) => panic!("Expected BadAuth error, but command succeeded"),
    }

    // 2. Try writing with NV Index auth and correct password
    execute_with_password_sessions(&mut sim, &write_cmd, 1, b"nvpassword").unwrap();

    // 3. Try certifying with NV Index auth but incorrect password
    let certify_cmd = NVCertify {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 0,
    };
    let res_cert = nv_certify_pw(&mut sim, &certify_cmd, &[], b"wrongpass");
    match res_cert {
        Err(err) => assert_eq!(err, 0xAA2), // BadAuth for session 2 (authHandle)
        Ok(_) => panic!("Expected BadAuth error, but command succeeded"),
    }

    // 4. Try certifying with NV Index auth and correct password
    nv_certify_pw(&mut sim, &certify_cmd, &[], b"nvpassword").unwrap();
}

/// NV indices authorizing themselves need AUTHREAD/AUTHWRITE for password/HMAC and POLICYREAD/POLICYWRITE for policy sessions
///
/// NV Indices authorizing themselves: password/HMAC sessions need `TPMA_NV_AUTHREAD` (read
/// operations such as `TPM2_PolicySecret`) or `TPMA_NV_AUTHWRITE`, policy sessions need
/// `TPMA_NV_POLICYREAD` / `TPMA_NV_POLICYWRITE` (C `IsAuthValueAvailable()` /
/// `IsAuthPolicyAvailable()`).
#[test]
fn nv_index_self_auth_requires_matching_attributes() {
    let mut sim = create_simulator!();
    let index = 0x0150_0030;
    // Write-only by authValue; authPolicy set but no POLICYREAD/POLICYWRITE.
    define_nv(
        &mut sim,
        index,
        NV_AUTHWRITE | NV_OWNERREAD | NV_NO_DA,
        b"nv",
        &EMPTY_POLICY,
        8,
    );
    let secret_params = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // Password session on TPM2_PolicySecret (a read operation): AUTHREAD is clear.
    let target = start(&mut sim, TpmSe::Policy);
    let code = rc(
        &mut sim,
        TpmCc::PolicySecret,
        &[index, target.session_handle.0],
        &[AuthEntry::pw(b"nv")],
        &secret_params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);

    // Policy session on TPM2_PolicySecret: POLICYREAD is clear.
    let policy = start(&mut sim, TpmSe::Policy);
    let code = rc(
        &mut sim,
        TpmCc::PolicySecret,
        &[index, target.session_handle.0],
        &[raw_entry(&policy, ATTR_CONTINUE, &[])],
        &secret_params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);

    // Writing with the authValue is allowed.
    let code = rc(
        &mut sim,
        TpmCc::NVWrite,
        &[index, index],
        &[AuthEntry::pw(b"nv")],
        &nv_write_params(&[1; 8], 0),
    );
    assert_eq!(code, RC_SUCCESS);
}

/// PIN Fail/PIN Pass NV indices: authValue availability before write and at pinLimit, and pinCount maintenance on every use
///
/// PIN Fail / PIN Pass indices: the authValue is only available once written and while
/// `pinCount < pinLimit`, and `pinCount` is maintained on every use (C `IsAuthValueAvailable()`
/// and the PIN processing in `CheckAuthSession()`).
#[test]
fn nv_pin_fail_and_pin_pass_auth_and_counters() {
    let mut sim = create_simulator!();

    // --- PIN Fail ---
    let pin_fail = 0x0150_0010;
    define_nv(
        &mut sim,
        pin_fail,
        NV_TYPE_PIN_FAIL | NV_AUTHREAD | NV_OWNERWRITE | NV_OWNERREAD | NV_NO_DA,
        b"pin",
        &[],
        8,
    );
    // Not written yet: authValue unavailable.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"pin"),
        RC_AUTH_UNAVAILABLE
    );

    write_pin(&mut sim, pin_fail, 0, 2);
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"pin"),
        RC_SUCCESS
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 0);

    // A failure increments pinCount (NO_DA, so TPM_RC_BAD_AUTH), a success clears it.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"bad"),
        RC_BAD_AUTH_S1
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 1);
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"pin"),
        RC_SUCCESS
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 0);

    // Reaching pinLimit makes the authValue unavailable, even with the right PIN.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"bad"),
        RC_BAD_AUTH_S1
    );
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"bad"),
        RC_BAD_AUTH_S1
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 2);
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"pin"),
        RC_AUTH_UNAVAILABLE
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 2);

    // --- PIN Pass ---
    let pin_pass = 0x0150_0011;
    define_nv(
        &mut sim,
        pin_pass,
        NV_TYPE_PIN_PASS | NV_AUTHREAD | NV_OWNERWRITE | NV_OWNERREAD | NV_NO_DA,
        b"pin",
        &[],
        8,
    );
    write_pin(&mut sim, pin_pass, 0, 1);
    // A failure does not change pinCount of a PIN Pass index.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_pass, b"bad"),
        RC_BAD_AUTH_S1
    );
    assert_eq!(read_pin_count(&mut sim, pin_pass), 0);
    // Each success consumes one use.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_pass, b"pin"),
        RC_SUCCESS
    );
    assert_eq!(read_pin_count(&mut sim, pin_pass), 1);
    assert_eq!(
        read_pin_with_password(&mut sim, pin_pass, b"pin"),
        RC_AUTH_UNAVAILABLE
    );
    assert_eq!(read_pin_count(&mut sim, pin_pass), 1);
}

/// NV_Extend/SetBits/WriteLock (POLICYWRITE) and ReadLock (POLICYREAD) accept a satisfied policy session
///
/// Extend, SetBits, WriteLock (POLICYWRITE) and ReadLock (POLICYREAD) accept a satisfied policy
/// session on an index without AUTHWRITE / AUTHREAD.
#[test]
fn policy_session_authorizes_extend_setbits_and_locks() {
    let mut sim = create_simulator!();
    let policy_rw = TpmaNv::POLICYWRITE | TpmaNv::POLICYREAD | TpmaNv::OWNERREAD;

    let ext = 0x0150_0400;
    define(
        &mut sim,
        ext,
        TpmaNv::from(TpmNt::Extend) | policy_rw,
        32,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, ext);
    let mut session = start_session(&mut sim, TpmSe::Policy);
    let cmd = NVExtend {
        auth_handle: Handle(ext),
        nv_index: Handle(ext),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xaa; 8]).unwrap(),
    };
    with_session(&mut sim, &cmd, &[&name, &name], &mut session)
        .expect("NV_Extend with a POLICYWRITE policy session failed");

    let bits = 0x0150_0401;
    define(
        &mut sim,
        bits,
        TpmaNv::from(TpmNt::Bits) | policy_rw,
        8,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, bits);
    with_session(
        &mut sim,
        &NVSetBits {
            auth_handle: Handle(bits),
            nv_index: Handle(bits),
            bits: 1,
        },
        &[&name, &name],
        &mut session,
    )
    .expect("NV_SetBits with a POLICYWRITE policy session failed");

    let locks = 0x0150_0402;
    define(
        &mut sim,
        locks,
        policy_rw | TpmaNv::WRITE_STCLEAR | TpmaNv::READ_STCLEAR,
        8,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, locks);
    with_session(
        &mut sim,
        &NVWriteLock {
            auth_handle: Handle(locks),
            nv_index: Handle(locks),
        },
        &[&name, &name],
        &mut session,
    )
    .expect("NV_WriteLock with a POLICYWRITE policy session failed");
    let name = nv_index_name(&mut sim, locks);
    with_session(
        &mut sim,
        &NVReadLock {
            auth_handle: Handle(locks),
            nv_index: Handle(locks),
        },
        &[&name, &name],
        &mut session,
    )
    .expect("NV_ReadLock with a POLICYREAD policy session failed");
}

/// NV_Write enforces AUTHWRITE/PPWRITE/OWNERWRITE attributes (NV_AUTHORIZATION / AUTH_UNAVAILABLE)
#[test]
fn write_role_attributes_enforced() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500031;

    // 1. Index defined with OWNERWRITE | OWNERREAD only (no AUTHWRITE, no PPWRITE)
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::from_bytes(b"nvpass").unwrap(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 10]).unwrap(),
        offset: 0,
    };

    // Try writing with AUTHWRITE (using nv_index_val auth handle) -> should fail with NvAuthorization (0x14B)
    let res_auth = execute_with_password_sessions(&mut sim, &write_cmd, 1, b"nvpass");
    match res_auth {
        // AUTHWRITE is clear: the authValue is unavailable (C IsAuthValueAvailable).
        Err(err) => assert_eq!(err, TpmRc::AUTH_UNAVAILABLE.get()),
        Ok(_) => panic!("Expected NvAuthorization error for AUTHWRITE, but write succeeded"),
    }

    // Try writing with PPWRITE (using RHPlatform auth handle) -> should fail with NvAuthorization (0x14B)
    let res_pp = execute_with_password_sessions(
        &mut sim,
        &NVWrite {
            auth_handle: Handle::RH_PLATFORM,
            ..write_cmd
        },
        1,
        &[],
    );
    match res_pp {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for PPWRITE, but write succeeded"),
    }

    // Try writing with OWNERWRITE (using RHOwner auth handle) -> success
    execute_with_password_sessions(
        &mut sim,
        &NVWrite {
            auth_handle: Handle::RH_OWNER,
            ..write_cmd
        },
        1,
        &[],
    )
    .unwrap();

    // 2. Define another index with AUTHWRITE | OWNERREAD only (no OWNERWRITE)
    let nv_index_val_2 = 0x01500032;
    let nv_public_struct_2 = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val_2),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info_2 = tpm2::Tpm2b(nv_public_struct_2);
    let cmd_2 = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::from_bytes(b"nvpass2").unwrap(),
        public_info: public_info_2,
    };
    execute_with_password_sessions(&mut sim, &cmd_2, 1, &[]).unwrap();

    let write_cmd_2 = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val_2),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xBB; 10]).unwrap(),
        offset: 0,
    };

    // Try writing with OWNERWRITE (using RHOwner auth handle) -> should fail with NvAuthorization (0x14B)
    let res_owner_2 = execute_with_password_sessions(&mut sim, &write_cmd_2, 1, &[]);
    match res_owner_2 {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for OWNERWRITE, but write succeeded"),
    }

    // Try writing with AUTHWRITE (using nv_index_val_2 auth handle) -> success
    execute_with_password_sessions(
        &mut sim,
        &NVWrite {
            auth_handle: Handle(nv_index_val_2),
            ..write_cmd_2
        },
        1,
        b"nvpass2",
    )
    .unwrap();
}
