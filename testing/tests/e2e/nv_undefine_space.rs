//! TPM2_NV_UndefineSpace and TPM2_NV_UndefineSpaceSpecial: authorization and handle checks.

use crate::_common::{define_nv_space as define, exec_with_empty_passwords as pw, *};
use testing::tpm::Tpm;
use tpm2::commands::{
    NVDefineSpace, NVRead, NVUndefineSpace, NVUndefineSpaceSpecial, PolicyCommandCode,
    PolicyGetDigest,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

/// NV_UndefineSpace(Special) without sessions is TPM_RC_AUTH_MISSING before index attributes are inspected
///
/// Without sessions, NV_UndefineSpace(Special) report `TPM_RC_AUTH_MISSING` before the
/// command action inspects the index attributes.
#[test]
fn auth_missing_before_attribute_checks() {
    let mut sim = Tpm::new();
    let index = 0x0150_0900;
    define_platform(
        &mut sim,
        index,
        TpmaNv::PPREAD | TpmaNv::PPWRITE | TpmaNv::POLICY_DELETE,
        8,
        &command_code_policy(TpmCc::NVUndefineSpaceSpecial),
    );
    assert_eq!(
        pw(
            &mut sim,
            &NVUndefineSpace {
                auth_handle: Handle::RH_PLATFORM,
                nv_index: Handle(index)
            },
            0
        )
        .unwrap_err(),
        TpmRc::AUTH_MISSING.get()
    );

    let owner_index = 0x0150_0901;
    define_nv_with_policy_unwrap(&mut sim, owner_index, OWNER_RW, 8, &[]);
    assert_eq!(
        pw(
            &mut sim,
            &NVUndefineSpaceSpecial {
                nv_index: Handle(owner_index),
                platform: Handle::RH_PLATFORM
            },
            0
        )
        .unwrap_err(),
        TpmRc::AUTH_MISSING.get()
    );
}

/// NV_UndefineSpace: undefined index -> HANDLE, owner cannot delete platform index, POLICY_DELETE / hierarchy rules.
#[test]
fn authorization_and_policy_delete() {
    let mut sim = Tpm::new();

    let undefine = |sim: &mut Tpm, auth_handle: Handle, nv_index: Handle| {
        execute_with_password_sessions(
            sim,
            &NVUndefineSpace {
                auth_handle,
                nv_index,
            },
            1,
            &[],
        )
        .map(|_| ())
    };

    // 1. Try to undefine a non-existent index (should fail with Handle)
    assert_eq!(
        undefine(&mut sim, Handle::RH_OWNER, Handle(0x01000007)).err(),
        Some(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // 2. Define an Owner-created index
    let owner_index = Handle(0x01000008);
    let mut owner_attrs = TpmaNv::from(TpmNt::Ordinary);
    owner_attrs.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE); // No PLATFORMCREATE
    define(&mut sim, Handle::RH_OWNER, owner_index, owner_attrs, 16)
        .expect("Failed to define Owner-created space");

    // 3. Define a Platform-created index
    let platform_index = Handle(0x01000009);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        platform_index,
        platform_attrs(TpmNt::Ordinary, TpmaNv::empty()),
        16,
    )
    .expect("Failed to define Platform-created space");

    // 4. Define an index with POLICY_DELETE set
    let policy_del_index = Handle(0x0100000a);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        policy_del_index,
        platform_attrs(TpmNt::Ordinary, TpmaNv::POLICY_DELETE),
        16,
    )
    .expect("Failed to define POLICY_DELETE space");

    // 5. Undefine Platform-created index under Owner Auth (should fail with NvAuthorization)
    assert_eq!(
        undefine(&mut sim, Handle::RH_OWNER, platform_index).err(),
        Some(TpmRc::NV_AUTHORIZATION.get())
    );

    // 6. Undefine Owner-created index under Owner Auth -> Success
    undefine(&mut sim, Handle::RH_OWNER, owner_index)
        .expect("Failed to undefine Owner-created index under Owner Auth");

    // Re-define Owner-created index for further testing
    define(&mut sim, Handle::RH_OWNER, owner_index, owner_attrs, 16)
        .expect("Failed to re-define Owner-created space");

    // 7. Undefine Owner-created index under Platform Auth when shEnable is SET -> Success
    undefine(&mut sim, Handle::RH_PLATFORM, owner_index).expect(
        "Failed to undefine Owner-created index under Platform Auth when sh_enable is true",
    );

    // Re-define Owner-created index for further testing
    define(&mut sim, Handle::RH_OWNER, owner_index, owner_attrs, 16)
        .expect("Failed to re-define Owner-created space");

    // Disable storage hierarchy (shEnable = CLEAR) with TPM2_HierarchyControl.
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);

    // 8. Undefine Owner-created index under Platform Auth when shEnable is CLEAR -> should fail
    // with Handle (visibility check fails). C `NvIndexIsAccessible`: TPM_RC_HANDLE + RC_H2.
    assert_eq!(
        undefine(&mut sim, Handle::RH_PLATFORM, owner_index).err(),
        Some(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // Re-enable storage hierarchy
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, true);

    // 9. Undefine Platform-created index under Platform Auth -> Success
    undefine(&mut sim, Handle::RH_PLATFORM, platform_index)
        .expect("Failed to undefine Platform-created index under Platform Auth");

    // 10. Undefine index with POLICY_DELETE set under Platform Auth -> should fail with Attributes
    assert_eq!(
        undefine(&mut sim, Handle::RH_PLATFORM, policy_del_index).err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(2)).get())
    );
}

/// With phEnableNV clear, NV_UndefineSpace of a platform index is TPM_RC_HANDLE + RC_H2 before the POLICY_DELETE check
///
/// With `phEnableNV` clear, a platform index is reported as `TPM_RC_HANDLE + RC_H2` before the
/// `TPMA_NV_POLICY_DELETE` attribute check.
#[test]
fn disabled_platform_nv_reported_before_policy_delete() {
    let mut sim = Tpm::new();
    let index = 0x0150_0602;
    define_platform(
        &mut sim,
        index,
        TpmaNv::PPREAD | TpmaNv::PPWRITE | TpmaNv::POLICY_DELETE,
        8,
        &EMPTY_POLICY,
    );
    set_hierarchy_enabled(&mut sim, Handle::RH_PLATFORM_NV, false);
    assert_eq!(
        pw(
            &mut sim,
            &NVUndefineSpace {
                auth_handle: Handle::RH_PLATFORM,
                nv_index: Handle(index)
            },
            1
        )
        .unwrap_err(),
        TpmRc::HANDLE.with(Position::handle(2)).get()
    );
}

/// Raw NV_UndefineSpace(Special) with invalid NV index handles return TPM_RC_VALUE at the right handle position
#[test]
fn invalid_index_handle_return_codes() {
    let mut sim = Tpm::new();

    // Helper to construct a raw wire buffer with session (tag 0x8002, empty password session)
    let make_request = |cc: u32, h0: u32, h1: u32| -> [u8; 31] {
        let mut buf = [0u8; 31];
        buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes()); // tag
        buf[2..6].copy_from_slice(&31u32.to_be_bytes()); // size
        buf[6..10].copy_from_slice(&cc.to_be_bytes()); // cc
        buf[10..14].copy_from_slice(&h0.to_be_bytes()); // handle 0
        buf[14..18].copy_from_slice(&h1.to_be_bytes()); // handle 1
        buf[18..22].copy_from_slice(&9u32.to_be_bytes()); // authSize
        buf[22..26].copy_from_slice(&Handle::RS_PW.0.to_be_bytes()); // session handle
        buf[26..28].copy_from_slice(&0u16.to_be_bytes()); // nonce
        buf[28] = 0; // session attributes
        buf[29..31].copy_from_slice(&0u16.to_be_bytes()); // hmac
        buf
    };
    let mut rc_of = |req: &[u8]| -> u32 {
        let mut resp = [0u8; 256];
        let resp = sim.transact(req, &mut resp).expect("transact");
        u32::from_be_bytes(resp[6..10].try_into().unwrap())
    };

    // 1. CPCTPM_TC2_3_33_04_05 Step 1: NV_UndefineSpace(TPM_RH_OWNER, 0x02400000)
    assert_eq!(
        rc_of(&make_request(0x0122, Handle::RH_OWNER.0, 0x02400000)),
        TpmRc::VALUE.with(Position::handle(2)).get(),
        "NV_UndefineSpace with 0x02400000 should return TPM_RC_VALUE at Pos2"
    );

    // 2. CPCTPM_TC2_3_33_04_05 Step 2: NV_UndefineSpace(TPM_RH_PLATFORM, 0x00400000)
    assert_eq!(
        rc_of(&make_request(0x0122, Handle::RH_PLATFORM.0, 0x00400000)),
        TpmRc::VALUE.with(Position::handle(2)).get(),
        "NV_UndefineSpace with 0x00400000 should return TPM_RC_VALUE at Pos2"
    );

    // 3. CPCTPM_TC2_4_33_05_03 Step 1: NV_UndefineSpaceSpecial(0x02400000, TPM_RH_PLATFORM)
    assert_eq!(
        rc_of(&make_request(0x011F, 0x02400000, Handle::RH_PLATFORM.0)),
        TpmRc::VALUE.with(Position::handle(1)).get(),
        "NV_UndefineSpaceSpecial with 0x02400000 should return TPM_RC_VALUE at Pos1"
    );

    // 4. CPCTPM_TC2_4_33_05_03 Step 2: NV_UndefineSpaceSpecial(0x00400000, TPM_RH_PLATFORM)
    assert_eq!(
        rc_of(&make_request(0x011F, 0x00400000, Handle::RH_PLATFORM.0)),
        TpmRc::VALUE.with(Position::handle(1)).get(),
        "NV_UndefineSpaceSpecial with 0x00400000 should return TPM_RC_VALUE at Pos1"
    );
}

/// NV_UndefineSpaceSpecial with RH_OWNER as platform handle is TPM_RC_VALUE + RC_H2
#[test]
fn special_requires_platform_handle() {
    let mut sim = Tpm::new();
    let index = 0x0150_020a;
    define_platform(
        &mut sim,
        index,
        TpmaNv::PPREAD | TpmaNv::PPWRITE | TpmaNv::POLICY_DELETE,
        8,
        &command_code_policy(TpmCc::NVUndefineSpaceSpecial),
    );
    let rc = pw(
        &mut sim,
        &NVUndefineSpaceSpecial {
            nv_index: Handle(index),
            platform: Handle::RH_OWNER,
        },
        2,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::VALUE.with(Position::handle(2)).get());
}

/// NV_UndefineSpaceSpecial deletes a POLICY_DELETE index under platform auth with a PolicyCommandCode policy session
#[test]
fn special_with_policy_delete_session() {
    let mut sim = Tpm::new();

    // 1. Run a Trial session with PolicyCommandCode(NVUndefineSpaceSpecial) to compute required policy digest
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap()
    .session_handle;

    let policy_cc_cmd = PolicyCommandCode {
        policy_session: trial_session,
        code: TpmCc::NVUndefineSpaceSpecial,
    };
    execute_tpm_command_full(&mut sim, &policy_cc_cmd, &[]).unwrap();

    let digest_resp = execute_tpm_command_full(
        &mut sim,
        &PolicyGetDigest {
            policy_session: trial_session,
        },
        &[],
    )
    .unwrap();
    let policy_digest = digest_resp.policy_digest;

    // 2. Define an NV index with POLICY_DELETE bound to policy_digest
    let nv_idx = Handle(0x01000022);
    let define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::from_bytes(b"idx_pass").unwrap(),
        public_info: Tpm2b(TpmsNvPublic {
            nv_index: nv_idx,
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::POLICY_DELETE
                | TpmaNv::PLATFORMCREATE
                | TpmaNv::AUTHWRITE
                | TpmaNv::AUTHREAD,
            auth_policy: policy_digest,
            data_size: 32,
        }),
    };
    let platform_auth_session = make_auth_session(b"");
    execute_tpm_command_with_auths(
        &mut sim,
        &define_cmd,
        core::slice::from_ref(&platform_auth_session),
    )
    .expect("Failed to define NV index with POLICY_DELETE");

    // 3. Start a real Policy session and execute PolicyCommandCode(NVUndefineSpaceSpecial)
    let real_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    execute_tpm_command_full(
        &mut sim,
        &PolicyCommandCode {
            policy_session: real_session.session_handle,
            ..policy_cc_cmd
        },
        &[],
    )
    .unwrap();

    // 4. Call NV_UndefineSpaceSpecial under Platform auth and satisfied policy session
    let undefine_cmd = NVUndefineSpaceSpecial {
        nv_index: nv_idx,
        platform: Handle::RH_PLATFORM,
    };

    // Compute command HMAC for policy session (HMAC with session_key = &[])
    let nv_name = nv_name(&define_cmd.public_info.0);

    let mut cp_data = Vec::new();
    cp_data.extend_from_slice(&TpmCc::NVUndefineSpaceSpecial.code().to_be_bytes());
    cp_data.extend_from_slice(nv_name.get_buffer());
    cp_data.extend_from_slice(&Handle::RH_PLATFORM.0.to_be_bytes());
    let cp_hash = sha256_bytes(&cp_data);

    let mut hmac_state =
        tpm2::crypto::HmacStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256, &[]).unwrap();
    let caller_nonce = [5u8; 32];
    hmac_state.update(&cp_hash).unwrap();
    hmac_state.update(&caller_nonce).unwrap();
    hmac_state
        .update(real_session.nonce_tpm.get_buffer())
        .unwrap();
    hmac_state.update(&[1u8]).unwrap();
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let policy_hmac = hmac_state.finalize(&mut hmac_buf).unwrap();

    let policy_auth_command = TpmsAuthCommand {
        session_handle: real_session.session_handle,
        nonce: Tpm2bNonce::from_bytes(&caller_nonce).unwrap(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(policy_hmac.digest()).unwrap(),
    };
    let auths = [policy_auth_command, platform_auth_session];
    execute_tpm_command_with_auths(&mut sim, &undefine_cmd, &auths)
        .expect("Failed to undefine NV index with NV_UndefineSpaceSpecial");

    // 5. Verify index is undefined (read fails)
    let read_cmd = NVRead {
        auth_handle: nv_idx,
        nv_index: nv_idx,
        size: 32,
        offset: 0,
    };
    let read_res = execute_tpm_command_with_auths(
        &mut sim,
        &read_cmd,
        core::slice::from_ref(&platform_auth_session),
    );
    assert!(read_res.is_err());
}
