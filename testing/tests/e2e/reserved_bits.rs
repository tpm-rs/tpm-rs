//! Reserved bits in TPMA_OBJECT, TPMA_NV and TPMA_SESSION are rejected.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{Create, CreatePrimary};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bData, Tpm2bDigest, TpmaObject, TpmiAlgHash, TpmlPcrSelection,
    TpmsAuthCommand,
};

/// Reserved bits in TPMA_OBJECT (CreatePrimary), TPMA_NV (NV_DefineSpace) and TPMA_SESSION fail with TPM_RC_RESERVED_BITS.
#[test]
fn object_nv_and_session_attributes() {
    let mut sim = Tpm::new();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    // 1. Test TpmaObject reserved bits in CreatePrimary (parameter 2)
    for reserved_bit in [1u32 << 0, 1u32 << 12, 1u32 << 20] {
        let mut pub_template = default_ecc_public();
        pub_template.object_attributes =
            TpmaObject(pub_template.object_attributes.0 | reserved_bit);
        let in_public = tpm2::Tpm2b(pub_template);
        let cmd = CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive,
            in_public,
            ..Default::default()
        };
        // One password session: with none, C returns AUTH_MISSING first.
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[])
            .expect_err("CreatePrimary with reserved TpmaObject bits must fail");
        assert_eq!(
            err,
            TpmRc::RESERVED_BITS.with(Position::parameter(2)).get(),
            "TpmaObject reserved bit {reserved_bit:#x} must return TPM_RC_RESERVED_BITS + P2"
        );
    }

    // 2. Test TpmaNv reserved bits in NV_DefineSpace (parameter 2)
    for reserved_bit in [1u32 << 8, 1u32 << 20] {
        let nv_public = tpm2::TpmsNvPublic {
            nv_index: Handle(0x01500001),
            name_alg: TpmiAlgHash::Sha256,
            attributes: tpm2::TpmaNv(
                (tpm2::TpmaNv::OWNERWRITE | tpm2::TpmaNv::OWNERREAD).0 | reserved_bit,
            ),
            auth_policy: Tpm2bDigest::default(),
            data_size: 32,
        };
        let cmd = tpm2::commands::NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[])
            .expect_err("NVDefineSpace with reserved TpmaNv bits must fail");
        assert_eq!(
            err,
            TpmRc::RESERVED_BITS.with(Position::parameter(2)).get(),
            "TpmaNv reserved bit {reserved_bit:#x} must return TPM_RC_RESERVED_BITS + P2"
        );
    }

    // 3. Test TpmaSession reserved bits in command auth session area (session 1)
    let in_public = tpm2::Tpm2b(default_ecc_public());
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let mut cmd_buf = [0u8; 2048];
    let mut cmd_header = CmdHeader {
        tag: tpm2::TpmiStCommandTag::Sessions,
        size: 0,
        code: tpm2::TpmCc::CreatePrimary,
    };
    let mut written = marshal_to_slice(&cmd_header, &mut cmd_buf);
    written += marshal_to_slice(&cmd.primary_handle, &mut cmd_buf[written..]);

    let auth_cmd = tpm2::TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(0x08), // reserved bit 3 set
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buf = [0u8; 256];
    let auth_len = marshal_to_slice(&auth_cmd, &mut auth_buf);
    written += marshal_to_slice(&(auth_len as u32), &mut cmd_buf[written..]);
    cmd_buf[written..written + auth_len].copy_from_slice(&auth_buf[..auth_len]);
    written += auth_len;
    written += marshal_to_slice(&cmd, &mut cmd_buf[written..]);

    cmd_header.size = written as u32;
    marshal_to_slice(&cmd_header, &mut cmd_buf);

    let mut resp_buf = [0u8; 1024];
    sim.transact(&cmd_buf[..written], &mut resp_buf).unwrap();
    let mut resp_slice = &resp_buf[..];
    let resp_hdr = <RespHeader as tpm2::Unmarshal>::unmarshal(&mut resp_slice).unwrap();
    assert_eq!(
        resp_hdr.rc,
        TpmRc::RESERVED_BITS.with(Position::session(1)).get()
    );
}

/// Reserved TPMA_OBJECT/TPMA_SESSION bits fail with RESERVED_BITS; FIRMWARE_LIMITED/SVN_LIMITED unmarshal but fail ATTRIBUTES + P2 under a normal parent.
#[test]
fn object_session_and_firmware_svn_limited() {
    let mut sim = Tpm::new();

    let parent_handle = create_parent(&mut sim);

    // 1. Test reserved bit in TPMA_OBJECT (bit 0 = 1) returns TPM_RC_RESERVED_BITS at parameter 2
    let mut template = rsa_parent_template();
    template.object_attributes = TpmaObject(template.object_attributes.0 | 0x00000001);
    let create_cmd_bad_obj_attr = Create {
        parent_handle,
        in_sensitive: empty_sensitive(),
        in_public: tpm2::Tpm2b(template),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let err =
        execute_tpm_command_offsets(&mut sim, &create_cmd_bad_obj_attr, &[empty_password_auth()])
            .unwrap_err();
    assert_eq!(err, TpmRc::RESERVED_BITS.with(Position::parameter(2)).get());

    // 2. Test reserved bit in TPMA_SESSION (bit 3 = 0x08) returns TPM_RC_RESERVED_BITS at session 1
    let create_cmd_good = Create {
        parent_handle,
        in_sensitive: empty_sensitive(),
        in_public: tpm2::Tpm2b(rsa_parent_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let bad_session_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(0x40000009),
        nonce: Tpm2bDigest::default(),
        session_attributes: tpm2::TpmaSession(0x08), // reserved bit 3
        hmac: Tpm2bAuth::default(),
    };
    let err_sess =
        execute_tpm_command_offsets(&mut sim, &create_cmd_good, &[bad_session_auth]).unwrap_err();
    assert_eq!(
        err_sess,
        TpmRc::RESERVED_BITS.with(Position::session(1)).get()
    );

    // 3. Test FIRMWARE_LIMITED and SVN_LIMITED unmarshal cleanly (not RESERVED_BITS)
    // but fail attribute validation with TPM_RC_ATTRIBUTES at parameter 2 when parent is not firmware/svn limited.
    for limited_flag in [TpmaObject::FIRMWARE_LIMITED, TpmaObject::SVN_LIMITED] {
        let mut lim_template = rsa_parent_template();
        lim_template.object_attributes |= limited_flag;
        let create_cmd_lim = Create {
            parent_handle,
            in_sensitive: empty_sensitive(),
            in_public: tpm2::Tpm2b(lim_template),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let err_lim =
            execute_tpm_command_offsets(&mut sim, &create_cmd_lim, &[empty_password_auth()])
                .unwrap_err();
        assert_eq!(
            err_lim,
            TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()
        );
    }
}
