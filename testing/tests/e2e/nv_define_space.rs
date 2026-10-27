//! TPM2_NV_DefineSpace: attribute, size, authPolicy and authValue validation.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{NVDefineSpace, NVReadPublic};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_platform_linux::PlatformCryptoProvider;

/// NV_DefineSpace attribute/size errors (WRITTEN, oversize, PLATFORMCREATE by owner, WRITEALL > 1024, CLEAR_STCLEAR+WRITEDEFINE) carry correct positions
#[test]
fn attribute_and_size_error_positions() {
    let mut sim = Tpm::new();
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0205, OWNER_RW | TpmaNv::WRITTEN, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());

    // One octet more than `MAX_NV_INDEX_SIZE` (2048 by default): `dataSize` is the last field of
    // `publicInfo` (after an empty `auth`).
    let max = tpm2::TPM2_MAX_NV_INDEX_SIZE;
    let cmd = tpm2::commands::NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: tpm2::Tpm2bAuth::default(),
        public_info: tpm2::Tpm2b(nv_public(0x0150_0206, OWNER_RW, max, &[])),
    };
    let rc = crate::_common::execute_with_corrupted_bytes_status(&mut sim, &cmd, 1, &[], |p| {
        let last = p.len() - 2;
        crate::_common::put_u16(p, last, max + 1);
    })
    .unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(2)).get());

    // An owner-defined index can't be platform-created (blames authHandle).
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0207, OWNER_RW | TpmaNv::PLATFORMCREATE, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::handle(1)).get());

    // WRITEALL is limited by MAX_NV_BUFFER_SIZE (1024), not MAX_NV_INDEX_SIZE.
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0208, OWNER_RW | TpmaNv::WRITEALL, 1025, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(2)).get());

    // CLEAR_STCLEAR and WRITEDEFINE are mutually exclusive.
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(
            0x0150_0209,
            OWNER_RW | TpmaNv::CLEAR_STCLEAR | TpmaNv::WRITEDEFINE,
            8,
            &[],
        ),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
}

/// NV_DefineSpace with authPolicy size not matching nameAlg is TPM_RC_SIZE + RC_P2
#[test]
fn auth_policy_size_mismatch_rejected() {
    let mut sim = Tpm::new();
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0200, OWNER_RW, 8, &[0xAA; 20]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(2)).get());
}

/// NV_DefineSpace authValue size limit ignores trailing zeros; 33 significant bytes are TPM_RC_SIZE + RC_P1
#[test]
fn auth_value_trailing_zeros_ignored_for_size() {
    let mut sim = Tpm::new();
    // 32 significant bytes followed by zeros: fits a SHA-256 nameAlg once zeros are removed.
    let mut auth = vec![0x42u8; 32];
    auth.extend_from_slice(&[0, 0, 0]);
    try_define(
        &mut sim,
        Handle::RH_OWNER,
        &auth,
        nv_public(0x0150_0201, OWNER_RW, 8, &[]),
    )
    .expect("auth with trailing zeros must be accepted");
    // 33 significant bytes are too many.
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[0x42u8; 33],
        nv_public(0x0150_0202, OWNER_RW, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(1)).get());
}

/// CLEAR_STCLEAR+WRITEDEFINE and PIN_PASS+GLOBALLOCK/WRITEDEFINE fail with ATTRIBUTES + P2.
#[test]
fn conflicting_attributes_rejected() {
    let mut sim = Tpm::new();

    // 1. CLEAR_STCLEAR and WRITEDEFINE set on the same NV index must fail (according to spec / C implementation).
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500020),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE
                | TpmaNv::OWNERREAD
                | TpmaNv::CLEAR_STCLEAR
                | TpmaNv::WRITEDEFINE,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        // C `NvDefineSpace` rejects this combination with TPM_RC_ATTRIBUTES + RC_P2.
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 2. PinPass with GLOBALLOCK set must fail.
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::GLOBALLOCK;
        attributes.set_type(tpm2::TpmNt::PinPass);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500021),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        // C `NvDefineSpace` rejects this combination with TPM_RC_ATTRIBUTES + RC_P2.
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 3. PinPass with WRITEDEFINE set must fail.
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::WRITEDEFINE;
        attributes.set_type(tpm2::TpmNt::PinPass);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500022),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        // C `NvDefineSpace` rejects this combination with TPM_RC_ATTRIBUTES + RC_P2.
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 4. Totally unrecognized name_alg (like TpmiAlgHash::try_from(0x1234).unwrap()).
    // Gaps identified: implementation does NOT validate that name_alg is a supported hash algorithm at creation.
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500023),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let res = execute_with_corrupted_bytes(&mut sim, &cmd, 1, &[], |buf| {
            buf[8..10].copy_from_slice(&0x1234u16.to_be_bytes());
        });
        assert!(
            res.is_err(),
            "Expected failure now because name_alg unmarshalling validates the enum value"
        );
    }
}

/// NV_DefineSpace then NV_ReadPublic returns the public area and correct Name; redefining fails with NV_DEFINED.
#[test]
fn define_then_read_public_and_name() {
    let mut sim = Tpm::new();

    // Construct TpmsNvPublic structure
    let nv_index_val = 0x01500001;
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
        auth: Tpm2bAuth::default(),
        public_info,
    };

    // Execute NVDefineSpace with a password session
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).expect("Failed to define NV space");

    // Read public area back
    let read_cmd = NVReadPublic {
        nv_index: Handle(nv_index_val),
    };

    let read_rsp = sim
        .execute(read_cmd)
        .expect("Failed to read NV public area");

    assert_eq!(read_rsp.nv_public, public_info);

    // Verify calculated name (SHA256 of the nv public structure)
    let provider = PlatformCryptoProvider;
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(
        &provider,
        TpmiAlgHash::Sha256,
        &crate::test_utils::marshal_to_vec(&public_info.0),
        &mut out,
    )
    .unwrap()
    .digest();

    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(digest);
    let expected_name =
        tpm2::Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(read_rsp.nv_name, expected_name);

    // Edge case 1: Redefining an already defined NV space should fail with NvDefined (0x14C)
    let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
    assert_eq!(err, TpmRc::NV_DEFINED.get());
}

/// NV_DefineSpace rejects bad auth handles, malformed indices and invalid attribute/size combinations.
#[test]
fn handle_index_and_attribute_validation() {
    let mut sim = Tpm::new();

    // 1. Invalid auth handles (e.g. transient handle, must fail with Value)
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x0150000a),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle(0x80000000), // transient handle instead of owner/platform,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        // Returns TpmRc::VALUE.with(Position::handle(1)) -> which is 0x1C5 (Value + Pos1)
        assert_eq!(err, TpmRc::VALUE.with(Position::handle(1)).get());
    }

    // 2. Invalid NV Index format (must start with 0x01 in high byte)
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x0250000b), // high byte 0x02 instead of 0x01
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        // Returns value_for(Position::handle(2)) -> which is 0x2C5
        assert_eq!(err, TpmRc::VALUE.with(Position::parameter(2)).get());
    }

    // 3. Set written/readlocked/writelocked at creation time (must fail with Attributes)
    for bad_attr in [TpmaNv::WRITTEN, TpmaNv::READLOCKED, TpmaNv::WRITELOCKED] {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x0150000c),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | bad_attr,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 4. Size check for counter, bits, pin_fail, pin_pass (must be 8)
    for nt_type in [
        tpm2::TpmNt::Counter,
        tpm2::TpmNt::Bits,
        tpm2::TpmNt::PinFail,
        tpm2::TpmNt::PinPass,
    ] {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        if matches!(nt_type, tpm2::TpmNt::PinFail) {
            attributes |= TpmaNv::NO_DA;
        }
        attributes.set_type(nt_type);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x0150000d),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 7, // invalid size (not 8)
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::SIZE.with(Position::parameter(2)).get());
    }

    // 5. Size check for extend (must be digest size of name_alg)
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Extend);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x0150000e),
            name_alg: TpmiAlgHash::Sha256, // SHA256 digest size is 32
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 31, // invalid size
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::SIZE.with(Position::parameter(2)).get());
    }

    // 6. Read/write attribute consistency check
    // No read attributes (only OWNERWRITE)
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x0150000f),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE, // no read attributes
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }
    // No write attributes (only OWNERREAD)
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500010),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERREAD, // no write attributes
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 7. CLEAR_STCLEAR & Counter attribute check
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::CLEAR_STCLEAR;
        attributes.set_type(tpm2::TpmNt::Counter);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500011),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 8. PLATFORMCREATE consistency check
    // auth_handle is RHPlatform but PLATFORMCREATE is not set
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500012),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::PPWRITE | TpmaNv::PPREAD, // no PLATFORMCREATE
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_PLATFORM,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::handle(1)).get());
    }
    // auth_handle is RHOwner but PLATFORMCREATE is set
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500013),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::PLATFORMCREATE,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::handle(1)).get());
    }

    // 9. POLICY_DELETE consistency check: POLICY_DELETE is set but auth_handle is RHOwner (not RHPlatform)
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500014),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::POLICY_DELETE,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 10. PinFail NO_DA check: PinFail index type without NO_DA attribute
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::PinFail); // no NO_DA
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500015),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 11. PinFail/PinPass write attributes checks
    // Must intersect PPWRITE | OWNERWRITE | POLICYWRITE, and MUST NOT contain AUTHWRITE
    // Case A: no write attributes
    {
        let mut attributes = TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::PinPass);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500016),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }
    // Case B: contains AUTHWRITE
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::AUTHWRITE;
        attributes.set_type(tpm2::TpmNt::PinPass);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500017),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
    }

    // 12. Auth value size check (cmd.auth.get_size() > name_alg digest size)
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500018),
            name_alg: TpmiAlgHash::Sha256, // SHA256 digest size is 32
            attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 64,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            // 33 significant bytes > 32 (trailing zeros would be removed before the check).
            auth: Tpm2bAuth::from_bytes(&[0x5au8; 33]).unwrap(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::SIZE.with(Position::parameter(1)).get());
    }

    // 13. MAX_NV_BUFFER_SIZE check (data_size > 2048 and WRITEALL is set)
    {
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(0x01500019),
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::WRITEALL,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 2049, // data_size > 2048
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::SIZE.with(Position::parameter(2)).get());
    }
}

/// NV_DefineSpace with external/permanent/non-NV handles in nvIndex fails unmarshalling with TPM_RC_VALUE + RC_P2
#[test]
fn non_nv_index_handle_rejected() {
    let mut sim = Tpm::new();
    // `TPMS_NV_PUBLIC.nvIndex` is a `TPMI_RH_NV_LEGACY_INDEX` in the C reference
    // (`TPMS_NV_PUBLIC_Unmarshal`), so external/permanent NV handles fail unmarshaling with
    // `TPM_RC_VALUE` just like any other non-NV handle (the finding's `TPM_RC_HANDLE` claim does
    // not hold).
    for (index, expected) in [
        (0x1150_0000, TpmRc::VALUE.with(Position::parameter(2))),
        (0x1250_0000, TpmRc::VALUE.with(Position::parameter(2))),
        (0x0250_0000, TpmRc::VALUE.with(Position::parameter(2))),
    ] {
        let rc = try_define(
            &mut sim,
            Handle::RH_OWNER,
            &[],
            nv_public(index, OWNER_RW, 8, &[]),
        )
        .unwrap_err();
        assert_eq!(rc, expected.get(), "nvIndex {index:#x}");
    }
}

/// NV_DefineSpace with dataSize 65535 fails with TPM_RC_SIZE.
#[test]
fn oversized_data_size_rejected() {
    let mut sim = Tpm::new();

    let nv_index_val = 0x01500003;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 65535, // Large data size to cause u16 overflow
    };

    let public_info = tpm2::Tpm2b(nv_public_struct);

    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };

    let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
    assert_eq!(err, TpmRc::SIZE.with(Position::parameter(2)).get());
}

/// With an owner password set, NV_DefineSpace fails with empty or wrong auth (BAD_AUTH + S1) and succeeds with the right one.
#[test]
fn owner_auth_required() {
    let mut sim = Tpm::new();

    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(0x01500024),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info: tpm2::Tpm2b(nv_public_struct),
    };

    // 1. Change Owner Auth to "ownerpass"
    let hca_cmd = tpm2::commands::HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"ownerpass").unwrap(),
    };
    execute_with_password_sessions(&mut sim, &hca_cmd, 1, &[])
        .expect("Failed to change hierarchy auth");

    // 2. Try DefineSpace with empty auth
    let err_no_auth = match execute_with_password_sessions(&mut sim, &cmd, 1, &[]) {
        Ok(_) => panic!("Expected auth failure with empty password, but it succeeded!"),
        Err(e) => e,
    };
    // Expected: 0x9A2 (BadAuth for session 1)
    assert_eq!(
        err_no_auth, 0x9A2,
        "Expected auth failure with empty password"
    );

    // 3. Try DefineSpace with wrong auth
    let err_wrong_auth = match execute_with_password_sessions(&mut sim, &cmd, 1, b"wrongpass") {
        Ok(_) => panic!("Expected auth failure with wrong password, but it succeeded!"),
        Err(e) => e,
    };
    // Expected: 0x9A2 (BadAuth for session 1)
    assert_eq!(
        err_wrong_auth, 0x9A2,
        "Expected auth failure with wrong password"
    );

    // 4. Try DefineSpace with correct auth
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, b"ownerpass");
    assert!(
        res.is_ok(),
        "Expected success with correct password, got: {:?}",
        res.err()
    );
}

/// PIN pass/fail indexes reject GLOBALLOCK/WRITEDEFINE with TPM_RC_ATTRIBUTES + RC_P2
#[test]
fn pin_index_lock_attributes_rejected() {
    let mut sim = Tpm::new();
    let pin_pass = TpmaNv::from(TpmNt::PinPass) | TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD;
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0203, pin_pass | TpmaNv::GLOBALLOCK, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());

    let pin_fail =
        TpmaNv::from(TpmNt::PinFail) | TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA;
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0204, pin_fail | TpmaNv::WRITEDEFINE, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
}

/// NV_DefineSpace with a reserved TPM_NT in attributes fails with TPM_RC_ATTRIBUTES (TC2_3_33_03_06).
///
/// Regression test for CPCTPM_TC2_3_33_03_06:
/// TPM2_NV_DefineSpace with invalid TPM_NT in attributes (e.g. 0x05 or 0x06)
/// must return TPM_RC_ATTRIBUTES (0x0082), not TPM_RC_VALUE.
#[test]
fn reserved_nv_type_rejected() {
    let mut sim = Tpm::new();

    // NV_DefineSpace with authHandle = RH_OWNER, attributes containing reserved NT = 0x05 (bits 4..7 = 0x50)
    // Attributes: OWNERWRITE (0x00020000) | OWNERREAD (0x00040000) | (0x05 << 4 = 0x50) -> 0x00060050
    let mut nv_def_req = Vec::new();
    nv_def_req.extend_from_slice(&0x8002u16.to_be_bytes()); // SESSIONS
    nv_def_req.extend_from_slice(&0u32.to_be_bytes()); // commandSize placeholder
    nv_def_req.extend_from_slice(&0x0000012au32.to_be_bytes()); // TPM_CC_NV_DefineSpace
    nv_def_req.extend_from_slice(&0x40000001u32.to_be_bytes()); // authHandle: RH_OWNER
    nv_def_req.extend_from_slice(&9u32.to_be_bytes()); // authSize: 9
    nv_def_req.extend_from_slice(&0x40000009u32.to_be_bytes()); // session: RS_PW
    nv_def_req.extend_from_slice(&0u16.to_be_bytes()); // nonce
    nv_def_req.push(0x01); // continueSession
    nv_def_req.extend_from_slice(&0u16.to_be_bytes()); // hmac
    nv_def_req.extend_from_slice(&0u16.to_be_bytes()); // auth size: 0
    // publicInfo (TPM2B_NV_PUBLIC)
    let mut pub_info = Vec::new();
    pub_info.extend_from_slice(&0x01000001u32.to_be_bytes()); // nvIndex: 0x01000001
    pub_info.extend_from_slice(&0x000bu16.to_be_bytes()); // nameAlg: SHA256 (0x000b)
    pub_info.extend_from_slice(&0x00060050u32.to_be_bytes()); // attributes: OWNERREAD | OWNERWRITE | NT=5 (invalid)
    pub_info.extend_from_slice(&0u16.to_be_bytes()); // authPolicy size: 0
    pub_info.extend_from_slice(&8u16.to_be_bytes()); // dataSize: 8

    let pub_info_len = pub_info.len() as u16;
    nv_def_req.extend_from_slice(&pub_info_len.to_be_bytes());
    nv_def_req.extend_from_slice(&pub_info);

    let rc = raw_rc(&mut sim, &finish(nv_def_req));
    assert_eq!(
        rc,
        TpmRc::ATTRIBUTES
            .with(tpm2::errors::Position::parameter(2))
            .get(),
        "Expected TPM_RC_ATTRIBUTES + RC_P2 (0x02C2, C NvDefineSpace blamePublic) for NV_DefineSpace with reserved TPM_NT in attributes"
    );
}
