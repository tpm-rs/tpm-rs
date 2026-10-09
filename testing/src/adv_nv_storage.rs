#![forbid(unsafe_code)]
use tpm2::Alg;

use crate::test_utils::{execute_with_corrupted_bytes, execute_with_password_sessions};
use tpm2::Handle;
use tpm2::TpmiAlgHash;
use tpm2::commands::{NVDefineSpace, NVDefineSpaceHandles, NVReadPublic, NVReadPublicHandles};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bAuth, TpmaNv, TpmsNvPublic};
use tpm2_platform_linux::PlatformCryptoProvider;
use tpm2_simulator::create_simulator;

#[test]
fn test_nv_define_space_and_read_public() {
    let mut sim = create_simulator!();

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
        auth: Tpm2bAuth::default(),
        public_info,
    };

    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };

    // Execute NVDefineSpace with a password session
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[])
        .expect("Failed to define NV space");

    // Read public area back
    let read_cmd = NVReadPublic {};
    let read_handles = NVReadPublicHandles {
        nv_index: Handle(nv_index_val),
    };

    let (read_rsp, _) = sim
        .execute_with_handles(read_cmd, read_handles)
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
    let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
    assert_eq!(err, TpmRc::NV_DEFINED.get());
}

#[test]
fn test_nv_read_public_undefined() {
    let mut sim = create_simulator!();

    // Read public area of an undefined index should fail with Handle (0x08B or 0x10B depending on format)
    let read_cmd = NVReadPublic {};
    let read_handles = NVReadPublicHandles {
        nv_index: Handle(0x01500002),
    };

    let err = sim
        .execute_with_handles(read_cmd, read_handles)
        .unwrap_err();
    // C `NvIndexIsAccessible` during handle unmarshaling: TPM_RC_HANDLE + RC_H1.
    assert_eq!(err.get(), TpmRc::HANDLE.with(Position::handle(1)).get());
}

#[test]
fn test_nv_define_space_overflow() {
    let mut sim = create_simulator!();

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
        auth: Tpm2bAuth::default(),
        public_info,
    };

    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
    assert_eq!(err, TpmRc::SIZE.with(Position::parameter(2)).get());
}

#[test]
fn test_nv_read_public_large_index() {
    let mut sim = create_simulator!();

    let nv_index_val = 0x01500004;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 2000, // Large index size
    };

    let public_info = tpm2::Tpm2b(nv_public_struct);

    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };

    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };

    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[])
        .expect("Failed to define large NV space");

    // Read public area back
    let read_cmd = NVReadPublic {};
    let read_handles = NVReadPublicHandles {
        nv_index: Handle(nv_index_val),
    };

    let (read_rsp, _) = sim
        .execute_with_handles(read_cmd, read_handles)
        .expect("Failed to read large NV public area");

    assert_eq!(read_rsp.nv_public, public_info);
}

#[test]
fn test_nv_define_space_adversarial() {
    let mut sim = create_simulator!();

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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle(0x80000000), // transient handle instead of owner/platform
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_PLATFORM,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            // 33 significant bytes > 32 (trailing zeros would be removed before the check).
            auth: Tpm2bAuth::from_bytes(&[0x5au8; 33]).unwrap(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::SIZE.with(Position::parameter(2)).get());
    }
}

#[test]
fn test_nv_define_space_invalid_attribute_combos() {
    let mut sim = create_simulator!();

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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap_err();
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
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let res = execute_with_corrupted_bytes(&mut sim, &cmd, handles, 1, &[], |buf| {
            buf[8..10].copy_from_slice(&0x1234u16.to_be_bytes());
        });
        assert!(
            res.is_err(),
            "Expected failure now because name_alg unmarshalling validates the enum value"
        );
    }
}

#[test]
fn test_nv_define_space_hierarchy_auth() {
    let mut sim = create_simulator!();

    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(0x01500024),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: tpm2::Tpm2b(nv_public_struct),
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };

    // 1. Change Owner Auth to "ownerpass"
    let hca_cmd = tpm2::commands::HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"ownerpass").unwrap(),
    };
    let hca_handles = tpm2::commands::HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &hca_cmd, hca_handles, 1, &[])
        .expect("Failed to change hierarchy auth");

    // 2. Try DefineSpace with empty auth
    let err_no_auth = match execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]) {
        Ok(_) => panic!("Expected auth failure with empty password, but it succeeded!"),
        Err(e) => e,
    };
    // Expected: 0x9A2 (BadAuth for session 1)
    assert_eq!(
        err_no_auth, 0x9A2,
        "Expected auth failure with empty password"
    );

    // 3. Try DefineSpace with wrong auth
    let err_wrong_auth =
        match execute_with_password_sessions(&mut sim, &cmd, handles, 1, b"wrongpass") {
            Ok(_) => panic!("Expected auth failure with wrong password, but it succeeded!"),
            Err(e) => e,
        };
    // Expected: 0x9A2 (BadAuth for session 1)
    assert_eq!(
        err_wrong_auth, 0x9A2,
        "Expected auth failure with wrong password"
    );

    // 4. Try DefineSpace with correct auth
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, b"ownerpass");
    assert!(
        res.is_ok(),
        "Expected success with correct password, got: {:?}",
        res.err()
    );
}
