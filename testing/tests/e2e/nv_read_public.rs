//! TPM2_NV_ReadPublic and NV index Names.

use crate::_common::*;
use tpm2::commands::{CreatePrimary, NVDefineSpace, NVReadPublic};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, TpmaNv, TpmaObject,
    TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmsEccParms, TpmsNvPublic, TpmtPublic,
    TpmtSymDefObject,
};
use tpm2_simulator::create_simulator;

/// An NV index near the top of the NV range is defined and read back.
#[test]
fn high_index_value_round_trips() {
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
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };

    execute_with_password_sessions(&mut sim, &cmd, 1, &[])
        .expect("Failed to define large NV space");

    // Read public area back
    let read_cmd = NVReadPublic {
        nv_index: Handle(nv_index_val),
    };

    let read_rsp = sim
        .execute(read_cmd)
        .expect("Failed to read large NV public area");

    assert_eq!(read_rsp.nv_public, public_info);
}

/// NV index Names for SHA-384/SHA-512/SHA-1 nameAlg match local computation; CreatePrimary with an unsupported nameAlg fails with TPM_RC_VALUE
#[test]
fn name_alg_nv_index_names_and_unsupported_primary() {
    let mut sim = create_simulator!();

    // 1. SHA384 NV Name calculation
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Ordinary);

        let public_info_struct = TpmsNvPublic {
            nv_index: Handle(0x01800010),
            name_alg: TpmiAlgHash::Sha384,
            attributes,
            auth_policy: Tpm2bDigest::default(),
            data_size: 4,
        };
        let public_info = tpm2::Tpm2b(public_info_struct);

        let define_space = tpm2::commands::NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: tpm2::Tpm2bAuth::default(),
            public_info,
        };

        execute_with_password_sessions(&mut sim, &define_space, 1, &[])
            .expect("could not call TPM2_DefineSpace with SHA384");

        let read_public = tpm2::commands::NVReadPublic {
            nv_index: Handle(0x01800010),
        };

        let rsp = execute_with_password_sessions(&mut sim, &read_public, 0, &[])
            .expect("could not call TPM2_ReadPublic");

        let mut pub_buf = [0u8; 1024];
        let pub_len = marshal_to_slice(&public_info_struct, &mut pub_buf);

        let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
        let digest = tpm2::crypto::hash(
            CLIENT_CRYPTO,
            TpmiAlgHash::Sha384,
            &pub_buf[..pub_len],
            &mut digest_buf,
        )
        .unwrap()
        .digest();
        let mut name_bytes = [0u8; 50];
        name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha384).id().to_be_bytes());
        name_bytes[2..50].copy_from_slice(digest);
        let expected_name =
            Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

        assert_eq!(rsp.nv_name.get_buffer(), expected_name.get_buffer());
    }

    // 2. SHA512 NV Name calculation
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Ordinary);

        let public_info_struct = TpmsNvPublic {
            nv_index: Handle(0x01800011),
            name_alg: TpmiAlgHash::Sha512,
            attributes,
            auth_policy: Tpm2bDigest::default(),
            data_size: 4,
        };
        let public_info = tpm2::Tpm2b(public_info_struct);

        let define_space = tpm2::commands::NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: tpm2::Tpm2bAuth::default(),
            public_info,
        };

        execute_with_password_sessions(&mut sim, &define_space, 1, &[])
            .expect("could not call TPM2_DefineSpace with SHA512");

        let read_public = tpm2::commands::NVReadPublic {
            nv_index: Handle(0x01800011),
        };

        let rsp = execute_with_password_sessions(&mut sim, &read_public, 0, &[])
            .expect("could not call TPM2_ReadPublic");

        let mut pub_buf = [0u8; 1024];
        let pub_len = marshal_to_slice(&public_info_struct, &mut pub_buf);

        let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
        let digest = tpm2::crypto::hash(
            CLIENT_CRYPTO,
            TpmiAlgHash::Sha512,
            &pub_buf[..pub_len],
            &mut digest_buf,
        )
        .unwrap()
        .digest();
        let mut name_bytes = [0u8; 66];
        name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes());
        name_bytes[2..66].copy_from_slice(digest);
        let expected_name =
            Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

        assert_eq!(rsp.nv_name.get_buffer(), expected_name.get_buffer());
    }

    // 3. Supported SHA1 name_alg (define succeeds, read_public succeeds and returns valid SHA1 name)
    {
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Ordinary);

        let public_info_struct = TpmsNvPublic {
            nv_index: Handle(0x01800012),
            name_alg: TpmiAlgHash::Sha1,
            attributes,
            auth_policy: Tpm2bDigest::default(),
            data_size: 4,
        };
        let public_info = tpm2::Tpm2b(public_info_struct);

        let define_space = tpm2::commands::NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: tpm2::Tpm2bAuth::default(),
            public_info,
        };

        execute_with_password_sessions(&mut sim, &define_space, 1, &[])
            .expect("could not call TPM2_DefineSpace with SHA1");

        let read_public = tpm2::commands::NVReadPublic {
            nv_index: Handle(0x01800012),
        };

        let rsp = execute_with_password_sessions(&mut sim, &read_public, 0, &[])
            .expect("could not call TPM2_ReadPublic on SHA1 NV index");
        assert_eq!(
            &rsp.nv_name.get_buffer()[0..2],
            &Alg::from(TpmiAlgHash::Sha1).id().to_be_bytes()
        );
    }

    // 4. create_primary with name_alg = SHA512 must fail with Value error
    {
        let ecc_parms = TpmsEccParms {
            symmetric: Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
            }),
            scheme: None,
            curve_id: tpm2::TpmEccCurve::NistP256,
            kdf: None,
        };

        let public_area = TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sm3_256), // unsupported name_alg in create_primary
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::ADMIN_WITH_POLICY
                | TpmaObject::RESTRICTED
                | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                ecc_parms,
                tpm2::TpmsEccPoint {
                    x: tpm2::Tpm2bEccParameter::default(),
                    y: tpm2::Tpm2bEccParameter::default(),
                },
            ),
        };
        let in_public = tpm2::Tpm2b(public_area);

        let sensitive_create = tpm2::TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: tpm2::Tpm2bSensitiveData::default(),
        };
        let in_sensitive = tpm2::Tpm2b(sensitive_create);

        let create_primary = CreatePrimary {
            primary_handle: Handle::RH_ENDORSEMENT,
            in_sensitive,
            in_public,
            ..Default::default()
        };

        // One password session: with none, C returns AUTH_MISSING before the
        // template is checked (SessionProcess.c:1650).
        let err = match execute_with_password_sessions(&mut sim, &create_primary, 1, &[]) {
            Ok(_) => panic!("expected create_primary to fail"),
            Err(e) => e,
        };
        assert_eq!(err, TpmRc::HASH.with(Position::parameter(2)).get());
    }
}

/// NV_ReadPublic of an undefined index fails with TPM_RC_HANDLE + H1.
#[test]
fn undefined_index_returns_handle_h1() {
    let mut sim = create_simulator!();

    // Read public area of an undefined index should fail with Handle (0x08B or 0x10B depending on format)
    let read_cmd = NVReadPublic {
        nv_index: Handle(0x01500002),
    };

    let err = sim.execute(read_cmd).unwrap_err();
    // C `NvIndexIsAccessible` during handle unmarshaling: TPM_RC_HANDLE + RC_H1.
    assert_eq!(err.get(), TpmRc::HANDLE.with(Position::handle(1)).get());
}
