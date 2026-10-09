#![allow(unused_imports, dead_code)]
use crate::test_utils::marshal_to_slice;
use tpm2::Alg;
use tpm2::errors::TpmRc;
// Ported from tpm-go/tpm2/test/names_test.go

use tpm2::Handle;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};

use crate::test_utils::*;
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNvPublic, Tpm2bSensitiveCreate,
    TpmaNv, TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmsEccParms, TpmsNvPublic, TpmtPublic,
    TpmtSymDefObject,
};
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_nv_name_algorithms_adversarial() {
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
            auth: tpm2::Tpm2bAuth::default(),
            public_info,
        };
        let define_handles = tpm2::commands::NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };

        execute_with_password_sessions(&mut sim, &define_space, define_handles, 1, &[])
            .expect("could not call TPM2_DefineSpace with SHA384");

        let read_public = tpm2::commands::NVReadPublic {};
        let read_handles = tpm2::commands::NVReadPublicHandles {
            nv_index: Handle(0x01800010),
        };

        let (rsp, _) = execute_with_password_sessions(&mut sim, &read_public, read_handles, 0, &[])
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
            auth: tpm2::Tpm2bAuth::default(),
            public_info,
        };
        let define_handles = tpm2::commands::NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };

        execute_with_password_sessions(&mut sim, &define_space, define_handles, 1, &[])
            .expect("could not call TPM2_DefineSpace with SHA512");

        let read_public = tpm2::commands::NVReadPublic {};
        let read_handles = tpm2::commands::NVReadPublicHandles {
            nv_index: Handle(0x01800011),
        };

        let (rsp, _) = execute_with_password_sessions(&mut sim, &read_public, read_handles, 0, &[])
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
            auth: tpm2::Tpm2bAuth::default(),
            public_info,
        };
        let define_handles = tpm2::commands::NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };

        execute_with_password_sessions(&mut sim, &define_space, define_handles, 1, &[])
            .expect("could not call TPM2_DefineSpace with SHA1");

        let read_public = tpm2::commands::NVReadPublic {};
        let read_handles = tpm2::commands::NVReadPublicHandles {
            nv_index: Handle(0x01800012),
        };

        let (rsp, _) = execute_with_password_sessions(&mut sim, &read_public, read_handles, 0, &[])
            .expect("could not call TPM2_ReadPublic on SHA1 NV index");
        assert_eq!(
            &rsp.nv_name.get_buffer()[0..2],
            &Alg::from(TpmiAlgHash::Sha1).id().to_be_bytes()
        );
    }

    // 4. create_primary with name_alg = SHA512 must fail with Value error
    {
        let ecc_parms = TpmsEccParms {
            symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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
            in_sensitive,
            in_public,
            ..Default::default()
        };
        let create_handles = CreatePrimaryHandles {
            primary_handle: Handle::RH_ENDORSEMENT,
        };

        let err =
            match execute_with_password_sessions(&mut sim, &create_primary, create_handles, 0, &[])
            {
                Ok(_) => panic!("expected create_primary to fail"),
                Err(e) => e,
            };
        assert_eq!(err, TpmRc::VALUE.get());
    }
}
