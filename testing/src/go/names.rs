use crate::test_utils::marshal_to_slice;
use tpm2::Alg;
// Ported from tpm-go/tpm2/test/names_test.go

use tpm2::Handle;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};

use crate::test_utils::*;
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, TpmaNv, TpmaObject, TpmiAlgHash,
    TpmiAlgSymMode, TpmsEccParms, TpmsNvPublic, TpmtPublic, TpmtSymDefObject,
};
use tpm2_simulator::create_simulator;

// Original Go test: names_test.go - TestHandleName
#[test]
fn test_handle_name() {
    let endorsement = Handle::RH_ENDORSEMENT; // 0x4000000B
    let want = [0x40, 0x00, 0x00, 0x0B];
    let bytes = endorsement.0.to_be_bytes();
    let name = Tpm2bName::from_bytes(&bytes).unwrap();
    assert_eq!(name.get_buffer(), &want);
}

// Original Go test: names_test.go - TestObjectName
#[test]
fn test_object_name() {
    let mut sim = create_simulator!();

    let auth_policy = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7,
        0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA,
    ];

    let ecc_parms = TpmsEccParms {
        symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        scheme: None,
        curve_id: tpm2::TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::ADMIN_WITH_POLICY
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::from_bytes(&auth_policy).unwrap(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            // go-tpm's ECCEKTemplate uses 32 zero bytes for both X and Y.
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
                y: tpm2::Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
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

    let (rsp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary, create_handles, 1, &[])
            .expect("could not call TPM2_CreatePrimary");

    let public_struct = rsp
        .out_public
        .to_struct()
        .expect("failed to convert to struct");

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public_struct, &mut pub_buf);

    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(
        CLIENT_CRYPTO,
        TpmiAlgHash::Sha256,
        &pub_buf[..pub_len],
        &mut digest_buf,
    )
    .unwrap()
    .digest();
    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(digest);
    let name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(rsp.name.get_buffer(), name.get_buffer());

    // Deferred FlushContext in Go.
    let _ = flush_context(&mut sim, rsp_handles.object_handle);
}

// Original Go test: names_test.go - TestNVName
#[test]
fn test_nv_name() {
    let mut sim = create_simulator!();

    let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
    attributes.set_type(tpm2::TpmNt::Ordinary);

    let public_info_struct = TpmsNvPublic {
        nv_index: Handle(0x0180000F),
        name_alg: TpmiAlgHash::Sha256,
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
        .expect("could not call TPM2_DefineSpace");

    let read_public = tpm2::commands::NVReadPublic {};
    let read_handles = tpm2::commands::NVReadPublicHandles {
        nv_index: Handle(0x0180000F),
    };

    let (rsp, _) = execute_with_password_sessions(&mut sim, &read_public, read_handles, 0, &[])
        .expect("could not call TPM2_ReadPublic");

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public_info_struct, &mut pub_buf);

    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(
        CLIENT_CRYPTO,
        TpmiAlgHash::Sha256,
        &pub_buf[..pub_len],
        &mut digest_buf,
    )
    .unwrap()
    .digest();
    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(digest);
    let name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(rsp.nv_name.get_buffer(), name.get_buffer());
}
