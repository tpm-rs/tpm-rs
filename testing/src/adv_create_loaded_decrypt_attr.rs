use crate::test_utils::*;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bData, Tpm2bPublicKeyRsa, Tpm2bTemplate, TpmaObject, TpmiAlgHash,
    TpmsRsaParms, TpmtPublic, TpmtRsaScheme,
    commands::{CreateLoaded, CreateLoadedHandles, CreatePrimary, CreatePrimaryHandles},
};
use tpm2_simulator::create_simulator;

#[test]
fn test_create_loaded_decrypt_attr() {
    let mut sim = create_simulator!();

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: tpm2::TpmiRsaKeyBits(2048),
        exponent: 0,
    };

    let public_primary = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject(
            TpmaObject::FIXED_TPM.0
                | TpmaObject::FIXED_PARENT.0
                | TpmaObject::SENSITIVE_DATA_ORIGIN.0
                | TpmaObject::USER_WITH_AUTH.0
                | TpmaObject::SIGN_ENCRYPT.0, // NOT DECRYPT
        ),
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };

    let cmd1 = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(tpm2::TpmsSensitiveCreate {
            user_auth: Default::default(),
            data: Default::default(),
        }),
        in_public: tpm2::Tpm2b(public_primary),
        outside_info: Tpm2bData::default(),
        creation_pcr: Default::default(),
    };
    let handles1 = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_rsp1, resp_handles1) =
        execute_with_password_sessions(&mut sim, &cmd1, handles1, 1, &[]).unwrap();

    let parent_handle = resp_handles1.object_handle;

    let public_child = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject(
            TpmaObject::FIXED_TPM.0
                | TpmaObject::FIXED_PARENT.0
                | TpmaObject::SENSITIVE_DATA_ORIGIN.0
                | TpmaObject::USER_WITH_AUTH.0
                | TpmaObject::SIGN_ENCRYPT.0,
        ),
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public_child, &mut pub_buf);

    let cmd2 = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(tpm2::TpmsSensitiveCreate {
            user_auth: Default::default(),
            data: Default::default(),
        }),
        in_public: Tpm2bTemplate::from_bytes(&pub_buf[..pub_len]).unwrap(),
    };
    let handles2 = CreateLoadedHandles { parent_handle };

    let res = execute_with_password_sessions(&mut sim, &cmd2, handles2, 1, &[]);
    assert!(
        res.is_err(),
        "Expected TPM2_CreateLoaded to fail on parent without decrypt attr"
    );
    let err = res.err().unwrap();
    assert_eq!(err, 0x182, "Expected Attributes error (0x182), got {}", err);
}
