use crate::test_utils::*;
use tpm2::Handle;
#[allow(deprecated)]
use tpm2::commands::{CreateLoaded, CreatePrimary};
use tpm2::*;
use tpm2_simulator::create_simulator;

#[test]
#[allow(deprecated)]
fn test_create_loaded_auth_bypass() {
    let mut sim = create_simulator!();

    // 1. Create a primary key WITH A PASSWORD
    let parent_password = b"secret_parent_pass";
    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(parent_password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive: tpm2::Tpm2b(tpmt_sensitive),
        in_public: tpm2::Tpm2b(pub_area),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp_handles = execute_with_password_sessions(&mut sim, &cp_cmd, 1, &[]).unwrap();

    // 2. Try to CreateLoaded under this parent WITH WRONG PASSWORD
    let cl_cmd = CreateLoaded {
        parent_handle: cp_resp_handles.object_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&pub_area),
    };

    let wrong_password = b"wrong_pass";
    let res = execute_with_password_sessions(&mut sim, &cl_cmd, 1, wrong_password);

    assert!(
        res.is_err(),
        "BUG: CreateLoaded succeeded with incorrect parent password! Missing auth check."
    );
}
