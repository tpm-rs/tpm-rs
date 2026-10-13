use crate::test_utils::*;
use tpm2::Handle;
#[allow(deprecated)]
use tpm2::commands::{Commit, CreateLoaded};
use tpm2::*;
use tpm2_simulator::create_simulator;

#[test]
#[allow(deprecated)]
fn test_commit_on_rsa_key() {
    let mut sim = create_simulator!();

    let password = b"hello";

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
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

    let in_public = crate::test_utils::make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &commit, 1, password);
    assert!(res.is_err(), "Commit on RSA key should fail");
}
