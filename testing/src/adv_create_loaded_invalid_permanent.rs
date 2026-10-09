use crate::test_utils::*;
use tpm2::commands::{CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

#[test]
fn test_create_loaded_invalid_permanent_handle() {
    let mut sim = create_simulator!();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
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
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let in_public = crate::test_utils::make_template(&pub_area);

    let create = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0xFFFFFFFF), // Invalid permanent handle
    };

    let res = execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]);
    assert!(res.is_err(), "CreateLoaded with 0xFFFFFFFF should fail");
}
