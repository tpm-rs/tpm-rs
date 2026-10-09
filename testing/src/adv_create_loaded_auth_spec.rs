use crate::test_utils::*;
use tpm2::commands::{CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

#[test]
fn test_create_loaded_auth_larger_than_name_alg_digest_fails() {
    let mut sim = create_simulator!();
    let password = [0x41u8; 40]; // 40 bytes, > SHA256 (32 bytes)
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(&password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
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

    let create = CreateLoaded {
        in_sensitive,
        in_public: crate::test_utils::make_template(&pub_area),
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(tpm2::Handle::RH_OWNER.0),
    };

    let res = execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]);

    // It should fail with TPM_RC_SIZE because the auth size > nameAlg digest size.
    assert!(
        res.is_err(),
        "Expected CreateLoaded to fail when auth size is too large"
    );
    match res {
        Err(e) => {
            // TPM_RC_SIZE = 0x095, optionally with format bits
            assert_eq!(
                e & 0x0BF,
                0x095,
                "Expected TPM_RC_SIZE for invalid auth length, got 0x{:X}",
                e
            );
        }
        Ok(_) => panic!("Expected CreateLoaded to fail but it succeeded"),
    }
}
