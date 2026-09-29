use crate::test_utils::*;
use tpm2::TpmEccCurve;
use tpm2::commands::{Commit, CommitHandles};
use tpm2::*;
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_commit_y2_without_p1() {
    let mut sim = create_simulator!();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"password").unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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

    let create = tpm2::commands::CreateLoaded {
        in_sensitive,
        in_public: crate::test_utils::make_template(&pub_area),
    };
    let create_handles = tpm2::commands::CreateLoadedHandles {
        parent_handle: tpm2::Handle(0x40000001),
    };

    let (_, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]).unwrap();
    let key_handle = rsp_handles.object_handle;

    // Test with y2 provided but P1 empty
    let y2_bytes = [0xCC; 32];
    let y2 = Tpm2bEccParameter::from_bytes(&y2_bytes).unwrap();
    let commit = Commit {
        p1: Tpm2bEccPoint::default(), // Empty!
        s2: Tpm2bSensitiveData::default(),
        y2,
    };
    let commit_handles = CommitHandles {
        sign_handle: key_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &commit, commit_handles, 1, b"password");
    match res {
        Err(e) => {
            // Should be TPM_RC_SIZE (0x095) per TPM 2.0 Spec (when s2 is empty and y2 is present).
            assert_eq!(
                e & 0x0BF,
                0x095,
                "Expected error when y2 is provided without s2/p1"
            );
        }
        Ok(_) => {
            panic!("Expected Commit to fail when y2 is provided without p1, but it succeeded!")
        }
    }
}
