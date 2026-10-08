use crate::test_utils::*;
use tpm2::TpmEccCurve;
use tpm2::commands::{Commit, CommitHandles};
use tpm2::*;
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_commit_s2_size_check() {
    let mut sim = create_simulator!();

    // Clear and get Owner auth
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

    // Test with s2 = 40 bytes (max allowed is 32 for SHA256)
    let s2_bytes = [0xBB; 40];
    let s2 = Tpm2bSensitiveData::from_bytes(&s2_bytes).unwrap();
    let commit = Commit {
        p1: Tpm2bEccPoint::default(),
        s2,
        y2: Tpm2bEccParameter::default(),
    };
    let commit_handles = CommitHandles {
        sign_handle: key_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &commit, commit_handles, 1, b"password");
    match res {
        Err(e) => {
            // TPM_RC_SIZE (0x095) with possible parameter info
            assert_eq!(
                e & 0x0BF,
                0x095,
                "Expected TPM_RC_SIZE for invalid s2 length, got 0x{:X}",
                e
            );
        }
        Ok(_) => panic!("Expected Commit to fail with TPM_RC_SIZE but it succeeded!"),
    }
}
