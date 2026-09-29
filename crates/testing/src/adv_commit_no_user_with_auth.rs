use crate::test_utils::*;
use tpm2::commands::{Commit, CommitHandles, CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_commit_no_user_with_auth_bypass() {
    let mut sim = create_simulator!();

    let password = b"secret";

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    // NOTICE: We omit TpmaObject::USER_WITH_AUTH
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
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
        parent_handle: Handle(tpm2::Handle::RH_OWNER.0),
    };

    let (_rsp_cp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]).unwrap();

    let commit = Commit {
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let commit_handles = CommitHandles {
        sign_handle: rsp_handles.object_handle,
    };

    // Attempt to authorize using the password
    let result = execute_with_password_sessions(&mut sim, &commit, commit_handles, 1, password);
    if result.is_ok() {
        panic!(
            "VULNERABILITY: Commit allowed password authorization even though USER_WITH_AUTH was 0!"
        );
    }
}
