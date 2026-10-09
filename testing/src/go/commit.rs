use crate::test_utils::*;
use tpm2::commands::{Commit, CommitHandles, CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

/// Builds the `CreateLoaded` command used by `TestCommit`: an ECDAA (SHA-256)
/// signing key on the BN P-256 curve, with `password` as its user auth.
pub(crate) fn commit_create_loaded(password: &'static [u8]) -> CreateLoaded<'static> {
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
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(tpm2::TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::BNP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    CreateLoaded {
        in_sensitive,
        in_public: crate::test_utils::make_template(&pub_area),
    }
}

// Original Go test: commit_test.go - TestCommit
#[test]
fn test_commit() {
    let mut sim = create_simulator!();

    let password = b"hello";

    let create = commit_create_loaded(password);
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle::RH_OWNER,
    };

    let (_rsp_cp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[])
            .expect("could not create key");

    // P1 = (1, 2), which lies on the BN P-256 curve (y^2 = x^3 + 3).
    let commit = Commit {
        p1: tpm2::Tpm2b(TpmsEccPoint {
            x: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
            y: Tpm2bEccParameter::from_bytes(&[2]).unwrap(),
        }),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    let commit_handles = CommitHandles {
        sign_handle: rsp_handles.object_handle,
    };

    let (resp1, _) =
        execute_with_password_sessions(&mut sim, &commit, commit_handles.clone(), 1, password)
            .expect("could not commit");
    let first_counter = resp1.counter;

    let (resp2, _) = execute_with_password_sessions(&mut sim, &commit, commit_handles, 1, password)
        .expect("could not commit");
    let second_counter = resp2.counter;

    assert_eq!(
        first_counter + 1,
        second_counter,
        "counter did not increment"
    );

    // Mirrors the deferred FlushContext in the Go test.
    let _ = flush_context(&mut sim, rsp_handles.object_handle);
}
