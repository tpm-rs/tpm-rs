use crate::test_utils::marshal_to_slice;
use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{Commit, CommitHandles};
use tpm2::{
    PublicParmsAndId, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEccPoint, Tpm2bTemplate, TpmEccCurve,
    TpmaObject, TpmiAlgHash, TpmsEccParms, TpmsEccPoint, TpmsSchemeEcdaa, TpmtEccScheme,
    TpmtPublic,
};
use tpm2_simulator::create_simulator;

#[test]
fn test_commit_s2_empty_y2_not_empty() {
    let mut sim = create_simulator!();
    let auth = b"secret";

    let ecc_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject(
            TpmaObject::USER_WITH_AUTH.0
                | TpmaObject::SIGN_ENCRYPT.0
                | TpmaObject::SENSITIVE_DATA_ORIGIN.0,
        ),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                // SM2P256 is close enough or use NIST_P256 if available?
                // Let's use SM2P256 or another valid curve from constants
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&ecc_pub, &mut pub_buf);

    let in_sens = tpm2::TpmsSensitiveCreate {
        user_auth: tpm2::Tpm2bDigest::from_bytes(auth).unwrap(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };

    let mut in_sens_buf = [0u8; 1024];
    let _in_sens_len = marshal_to_slice(&in_sens, &mut in_sens_buf);

    let create_cmd = tpm2::commands::CreateLoaded {
        in_sensitive: tpm2::Tpm2b(in_sens),
        in_public: Tpm2bTemplate::from_bytes(&pub_buf[..pub_len]).unwrap(),
    };

    let handles = tpm2::commands::CreateLoadedHandles {
        parent_handle: Handle::RH_OWNER,
    };

    let (_rsp, resp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, handles, 1, &[])
            .expect("CreateLoaded failed");

    let key_handle = resp_handles.object_handle;

    let mut commit_cmd = Commit::default();

    let mut p1_buf = [0u8; 1024];
    let p1_len = marshal_to_slice(
        &(TpmsEccPoint {
            x: Tpm2bEccParameter::from_bytes(&[1u8; 32]).unwrap(),
            y: Tpm2bEccParameter::from_bytes(&[2u8; 32]).unwrap(),
        }),
        &mut p1_buf,
    );
    commit_cmd.p1 = Tpm2bEccPoint::from_bytes(&p1_buf[..p1_len]).unwrap();

    commit_cmd.s2 = tpm2::Tpm2bSensitiveData::default(); // Empty
    commit_cmd.y2 = Tpm2bEccParameter::from_bytes(&[3u8; 32]).unwrap(); // Not empty

    let res = execute_with_password_sessions(
        &mut sim,
        &commit_cmd,
        CommitHandles {
            sign_handle: key_handle,
        },
        1,
        &[],
    );

    assert!(
        res.is_err(),
        "Expected Commit to fail when s2 is empty but y2 is not empty"
    );
}
