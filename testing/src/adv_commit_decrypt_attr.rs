use tpm2::TpmEccCurve;

use crate::test_utils::*;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bData, Tpm2bEccParameter, TpmaObject, TpmiAlgHash, TpmsEccParms,
    TpmsEccPoint, TpmtPublic,
    commands::{Commit, CommitHandles, CreatePrimary, CreatePrimaryHandles},
};
use tpm2_simulator::create_simulator;

#[test]
fn test_commit_decrypt_attr() {
    let mut sim = create_simulator!();

    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_primary = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject(
            TpmaObject::FIXED_TPM.0
                | TpmaObject::FIXED_PARENT.0
                | TpmaObject::SENSITIVE_DATA_ORIGIN.0
                | TpmaObject::USER_WITH_AUTH.0
                | TpmaObject::SIGN_ENCRYPT.0
                | TpmaObject::DECRYPT.0, // DECRYPT SET!
        ),
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
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

    let sign_handle = resp_handles1.object_handle;

    let cmd2 = Commit {
        p1: tpm2::Tpm2bEccPoint::default(),
        s2: tpm2::Tpm2bSensitiveData::default(),
        y2: tpm2::Tpm2bEccParameter::default(),
    };
    let handles2 = CommitHandles { sign_handle };

    let res = execute_with_password_sessions(&mut sim, &cmd2, handles2, 1, &[]);
    assert!(
        res.is_err(),
        "Expected TPM2_Commit to fail on handle WITH decrypt attr"
    );
    let err = res.err().unwrap();
    assert_eq!(err, 0x182, "Expected Attributes error (0x182), got {}", err);
}
