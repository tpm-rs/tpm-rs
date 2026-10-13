#![forbid(unsafe_code)]
use crate::test_utils::*;
use testing::tpm::Tpm;
use tpm2::commands::CreatePrimary;
use tpm2::commands::EvictControl;
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};

/// Equivalent of go-tpm's `ECCSRKTemplate`.
fn ecc_srk_template() -> TpmtPublic<'static> {
    static ZEROS: [u8; 32] = [0u8; 32];
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&ZEROS).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&ZEROS).unwrap(),
            },
        ),
    }
}

// Original Go test: evict_control_test.go - TestEvictControl
#[test]
fn test_evict_control() {
    let mut sim = Tpm::new();

    let srk_create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_public: tpm2::Tpm2b(ecc_srk_template()),
        ..Default::default()
    };
    let srk_create_rsp = execute_with_password_sessions(&mut sim, &srk_create, 1, &[])
        .expect("could not generate SRK");

    let evict_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: srk_create_rsp.object_handle,
        persistent_handle: Handle(0x81000000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]).expect("could not persist");
}
