#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};
use tpm2::commands::{EvictControl, EvictControlHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

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
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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
    let mut sim = create_simulator!();

    let srk_create = CreatePrimary {
        in_public: tpm2::Tpm2b(ecc_srk_template()),
        ..Default::default()
    };
    let srk_create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, srk_create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &srk_create, srk_create_handles, 1, &[])
            .expect("could not generate SRK");

    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: srk_create_rsp_handles.object_handle,
    };
    let evict_cmd = EvictControl {
        persistent_handle: Handle(0x81000000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[])
        .expect("could not persist");
}
