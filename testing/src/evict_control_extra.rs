//! Extra (non-Go-parity) tests for evict_control, moved out of src/go.

use crate::test_utils::*;
use tpm2::commands::CreatePrimary;
use tpm2::commands::EvictControl;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

fn get_ecc_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// Persists an SRK and then exercises EvictControl edge cases: persisting to
/// an already-occupied persistent handle, evicting with a mismatching
/// persistent handle, and finally evicting correctly.
#[test]
fn test_evict_control_edge_cases() {
    let mut sim = create_simulator!();

    // 1. CreatePrimary
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // 2. EvictControl
    let evict_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: rsp_handles.object_handle,
        persistent_handle: Handle(0x81000000),
    };

    // Execute EvictControl
    execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]).expect("could not persist");

    // Edge case 1: Try to persist another object to the same persistent handle
    // Let's just create another primary or try to persist the same one
    let err = execute_with_password_sessions(
        &mut sim,
        &evict_cmd, // same auth, object_handle and persistent_handle
        1,
        &[],
    )
    .unwrap_err();
    println!("Err: 0x{:08X}", err);
    assert_eq!(err, TpmRc::NV_DEFINED.get());

    // Edge case 2: Evict the persistent object with mismatching persistent_handle
    let evict_cmd_mismatch = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: Handle(0x81000000),
        persistent_handle: Handle(0x81000001),
    };
    let err2 = execute_with_password_sessions(&mut sim, &evict_cmd_mismatch, 1, &[]).unwrap_err();
    println!("Err2: 0x{:08X}", err2);
    assert_eq!(err2, TpmRc::HANDLE.with(Position::handle(2)).get());
    // Note: Spec says Handle or Value depending on implementation. We return Handle.

    // Edge case 3: Correctly evict the persistent object
    let evict_cmd_correct = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: Handle(0x81000000),
        persistent_handle: Handle(0x81000000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd_correct, 1, &[])
        .expect("could not evict persistent object");
}
