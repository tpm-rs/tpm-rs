use crate::test_utils::*;
use tpm2::commands::{Clear, ClearHandles, CreatePrimary, CreatePrimaryHandles};
use tpm2::*;
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

// Original Go test: clear_test.go - TestClear
#[test]
fn test_clear() {
    let mut sim = create_simulator!();

    let srk_create = CreatePrimary {
        in_public: tpm2::Tpm2b(ecc_srk_template()),
        ..Default::default()
    };
    let srk_create_handles = || CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (srk_create_rsp, _) =
        execute_with_password_sessions(&mut sim, &srk_create, srk_create_handles(), 1, &[])
            .expect("could not generate SRK");
    let srk_name1 = srk_create_rsp.name;

    let clear = Clear {};
    let clear_handles = ClearHandles {
        auth_handle: Handle::RH_LOCKOUT,
    };
    execute_with_password_sessions(&mut sim, &clear, clear_handles, 1, &[])
        .expect("could not clear TPM");

    let (srk_create_rsp, srk_create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &srk_create, srk_create_handles(), 1, &[])
            .expect("could not generate SRK");

    let srk_name2 = srk_create_rsp.name;

    // Go's `t.Errorf` does not abort the test, so the deferred flush still
    // runs before the test is reported as failed.
    let names_equal = srk_name1.get_buffer() == srk_name2.get_buffer();

    flush_context(&mut sim, srk_create_rsp_handles.object_handle).expect("could not flush SRK");

    assert!(
        !names_equal,
        "SRK Name did not change across clear, was {:02x?} both times",
        srk_name1.get_buffer()
    );
}
