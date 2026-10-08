#![forbid(unsafe_code)]
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};
use tpm2::commands::{EvictControl, EvictControlHandles};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;

use crate::test_utils::*;
use tpm2::*;
use tpm2_simulator::{Simulator, create_simulator};

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
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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

#[test]
fn test_evict_control_null_hierarchy() {
    let mut sim = create_simulator!();

    // CreatePrimary in Null hierarchy
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_NULL,
    };
    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let (_, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // Try to make persistent
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_PLATFORM,
        object_handle: rsp_handles.object_handle,
    };
    let evict_cmd = EvictControl {
        persistent_handle: Handle(0x81800000),
    };
    let res = execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[]);

    match res {
        Err(e) if e == TpmRc::ATTRIBUTES.with(Position::handle(2)).get() => { /* Expected */ }
        Err(e) => panic!("Expected attributes_for error, got 0x{:x}", e),
        Ok(_) => panic!("Expected error but succeeded"),
    }
}

#[test]
fn test_evict_control_persistent_value() {
    let mut sim = create_simulator!();

    // CreatePrimary in Platform hierarchy
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_PLATFORM,
    };
    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let (_, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // Make persistent
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_PLATFORM,
        object_handle: rsp_handles.object_handle,
    };
    let evict_cmd = EvictControl {
        persistent_handle: Handle(0x81800000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[]).unwrap();

    // Try to evict it with DIFFERENT persistent handle
    let evict_handles2 = EvictControlHandles {
        auth: Handle::RH_PLATFORM,
        object_handle: Handle(0x81800000), // Existing persistent handle
    };
    let evict_cmd2 = EvictControl {
        persistent_handle: Handle(0x81800001), // Mismatched persistent handle
    };
    let res2 = execute_with_password_sessions(&mut sim, &evict_cmd2, evict_handles2, 1, &[]);

    match res2 {
        Err(e) if e == TpmRc::HANDLE.with(Position::handle(2)).get() => { /* Expected */ }
        Err(e) => panic!("Expected Handle error, got 0x{:x}", e),
        Ok(_) => panic!("Expected error but succeeded"),
    }
}
