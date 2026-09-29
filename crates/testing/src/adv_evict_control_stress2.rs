#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, EvictControl, EvictControlHandles};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn get_ecc_srk_template(unique: u8) -> TpmtPublic<'static> {
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
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(&[unique; 32]))
                    .unwrap(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

#[test]
fn test_evict_control_comprehensive_stress() {
    let mut sim = create_simulator!();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);

    let hierarchies = [
        Handle::RH_OWNER,
        Handle::RH_PLATFORM,
        Handle::RH_ENDORSEMENT,
    ];

    let mut transient_handles = vec![];
    for (i, &h) in hierarchies.iter().enumerate() {
        let in_public = tpm2::Tpm2b(get_ecc_srk_template(i as u8));
        let create_cmd = CreatePrimary {
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let handles = CreatePrimaryHandles { primary_handle: h };
        let (_, rsp) =
            execute_with_password_sessions(&mut sim, &create_cmd, handles, 1, &[]).unwrap();
        transient_handles.push(rsp.object_handle);
    }

    let auth_handles = [Handle::RH_OWNER, Handle::RH_PLATFORM];
    let persistent_handles = [
        Handle(0x80000000), // Out of range
        Handle(0x81000005), // Owner range
        Handle(0x81800005), // Platform range
    ];

    for &auth in &auth_handles {
        for (i, &obj_hier) in hierarchies.iter().enumerate() {
            let obj = transient_handles[i];
            for &pers in &persistent_handles {
                let handles = EvictControlHandles {
                    auth,
                    object_handle: obj,
                };
                let cmd = EvictControl {
                    persistent_handle: pers,
                };

                let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);

                let mut expected_err = 0;

                // 0. Parameter unmarshalling check (TPMI_DH_PERSISTENT range 0x81000000..=0x81FFFFFF)
                if pers.0 < 0x81000000 || pers.0 > 0x81FFFFFF {
                    expected_err = TpmRc::VALUE.with(Position::parameter(1)).get();
                }

                // 1. Check Attributes for Null first (spec precedence in action code)
                if expected_err == 0 && obj_hier == Handle::RH_NULL {
                    expected_err = TpmRc::ATTRIBUTES.with(Position::handle(2)).get();
                }

                // 2. Check Hierarchy
                if expected_err == 0 {
                    if auth == Handle::RH_PLATFORM {
                        if obj_hier != Handle::RH_PLATFORM {
                            expected_err = TpmRc::HIERARCHY.with(Position::handle(2)).get();
                        }
                    } else if auth == Handle::RH_OWNER
                        && obj_hier != Handle::RH_OWNER
                        && obj_hier != Handle::RH_ENDORSEMENT
                    {
                        expected_err = TpmRc::HIERARCHY.with(Position::handle(2)).get();
                    }
                }

                // 3. Check Range
                if expected_err == 0 {
                    if auth == Handle::RH_PLATFORM {
                        if pers.0 < 0x81800000 || pers.0 > 0x81FFFFFF {
                            expected_err = TpmRc::RANGE.with(Position::parameter(1)).get();
                        }
                    } else if auth == Handle::RH_OWNER
                        && (pers.0 < 0x81000000 || pers.0 > 0x817FFFFF)
                    {
                        expected_err = TpmRc::RANGE.with(Position::parameter(1)).get();
                    }
                }

                if expected_err == 0 {
                    assert!(
                        res.is_ok(),
                        "Failed when it should succeed: auth={:?} hier={:?} pers={:x?}, err={:?}",
                        auth,
                        obj_hier,
                        pers,
                        res.err()
                    );
                    // Cleanup so next iteration won't fail with NvDefined
                    let evict_res = execute_with_password_sessions(
                        &mut sim,
                        &cmd,
                        EvictControlHandles {
                            auth,
                            object_handle: pers,
                        },
                        1,
                        &[],
                    );
                    assert!(evict_res.is_ok());
                } else {
                    assert!(
                        res.is_err(),
                        "Succeeded when it should fail: auth={:?} hier={:?} pers={:x?}, expected err={:x?}",
                        auth,
                        obj_hier,
                        pers,
                        expected_err
                    );
                    let actual_err = res.unwrap_err();
                    assert_eq!(
                        actual_err, expected_err,
                        "actual: {:x?}, expected: {:x?}",
                        actual_err, expected_err
                    );
                }
            }
        }
    }
}
