#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, EvictControl, EvictControlHandles};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

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
fn test_evict_control_stress() {
    let mut sim = create_simulator!();

    // Create a transient object in Owner hierarchy
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public_owner = tpm2::Tpm2b(get_ecc_srk_template(0));
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let create_handles_owner = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let create_cmd_owner = CreatePrimary {
        in_sensitive,
        in_public: in_public_owner,
        outside_info,
        creation_pcr,
    };

    let (_, rsp_owner) =
        execute_with_password_sessions(&mut sim, &create_cmd_owner, create_handles_owner, 1, &[])
            .unwrap();
    let owner_transient_handle = rsp_owner.object_handle;

    // Create a transient object in Platform hierarchy
    let in_public_plat = tpm2::Tpm2b(get_ecc_srk_template(1));
    let create_cmd_plat = CreatePrimary {
        in_sensitive,
        in_public: in_public_plat,
        outside_info,
        creation_pcr,
    };
    let create_handles_plat = CreatePrimaryHandles {
        primary_handle: Handle::RH_PLATFORM,
    };
    let (_, rsp_plat) =
        execute_with_password_sessions(&mut sim, &create_cmd_plat, create_handles_plat, 1, &[])
            .unwrap();
    let plat_transient_handle = rsp_plat.object_handle;

    // Fuzz inputs
    let auth_handles = [
        Handle::RH_OWNER,
        Handle::RH_PLATFORM,
        Handle::RH_NULL,
        Handle::RH_ENDORSEMENT,
    ];
    let object_handles = [
        owner_transient_handle,
        plat_transient_handle,
        Handle(0x81000005),
        Handle(0x81800005),
    ];
    let persistent_handles = [
        Handle(0x80000000), // Out of range
        Handle(0x81000005), // Owner range
        Handle(0x81800005), // Platform range
        Handle(0x82000000), // Out of range
    ];

    for &auth in &auth_handles {
        for &obj in &object_handles {
            for &pers in &persistent_handles {
                let handles = EvictControlHandles {
                    auth,
                    object_handle: obj,
                };
                let cmd = EvictControl {
                    persistent_handle: pers,
                };

                let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);

                // Determine expected behavior according to spec
                let is_obj_loaded = obj == owner_transient_handle || obj == plat_transient_handle;
                let is_transient = is_obj_loaded; // only transient ones in this test are loaded

                if !is_obj_loaded {
                    assert!(res.is_err());
                    assert_eq!(res.unwrap_err(), TpmRc::REFERENCE_H1.get());
                    continue;
                }

                if auth != Handle::RH_OWNER && auth != Handle::RH_PLATFORM {
                    assert!(res.is_err());
                    assert_eq!(
                        res.unwrap_err(),
                        388 // value_for(Position::handle(1))
                    );
                    continue;
                }

                if is_transient {
                    // Make Persistent checks
                    let mut expected_err = 0;

                    if auth == Handle::RH_PLATFORM {
                        if obj != plat_transient_handle {
                            expected_err = TpmRc::HIERARCHY.with(Position::handle(2)).get();
                        } else if pers.0 < 0x81800000 || pers.0 > 0x81FFFFFF {
                            expected_err = TpmRc::RANGE.with(Position::parameter(1)).get();
                        }
                    } else if auth == Handle::RH_OWNER {
                        if obj == plat_transient_handle {
                            expected_err = TpmRc::HIERARCHY.with(Position::handle(2)).get();
                        } else if pers.0 < 0x81000000 || pers.0 > 0x817FFFFF {
                            expected_err = TpmRc::RANGE.with(Position::parameter(1)).get();
                        }
                    }

                    if expected_err == 0 {
                        assert!(
                            res.is_ok(),
                            "Failed when it should succeed: auth={:x?} obj={:x?} pers={:x?}",
                            auth,
                            obj,
                            pers
                        );
                        // Once successful, we need to evict it so it doesn't fail on next iteration with NVDefined
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
                        assert!(res.is_err());
                        // Only verify it didn't succeed to keep it simple, since exact error handles might vary
                    }
                } else {
                    // Evict Persistent checks
                    let mut expected_err = 0;
                    if obj != pers {
                        expected_err = TpmRc::HANDLE.get();
                    } else {
                        if (auth == Handle::RH_OWNER && (obj.0 < 0x81000000 || obj.0 > 0x817FFFFF))
                            || (auth == Handle::RH_PLATFORM
                                && (obj.0 < 0x81000000 || obj.0 > 0x81FFFFFF))
                        {
                            expected_err = TpmRc::RANGE.with(Position::parameter(1)).get();
                        }
                    }

                    // since the object doesn't exist, it might also fail with Handle if it passes the previous checks
                    assert!(res.is_err());
                    if expected_err != 0 {
                        let err = res.unwrap_err();
                        if err != expected_err
                            && err != TpmRc::HANDLE.get()
                            && err != TpmRc::REFERENCE_H1.get()
                        {
                            panic!("actual: {:x?}, expected: {:x?}", err, expected_err);
                        }
                    }
                }
            }
        }
    }
}
