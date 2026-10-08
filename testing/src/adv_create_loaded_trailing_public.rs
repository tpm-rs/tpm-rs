use crate::test_utils::*;
use tpm2::commands::{CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_create_loaded_trailing_garbage_public() {
    let mut sim = create_simulator!();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let mut valid_buf = [0u8; 1024];
    let valid_len = marshal_to_slice(&pub_area, &mut valid_buf);

    let mut bad_buf = valid_buf[..valid_len + 5].to_vec();
    bad_buf[valid_len] = 0xDE;
    bad_buf[valid_len + 1] = 0xAD;

    let in_public = Tpm2bTemplate::from_bytes(&bad_buf).unwrap();

    let create = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPM_RH_OWNER
    };

    let res = execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]);
    match res {
        Ok(_) => panic!("BUG: CreateLoaded succeeded with trailing garbage in in_public!"),
        Err(e) => {
            println!("Got expected error code: 0x{:x}", e);
        }
    }
}
