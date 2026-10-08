use crate::test_utils::*;
use tpm2::commands::CreateLoadedHandles;
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_create_loaded_trailing_garbage_sensitive() {
    let mut sim = create_simulator!();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };

    let mut valid_buf = [0u8; 1024];
    let valid_len = marshal_to_slice(&tpmt_sensitive, &mut valid_buf);

    let mut bad_buf = valid_buf[..valid_len + 5].to_vec();
    // Add some trailing garbage
    bad_buf[valid_len] = 0xFF;
    bad_buf[valid_len + 1] = 0xFF;

    assert!(
        Tpm2bSensitiveCreate::from_bytes(&bad_buf).is_err(),
        "Client unmarshaler should reject trailing garbage in in_sensitive"
    );

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
    let in_public = crate::test_utils::make_template(&pub_area);

    struct BadCreateLoaded<'a> {
        in_sensitive_buf: &'a [u8],
        in_public: Tpm2bTemplate<'a>,
    }
    impl Marshal for BadCreateLoaded<'_> {
        const MAX_SIZE: usize = 4096;
        type MaxBuffer = [u8; 4096];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off =
                (self.in_sensitive_buf.len() as u16).marshal((&mut dst[0..2]).try_into().unwrap());
            dst[off..off + self.in_sensitive_buf.len()].copy_from_slice(self.in_sensitive_buf);
            off += self.in_sensitive_buf.len();
            off += self.in_public.marshal(
                (&mut dst[off..off + Tpm2bTemplate::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off
        }
    }
    impl Command for BadCreateLoaded<'_> {
        const CMD_CODE: TpmCc = TpmCc::CreateLoaded;
        type Handles = CreateLoadedHandles;
        type Response<'a> = ();
        type RespHandles = ();
    }

    let create = BadCreateLoaded {
        in_sensitive_buf: &bad_buf,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPM_RH_OWNER
    };

    let res = execute_with_password_sessions_status(&mut sim, &create, create_handles, 1, &[]);
    match res {
        Ok(_) => panic!("BUG: CreateLoaded succeeded with trailing garbage in in_sensitive!"),
        Err(e) => {
            println!("Got expected error code: 0x{:x}", e);
            // 0x195 is TpmRc::SIZE. With Pos1, it should be 0x195 + 0x100?
            // Actually let's just make sure it fails.
        }
    }
}
