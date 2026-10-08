use crate::test_utils::*;
use tpm2::commands::{Commit, CommitHandles, CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_commit_trailing_valid_p1() {
    let mut sim = create_simulator!();
    let password = b"hello";
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
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
    let create = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001),
    };
    let (_rsp_cp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]).unwrap();

    let commit1 = Commit {
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    let commit1_handles = CommitHandles {
        sign_handle: rsp_handles.object_handle,
    };
    let (commit1_rsp, _) =
        execute_with_password_sessions(&mut sim, &commit1, commit1_handles, 1, password).unwrap();

    let valid_point = commit1_rsp.e.0;

    let mut valid_point_buf = [0u8; 100];
    let valid_len = marshal_to_slice(&valid_point, &mut valid_point_buf);
    let bad_p1_buf = valid_point_buf[..valid_len + 5].to_vec();

    struct BadCommit<'a> {
        p1_buf: &'a [u8],
        s2: Tpm2bSensitiveData<'a>,
        y2: Tpm2bEccParameter<'a>,
    }
    impl Marshal for BadCommit<'_> {
        const MAX_SIZE: usize = 1024;
        type MaxBuffer = [u8; 1024];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off = (self.p1_buf.len() as u16).marshal((&mut dst[0..2]).try_into().unwrap());
            dst[off..off + self.p1_buf.len()].copy_from_slice(self.p1_buf);
            off += self.p1_buf.len();
            off += self.s2.marshal(
                (&mut dst[off..off + Tpm2bSensitiveData::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off += self.y2.marshal(
                (&mut dst[off..off + Tpm2bEccParameter::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off
        }
    }
    impl Command for BadCommit<'_> {
        const CMD_CODE: TpmCc = TpmCc::Commit;
        type Handles = CommitHandles;
        type Response<'a> = ();
        type RespHandles = ();
    }

    let commit2 = BadCommit {
        p1_buf: &bad_p1_buf,
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    let commit2_handles = CommitHandles {
        sign_handle: rsp_handles.object_handle,
    };

    let result =
        execute_with_password_sessions_status(&mut sim, &commit2, commit2_handles, 1, password);
    match result {
        Ok(_) => panic!("VULNERABILITY: Trailing garbage in valid p1 ignored!"),
        Err(e) => println!("Error code: 0x{:x}", e),
    }
}
