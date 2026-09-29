#![forbid(unsafe_code)]

use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash,
    TpmiAlgSymMode, TpmiRsaKeyBits, TpmsEccParms, TpmsRsaParms, TpmtPublic, TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn default_ecc_public() -> TpmtPublic<'static> {
    let ecc_parms = TpmsEccParms {
        symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        scheme: None,
        curve_id: tpm2::TpmEccCurve::NistP256,
        kdf: None,
    };

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
            ecc_parms,
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    }
}

fn rsa_public(bits: u16) -> TpmtPublic<'static> {
    let rsa_parms = TpmsRsaParms {
        symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        scheme: None,
        key_bits: TpmiRsaKeyBits(bits),
        exponent: 0,
    };

    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    }
}

#[test]
fn test_create_primary_invalid_handle() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(default_ecc_public());
    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };

    // Use an invalid handle for primary (e.g. transient handle 0x80000000)
    let handles = CreatePrimaryHandles {
        primary_handle: Handle(0x80000000),
    };

    let err = match execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]) {
        Ok(_) => panic!("expected CreatePrimary to fail"),
        Err(e) => e,
    };
    assert_eq!(err, TpmRc::VALUE.with(Position::handle(1)).get());
}

#[test]
fn test_create_primary_invalid_session_type() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(default_ecc_public());
    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    // Use a session handle other than password session (e.g. 0x03000000)
    // We expect the command to fail with value_for(Position::session(1)) -> 0x1C7
    let bad_session = tpm2::TpmsAuthCommand {
        session_handle: Handle(0x03000000),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: tpm2::Tpm2bDigest::default(),
    };

    let mut buf = [0u8; 1024];
    let mut session_buf = [0u8; 1024];
    let cmd_len = marshal_to_slice(&cmd, &mut buf);
    let session_len = marshal_to_slice(&bad_session, &mut session_buf);

    let mut req_buf = Vec::new();
    // write header: tag=0x8002, size=0, cc=CreatePrimary(0x131)
    req_buf.extend_from_slice(&0x8002_u16.to_be_bytes());
    req_buf.extend_from_slice(&0_u32.to_be_bytes()); // placeholder for size
    req_buf.extend_from_slice(&0x00000131_u32.to_be_bytes());

    // write handles
    req_buf.extend_from_slice(&handles.primary_handle.0.to_be_bytes());

    // write auth area size
    req_buf.extend_from_slice(&(session_len as u32).to_be_bytes());
    req_buf.extend_from_slice(&session_buf[..session_len]);

    // write parameters
    req_buf.extend_from_slice(&buf[..cmd_len]);

    // update size in header
    let total_size = req_buf.len() as u32;
    req_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut resp_buf = [0u8; 4096];
    sim.transact(&req_buf, &mut resp_buf).unwrap();
    let response_code = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());

    assert_eq!(
        response_code,
        TpmRc::HANDLE.with(Position::session(1)).get()
    );
}

#[test]
fn test_create_primary_unsupported_rsa_bits() {
    let mut sim = create_simulator!();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    // Request a 512-bit RSA key, which is unsupported.
    let in_public = tpm2::Tpm2b(rsa_public(512));

    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let err = match execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]) {
        Ok(_) => panic!("Expected error for 512-bit RSA key"),
        Err(e) => e,
    };
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(2)).get());
}

#[test]
fn test_create_primary_hierarchy_auth() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(default_ecc_public());
    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    // 1. Change Owner Auth to "ownerpass"
    let hca_cmd = tpm2::commands::HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"ownerpass").unwrap(),
    };
    let hca_handles = tpm2::commands::HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &hca_cmd, hca_handles, 1, &[])
        .expect("Failed to change hierarchy auth");

    // 2. Try CreatePrimary with NO auth (empty password).
    let res_no_auth = execute_with_password_sessions(&mut sim, &cmd, handles.clone(), 1, &[]);
    assert_eq!(
        res_no_auth.err(),
        Some(TpmRc::BAD_AUTH.with(Position::session(1)).get())
    );

    // 3. Try CreatePrimary with WRONG auth.
    let res_wrong_auth =
        execute_with_password_sessions(&mut sim, &cmd, handles.clone(), 1, b"wrongpass");
    assert_eq!(
        res_wrong_auth.err(),
        Some(TpmRc::BAD_AUTH.with(Position::session(1)).get())
    );

    // 4. Try CreatePrimary with CORRECT auth.
    let resp = execute_with_password_sessions(&mut sim, &cmd, handles, 1, b"ownerpass");
    assert!(
        resp.is_ok(),
        "Expected success with correct password, got: {:?}",
        resp.err()
    );
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct LocalRSADecryptCmd {
    pub cipher_text: Tpm2bPublicKeyRsa<'static>,
    pub in_scheme: Option<tpm2::TpmtRsaScheme>,
    pub label: tpm2::Tpm2bLabel<'static>,
}

impl tpm2::Marshal for LocalRSADecryptCmd {
    const MAX_SIZE: usize = Tpm2bPublicKeyRsa::MAX_SIZE
        + <Option<tpm2::TpmtRsaScheme>>::MAX_SIZE
        + tpm2::Tpm2bLabel::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self.cipher_text.marshal(
            (&mut dst[0..Tpm2bPublicKeyRsa::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.in_scheme.marshal(
            (&mut dst[offset..offset + <Option<tpm2::TpmtRsaScheme>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.label.marshal(
            (&mut dst[offset..offset + tpm2::Tpm2bLabel::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalRSADecryptCmd {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let cipher_text = Tpm2bPublicKeyRsa::unmarshal(src)?;
            let in_scheme = <Option<tpm2::TpmtRsaScheme>>::unmarshal(src)?;
            let label = tpm2::Tpm2bLabel::unmarshal(src)?;
            Ok(Self {
                cipher_text,
                in_scheme,
                label,
            })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct LocalRSADecryptHandles {
    pub key_handle: Handle,
}
impl tpm2::Marshal for LocalRSADecryptHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalRSADecryptHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let key_handle = Handle::unmarshal(src)?;
            Ok(Self { key_handle })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalRSADecryptRsp {
    pub message: Tpm2bPublicKeyRsa<'static>,
}
impl tpm2::Marshal for LocalRSADecryptRsp {
    const MAX_SIZE: usize = Tpm2bPublicKeyRsa::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.message.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalRSADecryptRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let message = Tpm2bPublicKeyRsa::unmarshal(src)?;
            Ok(Self { message })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl tpm2::commands::Command for LocalRSADecryptCmd {
    const CMD_CODE: tpm2::TpmCc = tpm2::TpmCc::RSADecrypt;
    type Handles = LocalRSADecryptHandles;
    type Response<'a> = LocalRSADecryptRsp;
    type RespHandles = ();
}

fn rsa_decrypt_public(bits: u16) -> TpmtPublic<'static> {
    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(bits),
        exponent: 0,
    };

    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    }
}

#[test]
fn test_create_primary_rsa_1024() {
    use rsa::traits::PublicKeyParts as _;
    let mut sim = create_simulator!();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(1024));
    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]).unwrap();
    let out_public_struct = rsp.out_public.0;
    if let PublicParmsAndId::Rsa(parms, unique) = &out_public_struct.parms_and_id {
        assert_eq!(parms.key_bits.0, 1024);
        assert_eq!(unique.get_buffer().len(), 128); // 1024 bits = 128 bytes

        // Perform RSA encryption using public key
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(unique.get_buffer()),
            rsa::BigUint::from(65537u32),
        )
        .unwrap();
        let msg = rsa::BigUint::from_bytes_be(b"hello 1024!");
        let e = rsa::BigUint::from(65537u32);
        let c = msg.modpow(&e, pub_key.n());
        let ciphertext_bytes = c.to_bytes_be();
        let mut ciphertext = vec![0u8; unique.get_buffer().len()];
        let start = ciphertext.len() - ciphertext_bytes.len();
        ciphertext[start..].copy_from_slice(&ciphertext_bytes);

        // Decrypt using simulator
        let decrypt_cmd = LocalRSADecryptCmd {
            cipher_text: Tpm2bPublicKeyRsa::from_bytes(crate::test_utils::leak_bytes(&ciphertext))
                .unwrap(),
            in_scheme: None,
            label: tpm2::Tpm2bLabel::default(),
        };
        let decrypt_handles = LocalRSADecryptHandles {
            key_handle: rsp_handles.object_handle,
        };
        let (decrypt_rsp, _) = sim
            .execute_with_handles(decrypt_cmd, decrypt_handles)
            .unwrap();

        let returned_bytes = decrypt_rsp.message.get_buffer();
        assert_eq!(&returned_bytes[returned_bytes.len() - 11..], b"hello 1024!");
    } else {
        panic!("expected RSA key");
    }
    flush_context(&mut sim, rsp_handles.object_handle).unwrap();
}

#[test]
fn test_create_primary_rsa_2048() {
    use rsa::traits::PublicKeyParts as _;
    let mut sim = create_simulator!();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(2048));
    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]).unwrap();
    let out_public_struct = rsp.out_public.0;
    if let PublicParmsAndId::Rsa(parms, unique) = &out_public_struct.parms_and_id {
        assert_eq!(parms.key_bits.0, 2048);
        assert_eq!(unique.get_buffer().len(), 256); // 2048 bits = 256 bytes

        // Perform RSA encryption using public key
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(unique.get_buffer()),
            rsa::BigUint::from(65537u32),
        )
        .unwrap();
        let msg = rsa::BigUint::from_bytes_be(b"hello 2048!");
        let e = rsa::BigUint::from(65537u32);
        let c = msg.modpow(&e, pub_key.n());
        let ciphertext_bytes = c.to_bytes_be();
        let mut ciphertext = vec![0u8; unique.get_buffer().len()];
        let start = ciphertext.len() - ciphertext_bytes.len();
        ciphertext[start..].copy_from_slice(&ciphertext_bytes);

        // Decrypt using simulator
        let decrypt_cmd = LocalRSADecryptCmd {
            cipher_text: Tpm2bPublicKeyRsa::from_bytes(crate::test_utils::leak_bytes(&ciphertext))
                .unwrap(),
            in_scheme: None,
            label: tpm2::Tpm2bLabel::default(),
        };
        let decrypt_handles = LocalRSADecryptHandles {
            key_handle: rsp_handles.object_handle,
        };
        let (decrypt_rsp, _) = sim
            .execute_with_handles(decrypt_cmd, decrypt_handles)
            .unwrap();

        let returned_bytes = decrypt_rsp.message.get_buffer();
        assert_eq!(&returned_bytes[returned_bytes.len() - 11..], b"hello 2048!");
    } else {
        panic!("expected RSA key");
    }
    flush_context(&mut sim, rsp_handles.object_handle).unwrap();
}

#[test]
fn test_create_primary_rsa_3072() {
    let mut sim = create_simulator!();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(3072));
    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_err(),
        "Expected failure for 3072-bit key size due to small internal buffers"
    );
}

#[test]
fn test_create_primary_rsa_4096() {
    let mut sim = create_simulator!();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(4096));
    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_err(),
        "Expected failure for 4096-bit key size due to small internal buffers"
    );
}

#[test]
fn test_tpma_reserved_bits_in_commands() {
    let mut sim = create_simulator!();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    // 1. Test TpmaObject reserved bits in CreatePrimary (parameter 2)
    for reserved_bit in [1u32 << 0, 1u32 << 12, 1u32 << 20] {
        let mut pub_template = default_ecc_public();
        pub_template.object_attributes =
            TpmaObject(pub_template.object_attributes.0 | reserved_bit);
        let in_public = tpm2::Tpm2b(pub_template);
        let cmd = CreatePrimary {
            in_sensitive,
            in_public,
            ..Default::default()
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, handles.clone(), 0, &[])
            .expect_err("CreatePrimary with reserved TpmaObject bits must fail");
        assert_eq!(
            err,
            TpmRc::RESERVED_BITS.with(Position::parameter(2)).get(),
            "TpmaObject reserved bit {reserved_bit:#x} must return TPM_RC_RESERVED_BITS + P2"
        );
    }

    // 2. Test TpmaNv reserved bits in NV_DefineSpace (parameter 2)
    for reserved_bit in [1u32 << 8, 1u32 << 20] {
        let nv_public = tpm2::TpmsNvPublic {
            nv_index: Handle(0x01500001),
            name_alg: TpmiAlgHash::Sha256,
            attributes: tpm2::TpmaNv(
                (tpm2::TpmaNv::OWNERWRITE | tpm2::TpmaNv::OWNERREAD).0 | reserved_bit,
            ),
            auth_policy: Tpm2bDigest::default(),
            data_size: 32,
        };
        let cmd = tpm2::commands::NVDefineSpace {
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public),
        };
        let nv_handles = tpm2::commands::NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        let err = execute_with_password_sessions(&mut sim, &cmd, nv_handles, 1, &[])
            .expect_err("NVDefineSpace with reserved TpmaNv bits must fail");
        assert_eq!(
            err,
            TpmRc::RESERVED_BITS.with(Position::parameter(2)).get(),
            "TpmaNv reserved bit {reserved_bit:#x} must return TPM_RC_RESERVED_BITS + P2"
        );
    }

    // 3. Test TpmaSession reserved bits in command auth session area (session 1)
    let in_public = tpm2::Tpm2b(default_ecc_public());
    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let mut cmd_buf = [0u8; 2048];
    let mut cmd_header = CmdHeader {
        tag: tpm2::TpmiStCommandTag::Sessions,
        size: 0,
        code: tpm2::TpmCc::CreatePrimary,
    };
    let mut written = marshal_to_slice(&cmd_header, &mut cmd_buf);
    written += marshal_to_slice(&handles, &mut cmd_buf[written..]);

    let auth_cmd = tpm2::TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(0x08), // reserved bit 3 set
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buf = [0u8; 256];
    let auth_len = marshal_to_slice(&auth_cmd, &mut auth_buf);
    written += marshal_to_slice(&(auth_len as u32), &mut cmd_buf[written..]);
    cmd_buf[written..written + auth_len].copy_from_slice(&auth_buf[..auth_len]);
    written += auth_len;
    written += marshal_to_slice(&cmd, &mut cmd_buf[written..]);

    cmd_header.size = written as u32;
    marshal_to_slice(&cmd_header, &mut cmd_buf);

    let mut resp_buf = [0u8; 1024];
    sim.transact(&cmd_buf[..written], &mut resp_buf).unwrap();
    let mut resp_slice = &resp_buf[..];
    let resp_hdr = <RespHeader as tpm2::Unmarshal>::unmarshal(&mut resp_slice).unwrap();
    assert_eq!(
        resp_hdr.rc,
        TpmRc::RESERVED_BITS.with(Position::session(1)).get()
    );
}
