#![forbid(unsafe_code)]

use crate::test_utils::{execute_with_password_sessions_status, flush_context};
use sha2::{Digest as _, Sha256};
use tpm2::commands::{
    Command, LoadExternal, Sign, SignHandles, VerifySignature, VerifySignatureHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmEccCurve};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bLabel, Tpm2bMaxBuffer,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits,
    TpmsEccParms, TpmsEccPoint, TpmsRsaParms, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme,
    TpmtSensitive, TpmtSigScheme, TpmtSignature, TpmtSymDefObject, TpmtTkHashcheck,
    TpmuSensitiveComposite,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// NIST P-256 ECC Coordinates and Private Scalar (same as in load_external_tests.rs)
pub const ECC_X: &[u8] = &[
    0x35, 0x61, 0x24, 0x4d, 0x85, 0x34, 0x89, 0x75, 0x4c, 0xf0, 0x71, 0x0d, 0x87, 0x5a, 0x7b, 0xa4,
    0xb2, 0xac, 0xa9, 0xcc, 0x38, 0xa5, 0xd0, 0x29, 0x85, 0xd4, 0xce, 0xb8, 0x3b, 0xcb, 0xd0, 0xa2,
];
pub const ECC_Y: &[u8] = &[
    0xf8, 0xf0, 0xb6, 0x85, 0x0f, 0x09, 0x25, 0x25, 0x4f, 0xf6, 0x3a, 0x19, 0xa0, 0x11, 0x25, 0xa8,
    0x89, 0x94, 0xfc, 0x86, 0x60, 0x60, 0x35, 0x4d, 0x93, 0x05, 0xa7, 0x11, 0x68, 0x6d, 0x71, 0x77,
];
pub const ECC_D: &[u8] = &[
    0xcb, 0x53, 0x36, 0x6e, 0xee, 0x57, 0xf7, 0xed, 0x84, 0x8e, 0xc5, 0x88, 0xa2, 0x61, 0xbd, 0xfb,
    0xae, 0x21, 0x65, 0x46, 0x6e, 0x43, 0x45, 0xc5, 0xb5, 0x80, 0xcf, 0x95, 0xd4, 0x84, 0xfa, 0x5b,
];

pub const RSA_N: &[u8] = &[
    0x9e, 0x67, 0x7c, 0x31, 0xb1, 0xf9, 0x15, 0x8a, 0x41, 0x4d, 0x16, 0xf0, 0x73, 0xbe, 0x59, 0x66,
    0xc0, 0xe3, 0x8d, 0xc3, 0x64, 0x4b, 0x01, 0x3c, 0xce, 0x5c, 0x13, 0x10, 0x41, 0x9f, 0xbc, 0x43,
    0x2d, 0xfa, 0xcb, 0xfc, 0xa4, 0xd8, 0x41, 0x05, 0xbc, 0xcb, 0xe5, 0xc8, 0xd9, 0x13, 0x21, 0x6c,
    0xb0, 0x13, 0xea, 0x10, 0x3a, 0x3b, 0x73, 0xe0, 0x9e, 0x59, 0x11, 0x0f, 0x5c, 0x1f, 0x54, 0x5c,
    0x39, 0x42, 0x1d, 0x45, 0xb4, 0x67, 0x2c, 0x19, 0xf7, 0x6c, 0xe6, 0x13, 0xdd, 0xb7, 0x55, 0x5b,
    0x00, 0xa6, 0xaa, 0x2f, 0x06, 0x2a, 0xa9, 0x23, 0x7f, 0xc0, 0xb8, 0xdd, 0x32, 0xb5, 0x00, 0xc1,
    0xe7, 0x51, 0xe1, 0x71, 0xc1, 0xa3, 0xb3, 0x3a, 0x44, 0x45, 0x6c, 0x43, 0xbb, 0xc1, 0x23, 0x6f,
    0x65, 0x15, 0x6e, 0x25, 0xdd, 0x51, 0x8b, 0x49, 0x04, 0x44, 0xd1, 0x55, 0xd3, 0x88, 0x5f, 0x6a,
    0xd3, 0xc1, 0x58, 0x4b, 0xca, 0xe9, 0xbe, 0x6d, 0x30, 0x46, 0xdd, 0x3c, 0x2b, 0xbb, 0xd7, 0xbd,
    0x94, 0x10, 0x5e, 0x32, 0x6e, 0xcd, 0x24, 0x96, 0x17, 0x7a, 0x88, 0xd7, 0xee, 0x60, 0x58, 0x95,
    0x6a, 0x18, 0x7f, 0x40, 0x53, 0x24, 0xc0, 0x0e, 0xa9, 0x08, 0x9c, 0x03, 0x27, 0xce, 0x0b, 0xcb,
    0xc5, 0x2c, 0xf2, 0xb0, 0xe7, 0xac, 0xe0, 0xfa, 0x84, 0xc4, 0x77, 0x2f, 0x83, 0x3d, 0xe5, 0x7c,
    0x67, 0x94, 0x93, 0x3e, 0x52, 0x6e, 0x21, 0xf3, 0x30, 0xb1, 0x5e, 0xca, 0x39, 0xf5, 0x0b, 0x28,
    0xb4, 0x87, 0x76, 0x77, 0xc3, 0xaf, 0x4f, 0x9c, 0x7f, 0x0c, 0x58, 0x9d, 0x80, 0xf2, 0xf4, 0x93,
    0x6e, 0x03, 0x1e, 0x1d, 0x15, 0x6c, 0xb7, 0xfb, 0xd6, 0x43, 0xe3, 0xd2, 0x58, 0x5a, 0x2e, 0x2d,
    0xc2, 0xb3, 0x69, 0xff, 0x93, 0x35, 0x53, 0x71, 0x51, 0x64, 0x76, 0x41, 0x85, 0x3d, 0x3e, 0x31,
];

// Local Command Structures

#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalHmacCmd {
    pub in_buffer: Tpm2bMaxBuffer<'static>,
    pub hash_alg: Option<TpmiAlgHash>,
}
impl tpm2::Marshal for LocalHmacCmd {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + 2;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .in_buffer
            .marshal((&mut dst[0..Tpm2bMaxBuffer::MAX_SIZE]).try_into().unwrap());
        offset += match self.hash_alg {
            Some(a) => a.marshal((&mut dst[offset..offset + 2]).try_into().unwrap()),
            None => {
                (tpm2::Alg::NULL.id()).marshal((&mut dst[offset..offset + 2]).try_into().unwrap())
            }
        };
        offset
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalHmacCmd {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let in_buffer = Tpm2bMaxBuffer::unmarshal(src)?;
            let hash_alg = <Option<TpmiAlgHash>>::unmarshal(src)?;
            Ok(Self {
                in_buffer,
                hash_alg,
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
pub struct LocalMacHandles {
    pub handle: Handle,
}
impl tpm2::Marshal for LocalMacHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalMacHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let handle = Handle::unmarshal(src)?;
            Ok(Self { handle })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalMacRsp {
    pub out_hmac: Tpm2bDigest<'static>,
}
impl tpm2::Marshal for LocalMacRsp {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_hmac.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalMacRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let out_hmac = Tpm2bDigest::unmarshal(src)?;
            Ok(Self { out_hmac })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl Command for LocalHmacCmd {
    const CMD_CODE: TpmCc = TpmCc::MAC;
    type Handles = LocalMacHandles;
    type Response<'a> = LocalMacRsp;
    type RespHandles = ();
}

#[derive(Clone, PartialEq, Debug)]
pub struct LocalRSADecryptCmd {
    pub cipher_text: Tpm2bPublicKeyRsa<'static>,
    pub in_scheme: Option<TpmtRsaScheme>,
    pub label: Tpm2bLabel<'static>,
}

impl tpm2::Marshal for LocalRSADecryptCmd {
    const MAX_SIZE: usize = Tpm2bPublicKeyRsa::MAX_SIZE
        + <Option<tpm2::TpmtRsaScheme>>::MAX_SIZE
        + Tpm2bLabel::MAX_SIZE;
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
            (&mut dst[offset..offset + Tpm2bLabel::MAX_SIZE])
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
            let label = Tpm2bLabel::unmarshal(src)?;
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

impl Command for LocalRSADecryptCmd {
    const CMD_CODE: TpmCc = TpmCc::RSADecrypt;
    type Handles = LocalRSADecryptHandles;
    type Response<'a> = LocalRSADecryptRsp;
    type RespHandles = ();
}

// Helpers for public areas

fn make_ecc_public_area(x: &[u8], y: &[u8], attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(x)).unwrap(),
                y: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(y)).unwrap(),
            },
        ),
    }
}

fn make_rsa_public_area(n: &[u8], name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(crate::test_utils::leak_bytes(n)).unwrap(),
        ),
    }
}

fn make_keyed_hash_public_area(unique: &[u8], attrs: TpmaObject) -> TpmtPublic<'static> {
    make_keyed_hash_public_area_with_sensitive(unique, attrs, b"secrets")
}

fn make_keyed_hash_public_area_with_sensitive(
    unique: &[u8],
    attrs: TpmaObject,
    sensitive_bytes: &[u8],
) -> TpmtPublic<'static> {
    let mut actual_unique = unique.to_vec();
    if unique == [0x01; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x02; 32]);
        hasher.update(sensitive_bytes);
        actual_unique = hasher.finalize().to_vec();
    }
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            None,
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&actual_unique)).unwrap(),
        ),
    }
}

fn get_bound_unique(sensitive_bytes: &[u8]) -> Tpm2bDigest<'_> {
    let mut hasher = Sha256::new();
    hasher.update([0x02; 32]);
    hasher.update(sensitive_bytes);
    Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&hasher.finalize())).unwrap()
}

// ==================== Adversarial Cryptographic Ops Tests ====================

/// 1. Test MAC with an invalid or non-existent handle.
///
/// Expected: TPM_RC_HANDLE (Error position Pos1 / Parameter-specific).
#[test]
fn adv_mac_invalid_handle() {
    let mut sim = create_simulator!();
    let cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let handles = LocalMacHandles {
        handle: Handle(0x8000000E), // Arbitrary unused handle
    };
    let res = sim.execute_with_handles(cmd, handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::REFERENCE_H0.get());
}

/// 2. Test MAC with unsupported/non-SHA256 hash algorithm (e.g. SHA384).
///
/// Expected: TPM_RC_HASH.
#[test]
fn adv_mac_unsupported_hash_alg() {
    let mut sim = create_simulator!();

    // Load a valid keyed hash key
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    // Send MAC command with SM3256 hash alg (unsupported)
    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sm3_256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::HASH.with(Position::parameter(2)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 3. Test MAC with a key that does not have the 'sign' attribute set.
///
/// Expected: TPM_RC_KEY.
#[test]
fn adv_mac_missing_sign_attribute() {
    let mut sim = create_simulator!();

    // Load a keyed hash key with NO attributes (or DECRYPT only)
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::DECRYPT, // NOT sign/encrypt
    ));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_err(),
        "MAC should fail when the key does not have the sign attribute"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::KEY.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 4. Test MAC with a restricted key.
///
/// Expected: TPM_RC_ATTRIBUTES.
#[test]
fn adv_mac_restricted_key() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(res.is_err(), "MAC should fail for a restricted key");
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::ATTRIBUTES.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 5. Test MAC with an invalid key type (e.g. RSA key).
///
/// Expected: TPM_RC_TYPE.
#[test]
fn adv_mac_invalid_key_type() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    // Try to perform MAC using the RSA key
    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_err(),
        "MAC should fail for non-keyedhash/non-symcipher key types"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::TYPE.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 6. Test MAC with a public-only key (no private key data loaded).
///
/// Expected: TPM_RC_KEY or TPM_RC_AUTH_UNAVAILABLE.
#[test]
fn adv_mac_public_only_key() {
    let mut sim = create_simulator!();

    // Load a public-only keyed hash key (in_private is default/empty)
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None, // Empty sensitive area
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_err(),
        "MAC should fail when sensitive area is missing"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::KEY.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 7. Test MAC with an empty input buffer (0 bytes).
///
/// Expected: TPM_RC_SUCCESS.
#[test]
fn adv_mac_empty_buffer() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::default(), // 0-length buffer
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_ok(),
        "MAC calculation on empty buffer should succeed"
    );

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 8. Test MAC with maximum-sized input buffer (1024 bytes).
///
/// Expected: TPM_RC_SUCCESS.
#[test]
fn adv_mac_max_buffer() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let max_data = [0x55u8; 1024];
    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(crate::test_utils::leak_bytes(&max_data)).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_ok(),
        "MAC calculation on maximum buffer size should succeed"
    );

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 9. Test RSADecrypt with non-RSA key type (e.g. KeyedHash key).
///
/// Expected: TPM_RC_KEY.
#[test]
fn adv_rsa_decrypt_invalid_key_type() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::DECRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let decrypt_cmd = LocalRSADecryptCmd {
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let decrypt_handles = LocalRSADecryptHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(decrypt_cmd, decrypt_handles);
    assert!(
        res.is_err(),
        "RSADecrypt should fail when key type is not RSA"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::KEY.get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 10. Test RSADecrypt with an invalid handle.
///
/// Expected: TPM_RC_HANDLE.
#[test]
fn adv_rsa_decrypt_invalid_handle() {
    let mut sim = create_simulator!();
    let decrypt_cmd = LocalRSADecryptCmd {
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let decrypt_handles = LocalRSADecryptHandles {
        key_handle: Handle(0x8000000E),
    };
    let res = sim.execute_with_handles(decrypt_cmd, decrypt_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::REFERENCE_H0.get());
}

/// 11. Test Sign with an invalid handle.
///
/// Expected: TPM_RC_HANDLE.
#[test]
fn adv_sign_invalid_handle() {
    let mut sim = create_simulator!();
    let sign_cmd = Sign {
        digest: Tpm2bDigest::default(),
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let sign_handles = SignHandles {
        key_handle: Handle(0x8000000E),
    };
    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, sign_handles, 0, &[]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));
}

/// 12. Test Sign with unsupported scheme (non-Null).
///
/// Expected: TPM_RC_SCHEME.
#[test]
fn adv_sign_unsupported_scheme() {
    let mut sim = create_simulator!();

    // Load ECC key
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Sm2(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let sign_handles = SignHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, sign_handles, 0, &[]);
    assert_eq!(res.err(), Some(TpmRc::SCHEME.get()));

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 13. Test VerifySignature with unsupported scheme (non-Null signature).
///
/// Expected: TPM_RC_SCHEME.
#[test]
fn adv_verify_signature_unsupported_scheme() {
    let mut sim = create_simulator!();

    // Load ECC key
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let verify_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        signature: TpmtSignature::Sm2(tpm2::TpmsSignatureEcc {
            hash: TpmiAlgHash::Sha256,
            signature_r: Tpm2bEccParameter::default(),
            signature_s: Tpm2bEccParameter::default(),
        }),
    };
    let verify_handles = VerifySignatureHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(verify_cmd, verify_handles);
    assert!(
        res.is_err(),
        "VerifySignature should fail for non-Null signature schemes"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::SCHEME.get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test RSADecrypt fails on a restricted key handle returning TPM_RC_ATTRIBUTES.
#[test]
fn adv_rsa_decrypt_restricted_key() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let decrypt_cmd = LocalRSADecryptCmd {
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let decrypt_handles = LocalRSADecryptHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(decrypt_cmd, decrypt_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::ATTRIBUTES.get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test RSADecrypt fails with TPM_RC_KEY if key lacks DECRYPT attribute.
#[test]
fn adv_rsa_decrypt_signing_only() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let decrypt_cmd = LocalRSADecryptCmd {
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let decrypt_handles = LocalRSADecryptHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(decrypt_cmd, decrypt_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::KEY.get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test Sign fails with TPM_RC_KEY if key lacks SIGN_ENCRYPT attribute.
#[test]
fn adv_sign_storage_only() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::DECRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let sign_handles = SignHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, sign_handles, 0, &[]);
    assert_eq!(res.err(), Some(TpmRc::KEY.get()));

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test VerifySignature fails with TPM_RC_ATTRIBUTES if key lacks SIGN_ENCRYPT.
#[test]
fn adv_verify_signature_missing_sign_attribute() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::DECRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let verify_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        signature: TpmtSignature::Rsassa(tpm2::TpmsSignatureRsa {
            hash: TpmiAlgHash::Sha256,
            sig: tpm2::Tpm2bPublicKeyRsa::default(),
        }),
    };
    let verify_handles = VerifySignatureHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(verify_cmd, verify_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::ATTRIBUTES.get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test VerifySignature fails with TPM_RC_HANDLE if KeyedHash key is public-only.
#[test]
fn adv_verify_signature_keyed_hash_public_only() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None, // public-only
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let verify_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        signature: TpmtSignature::Rsassa(tpm2::TpmsSignatureRsa {
            hash: TpmiAlgHash::Sha256,
            sig: tpm2::Tpm2bPublicKeyRsa::default(),
        }),
    };
    let verify_handles = VerifySignatureHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(verify_cmd, verify_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::HANDLE.get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with ExclusiveOr scheme (neither HMAC nor Null).
///
/// Expected: TPM_RC_TYPE.
#[test]
fn adv_mac_xor_key_scheme() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::ExclusiveOr(tpm2::TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sha256,
                kdf: Some(tpm2::TpmiAlgKdf::Kdf1Sp800_108),
            })),
            get_bound_unique(b"secrets"),
        ),
    });

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::TYPE.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with mismatched command hash algorithm (command SHA384 vs key Hmac(SHA256)).
///
/// Expected: TPM_RC_VALUE.
#[test]
fn adv_mac_mismatched_command() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            get_bound_unique(b"secrets"),
        ),
    });

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha384), // Mismatched command hash alg
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::VALUE.with(Position::parameter(2)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with Null key scheme and Null command hash algorithm.
///
/// Expected: TPM_RC_VALUE.
#[test]
fn adv_mac_null_scheme_null_command() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: None, // Null command hash alg
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::VALUE.with(Position::parameter(2)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with Null key scheme and unsupported command hash algorithm.
///
/// Expected: TPM_RC_HASH.
#[test]
fn adv_mac_null_scheme_unsupported_hash() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sm3_256), // SM3256 is unsupported by MAC command handler in code
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::HASH.with(Position::parameter(2)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with Null key scheme and multiple different supported command hash algorithms.
///
/// Expected: TPM_RC_SUCCESS for all and matching local HMAC results.
#[test]
fn adv_mac_null_scheme_success_multiple_hashes() {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384};

    let mut sim = create_simulator!();
    let key_bytes = b"my hmac key material";

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(key_bytes).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area_with_sensitive(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
        key_bytes,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let data = b"some message to hmac";

    // Test with SHA256
    let hmac_cmd_256 = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res_256 = sim
        .execute_with_handles(hmac_cmd_256, hmac_handles)
        .unwrap();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac_256 = HmacSha256::new_from_slice(key_bytes).unwrap();
    mac_256.update(data);
    let expected_256 = mac_256.finalize().into_bytes();
    assert_eq!(expected_256.as_slice(), res_256.0.out_hmac.as_ref());

    // Test with SHA384
    let hmac_cmd_384 = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha384),
    };
    let res_384 = sim
        .execute_with_handles(hmac_cmd_384, hmac_handles)
        .unwrap();

    type HmacSha384 = Hmac<Sha384>;
    let mut mac_384 = HmacSha384::new_from_slice(key_bytes).unwrap();
    mac_384.update(data);
    let expected_384 = mac_384.finalize().into_bytes();
    assert_eq!(expected_384.as_slice(), res_384.0.out_hmac.as_ref());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC buffer creation with too large input.
///
/// Expected: Tpm2bMaxBuffer::from_bytes returns error.
#[test]
fn adv_mac_buffer_too_large() {
    let large_data = [0xaa; 1025];
    let res = Tpm2bMaxBuffer::from_bytes(&large_data);
    assert!(res.is_err());
}

/// Test MAC with an invalid key type (ECC key).
///
/// Expected: TPM_RC_TYPE.
#[test]
fn adv_mac_invalid_key_type_ecc() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_err(),
        "MAC should fail for non-keyedhash/non-symcipher key types (ECC)"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::TYPE.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with a symmetric cipher key (invalid key type).
///
/// Expected: TPM_RC_TYPE.
#[test]
fn adv_mac_invalid_key_type_sym() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        ),
    });
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_err(),
        "MAC should fail for non-keyedhash key types (symmetric cipher)"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::TYPE.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with key default scheme HMAC-SHA256 and command hash_alg Null.
/// It should use SHA256 and succeed.
///
/// Expected: TPM_RC_SUCCESS.
#[test]
fn adv_mac_key_default_scheme_match_cmd_null() {
    let mut sim = create_simulator!();

    let scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(scheme, get_bound_unique(b"secrets")),
    });

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: None, // Null command hash
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_ok(),
        "MAC should succeed using key's default scheme when command hash is Null: {:?}",
        res.err()
    );

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with a KeyedHash key using XOR scheme.
///
/// Expected: TPM_RC_TYPE (since XOR scheme is not HMAC or Null).
#[test]
fn adv_mac_key_xor_scheme() {
    let mut sim = create_simulator!();

    let scheme = TpmtKeyedHashScheme::ExclusiveOr(tpm2::TpmsSchemeXor {
        hash_alg: TpmiAlgHash::Sha256,
        kdf: Some(tpm2::TpmiAlgKdf::Kdf2),
    });
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(Some(scheme), get_bound_unique(b"secrets")),
    });

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let res = sim.execute_with_handles(hmac_cmd, hmac_handles);
    assert!(
        res.is_err(),
        "MAC should fail for KeyedHash keys with XOR scheme"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::TYPE.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn adv_verify_signature_and_policy_signed_reject_tpm_alg_null() {
    use crate::test_utils::{RespHeader, start_auth_session};
    use tpm2::{TpmSe, Unmarshal};

    let mut sim = create_simulator!();

    // Load a public signing key for testing VerifySignature and PolicySigned
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None,
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();
    let key_handle = resp_handles.object_handle;

    // 1. Raw VerifySignature with TPM_ALG_NULL (0x0010) signature parameter -> TPM_RC_SCHEME + P + 2
    let mut verify_cmd_bytes = [0u8; 64];
    let mut offset = 0;
    verify_cmd_bytes[offset..offset + 2].copy_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
    offset += 2;
    let size_pos = offset;
    offset += 4;
    verify_cmd_bytes[offset..offset + 4]
        .copy_from_slice(&u32::from(TpmCc::VerifySignature).to_be_bytes());
    offset += 4;
    verify_cmd_bytes[offset..offset + 4].copy_from_slice(&key_handle.0.to_be_bytes()); // keyHandle
    offset += 4;
    verify_cmd_bytes[offset..offset + 2].copy_from_slice(&4u16.to_be_bytes()); // digest size = 4
    offset += 2;
    verify_cmd_bytes[offset..offset + 4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // digest
    offset += 4;
    verify_cmd_bytes[offset..offset + 2].copy_from_slice(&0x0010u16.to_be_bytes()); // signature = TPM_ALG_NULL
    offset += 2;
    verify_cmd_bytes[size_pos..size_pos + 4].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut resp_buf = [0u8; 256];
    sim.transact(&verify_cmd_bytes[..offset], &mut resp_buf)
        .unwrap();
    let mut resp_slice = &resp_buf[..];
    let resp_header = RespHeader::unmarshal(&mut resp_slice).unwrap();
    assert_eq!(
        resp_header.rc,
        TpmRc::SCHEME.with(Position::parameter(2)).get(),
        "VerifySignature with TPM_ALG_NULL signature must return TPM_RC_SCHEME + TPM_RC_P + TPM_RC_2"
    );

    // 2. Raw PolicySigned with TPM_ALG_NULL (0x0010) auth parameter -> TPM_RC_SCHEME + P + 5
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut ps_cmd_bytes = [0u8; 64];
    let mut offset = 0;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
    offset += 2;
    let size_pos = offset;
    offset += 4;
    ps_cmd_bytes[offset..offset + 4].copy_from_slice(&u32::from(TpmCc::PolicySigned).to_be_bytes());
    offset += 4;
    ps_cmd_bytes[offset..offset + 4].copy_from_slice(&key_handle.0.to_be_bytes()); // authObject
    offset += 4;
    ps_cmd_bytes[offset..offset + 4].copy_from_slice(&trial_session.session_handle.0.to_be_bytes()); // policySession
    offset += 4;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // nonceTPM (empty)
    offset += 2;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // cpHashA (empty)
    offset += 2;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // policyRef (empty)
    offset += 2;
    ps_cmd_bytes[offset..offset + 4].copy_from_slice(&0i32.to_be_bytes()); // expiration = 0
    offset += 4;
    ps_cmd_bytes[offset..offset + 2].copy_from_slice(&0x0010u16.to_be_bytes()); // auth = TPM_ALG_NULL
    offset += 2;
    ps_cmd_bytes[size_pos..size_pos + 4].copy_from_slice(&(offset as u32).to_be_bytes());

    sim.transact(&ps_cmd_bytes[..offset], &mut resp_buf)
        .unwrap();
    let mut resp_slice = &resp_buf[..];
    let resp_header = RespHeader::unmarshal(&mut resp_slice).unwrap();
    assert_eq!(
        resp_header.rc,
        TpmRc::SCHEME.with(Position::parameter(5)).get(),
        "PolicySigned with TPM_ALG_NULL auth must return TPM_RC_SCHEME + TPM_RC_P + TPM_RC_5"
    );

    flush_context(&mut sim, trial_session.session_handle).unwrap();
    flush_context(&mut sim, key_handle).unwrap();
}
