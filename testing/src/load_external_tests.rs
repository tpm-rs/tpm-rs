#![forbid(unsafe_code)]
use tpm2::Alg;

use crate::test_utils::{
    execute_sign, execute_with_password_sessions_status, flush_context, marshal_to_slice,
};
use sha2::{Digest as _, Sha256};
use tpm2::commands::{
    Command, LoadExternal, Sign, SignHandles, VerifySignature, VerifySignatureHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmEccCurve};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bLabel, Tpm2bMaxBuffer,
    Tpm2bName, Tpm2bPrivateKeyRsa, Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey,
    TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmsEccParms, TpmsEccPoint,
    TpmsRsaParms, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme, TpmtSensitive, TpmtSymDefObject,
    TpmtTkHashcheck, TpmuSensitiveComposite,
};
use tpm2_platform_linux::{LinuxRng, PlatformCryptoProvider};
use tpm2_simulator::{Simulator, create_simulator};

// 2048-bit RSA Modulus N, Prime P, Prime Q, Private Exponent D
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
pub const RSA_P: &[u8] = &[
    0xd9, 0xb4, 0x4e, 0xda, 0x74, 0x15, 0xd2, 0xb4, 0x06, 0x7c, 0xff, 0x45, 0xb7, 0xb6, 0xcf, 0xd6,
    0xb2, 0x20, 0xdf, 0x6f, 0xe6, 0x79, 0x8f, 0xc7, 0x42, 0x7e, 0xa1, 0x33, 0xdf, 0x06, 0x2b, 0x92,
    0xc0, 0xb7, 0xa5, 0xcf, 0x03, 0x0b, 0x7b, 0xd5, 0x22, 0x69, 0x7c, 0x7f, 0x4d, 0x8d, 0xe6, 0xcb,
    0x37, 0x1b, 0xe1, 0x39, 0x59, 0x50, 0x1e, 0x6b, 0xe3, 0x81, 0x3b, 0xbe, 0x01, 0x04, 0x45, 0xa3,
    0xab, 0x9a, 0xd5, 0xa4, 0x0a, 0x67, 0xc4, 0xcb, 0xc4, 0xa6, 0x1d, 0x6f, 0xf1, 0x81, 0x15, 0xcc,
    0x76, 0xa7, 0x92, 0x55, 0x0d, 0x5a, 0xa5, 0xf5, 0x46, 0x9c, 0x20, 0x68, 0x77, 0xe6, 0x28, 0x51,
    0x4b, 0x0f, 0x8a, 0x74, 0xe0, 0xa5, 0x3c, 0x13, 0x43, 0x0b, 0x28, 0x4e, 0xe0, 0x15, 0x5e, 0xd6,
    0xce, 0x23, 0x45, 0xbe, 0xc8, 0x34, 0x9b, 0xc9, 0x01, 0x3a, 0x80, 0x27, 0xf4, 0xfe, 0x59, 0xfd,
];
pub const RSA_Q: &[u8] = &[
    0xba, 0x44, 0xc4, 0x62, 0xc1, 0x17, 0x8a, 0x2b, 0xf0, 0x11, 0xca, 0xba, 0x79, 0xcb, 0xcd, 0x38,
    0x35, 0x10, 0x73, 0xd0, 0xd4, 0xf4, 0x91, 0xc4, 0x63, 0xa4, 0x7d, 0xa5, 0xcb, 0xab, 0xe5, 0x95,
    0x30, 0x08, 0x47, 0x93, 0x95, 0xca, 0x36, 0x04, 0x3a, 0xf2, 0xb8, 0x8a, 0x78, 0x0a, 0x35, 0xde,
    0x0c, 0xc3, 0xdb, 0xeb, 0x42, 0x9f, 0xdb, 0xf0, 0x94, 0xd0, 0x72, 0x32, 0x91, 0x4f, 0xef, 0x7b,
    0xc3, 0x81, 0x5a, 0x80, 0x00, 0x6c, 0x60, 0x44, 0xbc, 0x36, 0x56, 0xb5, 0x74, 0x65, 0x33, 0x86,
    0x5d, 0x86, 0x6a, 0x45, 0x0b, 0x9b, 0xa5, 0x66, 0xe9, 0x1b, 0x69, 0x16, 0x70, 0xad, 0xd2, 0x87,
    0x2d, 0x5f, 0x2f, 0x10, 0x86, 0xf8, 0x52, 0xe4, 0x2b, 0xbd, 0x96, 0xc6, 0xd1, 0x1f, 0x0d, 0x87,
    0xb1, 0x91, 0x8f, 0x7a, 0xdf, 0x30, 0x5d, 0x2b, 0xa6, 0xe6, 0x4a, 0x76, 0xd9, 0x39, 0x01, 0x45,
];

// NIST P-256 ECC Coordinates and Private Scalar
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

// 3. RSADecryptCmd
#[derive(Clone, PartialEq, Debug, Default)]
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

// 4. Hmac
#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalHmacCmd {
    pub in_buffer: Tpm2bMaxBuffer<'static>,
    pub hash_alg: Option<TpmiAlgHash>,
}
impl tpm2::Marshal for LocalHmacCmd {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .in_buffer
            .marshal((&mut dst[0..Tpm2bMaxBuffer::MAX_SIZE]).try_into().unwrap());
        offset += self.hash_alg.marshal(
            (&mut dst[offset..offset + <Option<TpmiAlgHash>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
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

// 5. MACStart (MACStart)
#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalMacStartCmd {
    pub auth: Tpm2bAuth<'static>,
    pub hash_alg: Option<TpmiAlgHash>,
}
impl tpm2::Marshal for LocalMacStartCmd {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .auth
            .marshal((&mut dst[0..Tpm2bAuth::MAX_SIZE]).try_into().unwrap());
        offset += self.hash_alg.marshal(
            (&mut dst[offset..offset + <Option<TpmiAlgHash>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalMacStartCmd {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let auth = Tpm2bAuth::unmarshal(src)?;
            let hash_alg = <Option<TpmiAlgHash>>::unmarshal(src)?;
            Ok(Self { auth, hash_alg })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct LocalMacStartHandles {
    pub handle: Handle,
}
impl tpm2::Marshal for LocalMacStartHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalMacStartHandles {
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

#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct LocalMacStartRespHandles {
    pub sequence_handle: Handle,
}
impl tpm2::Marshal for LocalMacStartRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalMacStartRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let sequence_handle = Handle::unmarshal(src)?;
            Ok(Self { sequence_handle })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl Command for LocalMacStartCmd {
    const CMD_CODE: TpmCc = TpmCc::MACStart;
    type Handles = LocalMacStartHandles;
    type Response<'a> = ();
    type RespHandles = LocalMacStartRespHandles;
}

// Helper functions for public areas
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

fn make_rsa_public_area(
    n: &[u8],
    name_alg: Option<TpmiAlgHash>,
    attrs: TpmaObject,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg,
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
    let mut actual_unique = unique.to_vec();
    if unique == [0x01; 32] || unique == [0x02; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"obfuscation is my middle name!!!");
        hasher.update(b"secrets");
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

// ==================== TIER 1 tests ====================

// F1: Public-only Key Load (ECC)
#[test]
fn test_load_external_ecc_no_sensitive() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_ecc_owner() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_OWNER,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_ecc_platform() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_PLATFORM,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_ecc_endorsement() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_ENDORSEMENT,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_ecc_attributes() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// F2: Public-only Key Load (RSA)
#[test]
fn test_load_external_rsa_null() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_rsa_owner() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_OWNER,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_rsa_platform() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_PLATFORM,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_rsa_endorsement() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_ENDORSEMENT,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_rsa_sha384() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha384),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// F3: Public + Sensitive Key Load
#[test]
fn test_load_external_keyed_hash_sensitive() {
    let mut sim = create_simulator!();
    let seed_value = Tpm2bDigest::from_bytes(b"obfuscation is my middle name!!!").unwrap();
    let sensitive_data = Tpm2bSensitiveData::from_bytes(b"secrets").unwrap();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value,
        sensitive: TpmuSensitiveComposite::KeyedHash(sensitive_data),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [
        0xed, 0x4f, 0xe8, 0xe2, 0xbf, 0xf9, 0x76, 0x65, 0xe7, 0xbf, 0xbe, 0x27, 0xc2, 0x36, 0x5d,
        0x07, 0xa9, 0xbe, 0x91, 0xdd, 0x92, 0xd9, 0x97, 0xcd, 0x91, 0xcc, 0x70, 0x6b, 0x60, 0x74,
        0xeb, 0x08,
    ];
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &unique_bytes,
        TpmaObject::default(),
    ));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_ecc_sensitive() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_rsa_sensitive() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(RSA_P).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_sym_sensitive() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(&[0x01; 16]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let mut hasher = Sha256::new();
    hasher.update([]);
    hasher.update([0x01; 16]);
    let sym_unique = hasher.finalize().to_vec();

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::from_bytes(&sym_unique).unwrap(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_sensitive_invalid_hierarchy() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_OWNER,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

// F4: Name Computation & Validation
#[test]
fn test_load_external_name_ecc() {
    let mut sim = create_simulator!();
    let pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let (resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();

    // Compute expected name
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_name_keyed_hash() {
    let mut sim = create_simulator!();
    let unique_bytes = [0x01; 32];
    let pub_struct = make_keyed_hash_public_area(&unique_bytes, TpmaObject::default());
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let (resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();

    // Compute expected name
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_name_rsa() {
    let mut sim = create_simulator!();
    let pub_struct =
        make_rsa_public_area(RSA_N, Some(TpmiAlgHash::Sha256), TpmaObject::SIGN_ENCRYPT);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let (resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();

    // Compute expected name
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_name_alg_null() {
    let mut sim = create_simulator!();
    let pub_struct = make_rsa_public_area(RSA_N, None, TpmaObject::SIGN_ENCRYPT);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let (resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    assert_eq!(resp.name, Tpm2bName::default());
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_name_sensitive_match() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    let in_public = tpm2::Tpm2b(pub_struct);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let (resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();

    // Compute expected name
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// ==================== TIER 2 tests ====================

// ECC Public Key Validation
#[test]
fn test_load_external_ecc_invalid_curve() {
    let mut sim = create_simulator!();
    let mut pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    if let PublicParmsAndId::Ecc(ref mut parms, _) = pub_struct.parms_and_id {
        parms.curve_id = TpmEccCurve::BNP638;
    }
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

#[test]
fn test_load_external_ecc_point_not_on_curve() {
    let mut sim = create_simulator!();
    let mut bad_y = ECC_Y.to_vec();
    bad_y[0] ^= 0xff; // corrupt coordinate
    let in_public = tpm2::Tpm2b(make_ecc_public_area(
        ECC_X,
        &bad_y,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

// RSA Public Key Validation
#[test]
fn test_load_external_rsa_invalid_exponent() {
    let mut sim = create_simulator!();
    let mut pub_struct =
        make_rsa_public_area(RSA_N, Some(TpmiAlgHash::Sha256), TpmaObject::SIGN_ENCRYPT);
    if let PublicParmsAndId::Rsa(ref mut parms, _) = pub_struct.parms_and_id {
        parms.exponent = 3; // invalid exponent (unsupported by TPM)
    }
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

// Hierarchy Validation
#[test]
fn test_load_external_invalid_hierarchy_handle() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle(0x80000000), // completely invalid handle
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

// Public Area Size Validation
#[test]
fn test_load_external_invalid_public_size() {
    let mut sim = create_simulator!();
    assert!(
        Tpm2bPublic::from_bytes(&[0; 10]).is_err(),
        "Client unmarshaler should reject invalid Tpm2bPublic buffer"
    );

    struct BadLoadExternal<'a> {
        in_public_buf: &'a [u8],
        hierarchy: Handle,
    }
    impl tpm2::Marshal for BadLoadExternal<'_> {
        const MAX_SIZE: usize = 256;
        type MaxBuffer = [u8; 256];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off = 0u16.marshal((&mut dst[0..2]).try_into().unwrap()); // in_private = None (0 size)
            off += (self.in_public_buf.len() as u16)
                .marshal((&mut dst[off..off + 2]).try_into().unwrap());
            dst[off..off + self.in_public_buf.len()].copy_from_slice(self.in_public_buf);
            off += self.in_public_buf.len();
            off += self
                .hierarchy
                .marshal((&mut dst[off..off + 4]).try_into().unwrap());
            off
        }
    }
    impl tpm2::Command for BadLoadExternal<'_> {
        const CMD_CODE: tpm2::TpmCc = tpm2::TpmCc::LoadExternal;
        type Handles = ();
        type Response<'a> = ();
        type RespHandles = ();
    }

    let cmd = BadLoadExternal {
        in_public_buf: &[0; 10],
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

// Sensitive Area Bindings & Consistency
#[test]
fn test_load_external_key_size_mismatch() {
    let mut sim = create_simulator!();
    // ECC key requires 32-byte scalar D. We provide a 16-byte one.
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(&[0x01; 16]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

#[test]
fn test_load_external_type_mismatch() {
    let mut sim = create_simulator!();
    // Public is ECC, but Sensitive is Sym (symmetric)
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(&[0x01; 16]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

#[test]
fn test_load_external_weak_sym_key() {
    let mut sim = create_simulator!();
    // Symmetric key with empty key material
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(&[]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

#[test]
fn test_load_external_rsa_primes_size_mismatch() {
    let mut sim = create_simulator!();
    // Provide a random 128-byte prime P that doesn't correspond to modulus RSA_N
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(
            Tpm2bPrivateKeyRsa::from_bytes(&[0x01; 128]).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

#[test]
fn test_load_external_invalid_private_attributes() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    // Load with FIXED_TPM set. Since sensitive is loaded, this must be rejected.
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::FIXED_TPM));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
}

// ==================== TIER 3 tests ====================

#[test]
fn test_load_external_ecc_sha384_platform() {
    let mut sim = create_simulator!();
    let pub_struct = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha384),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(ECC_X).unwrap(),
                y: Tpm2bEccParameter::from_bytes(ECC_Y).unwrap(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_PLATFORM,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_rsa_alg_null_owner() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area(RSA_N, None, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    assert_eq!(resp.name, Tpm2bName::default());
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_ecc_alg_null_sensitive() {
    let mut sim = create_simulator!();
    let mut pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    pub_struct.name_alg = None;
    let in_public = tpm2::Tpm2b(pub_struct);

    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    assert_eq!(resp.name, Tpm2bName::default());
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_keyed_hash_auth_policy() {
    let mut sim = create_simulator!();
    let seed_value = Tpm2bDigest::from_bytes(b"obfuscation is my middle name!!!").unwrap();
    let sensitive_data = Tpm2bSensitiveData::from_bytes(b"secrets").unwrap();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value,
        sensitive: TpmuSensitiveComposite::KeyedHash(sensitive_data),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [0x02; 32];
    let mut pub_struct = make_keyed_hash_public_area(&unique_bytes, TpmaObject::default());
    pub_struct.auth_policy = Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap();
    let in_public = tpm2::Tpm2b(pub_struct);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// ==================== TIER 4 tests ====================

#[test]
fn test_load_external_verify_signature_ecc() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let sign_load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_, sign_handles) = sim.execute_with_handles(sign_load_cmd, ()).unwrap();

    let digest = Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap();
    let sign_cmd = Sign {
        digest,
        in_scheme: Some(tpm2::TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let (sign_rsp, _) = execute_sign(
        &mut sim,
        &sign_cmd,
        SignHandles {
            key_handle: sign_handles.object_handle,
        },
        1,
        &[],
        &mut resp_buffer,
    )
    .unwrap();
    flush_context(&mut sim, sign_handles.object_handle).unwrap();

    let load_cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_load_resp, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let verify_cmd = VerifySignature {
        digest,
        signature: sign_rsp.signature,
    };
    let verify_handles = VerifySignatureHandles {
        key_handle: resp_handles.object_handle,
    };
    let _verify_resp = sim
        .execute_with_handles(verify_cmd, verify_handles)
        .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_verify_signature_rsa() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(RSA_P).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let sign_load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_, sign_handles) = sim.execute_with_handles(sign_load_cmd, ()).unwrap();

    let digest = Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap();
    let sign_cmd = Sign {
        digest,
        in_scheme: Some(tpm2::TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let (sign_rsp, _) = execute_sign(
        &mut sim,
        &sign_cmd,
        SignHandles {
            key_handle: sign_handles.object_handle,
        },
        1,
        &[],
        &mut resp_buffer,
    )
    .unwrap();
    flush_context(&mut sim, sign_handles.object_handle).unwrap();

    let load_cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_load_resp, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let verify_cmd = VerifySignature {
        digest,
        signature: sign_rsp.signature,
    };
    let verify_handles = VerifySignatureHandles {
        key_handle: resp_handles.object_handle,
    };
    let _verify_resp = sim
        .execute_with_handles(verify_cmd, verify_handles)
        .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_sign_ecc() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_load_resp, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let sign_handles = SignHandles {
        key_handle: resp_handles.object_handle,
    };
    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, sign_handles, 0, &[]);
    assert!(res.is_err());
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_decrypt_rsa() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(RSA_P).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::DECRYPT,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_load_resp, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let decrypt_cmd = LocalRSADecryptCmd {
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let decrypt_handles = LocalRSADecryptHandles {
        key_handle: resp_handles.object_handle,
    };
    let _decrypt_resp = sim
        .execute_with_handles(decrypt_cmd, decrypt_handles)
        .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn test_load_external_hmac_keyed_hash() {
    let mut sim = create_simulator!();
    let seed_value = Tpm2bDigest::from_bytes(b"obfuscation is my middle name!!!").unwrap();
    let sensitive_data = Tpm2bSensitiveData::from_bytes(b"secrets").unwrap();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value,
        sensitive: TpmuSensitiveComposite::KeyedHash(sensitive_data),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [0x01; 32];
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &unique_bytes,
        TpmaObject::SIGN_ENCRYPT,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_load_resp, resp_handles) = sim.execute_with_handles(load_cmd, ()).unwrap();

    let hmac_cmd = LocalHmacCmd {
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = LocalMacHandles {
        handle: resp_handles.object_handle,
    };
    let _hmac_resp = sim.execute_with_handles(hmac_cmd, hmac_handles).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// ==================== Adversarial Hardening Tests ====================

#[test]
fn adv_load_external_sh_disabled() {
    let mut sim = create_simulator!();
    sim.global_state.sh_enable = false;

    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_OWNER,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::HIERARCHY.with(Position::parameter(3));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_eh_disabled() {
    let mut sim = create_simulator!();
    sim.global_state.eh_enable = false;

    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_ENDORSEMENT,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::HIERARCHY.with(Position::parameter(3));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_forbidden_attributes_fixed_parent() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::FIXED_PARENT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::ATTRIBUTES.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_forbidden_attributes_restricted() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::RESTRICTED));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::ATTRIBUTES.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_ecc_invalid_coords_size() {
    let mut sim = create_simulator!();
    let bad_x = [0u8; 31];
    let in_public = tpm2::Tpm2b(make_ecc_public_area(
        &bad_x,
        ECC_Y,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::KEY.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_ecc_scalar_too_large() {
    let mut sim = create_simulator!();
    let bad_d = [0x01; 33];
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(&bad_d).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::KEY_SIZE.with(Position::parameter(1));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_keyed_hash_sensitive_too_large() {
    let mut sim = create_simulator!();
    let bad_sensitive_data = [0x01; 65];
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(&bad_sensitive_data).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [0x01; 32];
    let mut pub_area = make_keyed_hash_public_area(&unique_bytes, TpmaObject::default());
    if let PublicParmsAndId::KeyedHash(ref mut scheme, _) = pub_area.parms_and_id {
        *scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    }
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::KEY_SIZE.with(Position::parameter(1));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_unsupported_name_alg() {
    let mut sim = create_simulator!();
    let mut pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    pub_struct.name_alg = Some(TpmiAlgHash::Sm3_256);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::HASH.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_name_alg_sha512() {
    let mut sim = create_simulator!();
    let mut pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    pub_struct.name_alg = Some(TpmiAlgHash::Sha512);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();

    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha512, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn adv_load_external_transient_objects_exhaustion() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let mut handles = Vec::new();
    for _ in 0..tpm2_impl::MAX_LOADED_OBJECTS {
        let (_, resp_handles) = sim.execute_with_handles(cmd.clone(), ()).unwrap();
        handles.push(resp_handles.object_handle);
    }

    let res = sim.execute_with_handles(cmd.clone(), ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::OBJECT_MEMORY;
    assert_eq!(err.get(), expected.get());

    for handle in handles {
        flush_context(&mut sim, handle).unwrap();
    }
}

#[test]
fn adv_load_external_rsa_p_q_bits_mismatch() {
    let mut sim = create_simulator!();

    let mut p_bytes = [0u8; 128];
    p_bytes[0] = 0x80;
    p_bytes[127] = 0x01;

    let mut n_bytes = [0u8; 256];
    n_bytes[0] = 0x10;
    n_bytes[128] = 0xa0;
    n_bytes[255] = 0x01;

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(&p_bytes).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        &n_bytes,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::BINDING.with(Position::parameter(1));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_sensitive_auth_value_too_large() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::from_bytes(&[0x01; 33]).unwrap(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::SIZE.with(Position::parameter(1));
    assert_eq!(err.get(), expected.get());
}

#[test]
fn adv_load_external_sym_public_only() {
    let mut sim = create_simulator!();

    let sym_unique = [0x01; 32];
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::from_bytes(&sym_unique).unwrap(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn adv_load_external_sym_public_only_size_mismatch() {
    let mut sim = create_simulator!();

    let sym_unique = [0x01; 16];
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::from_bytes(&sym_unique).unwrap(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute_with_handles(cmd, ());
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::KEY.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}
