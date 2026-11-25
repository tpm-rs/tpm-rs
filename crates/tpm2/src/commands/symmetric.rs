//! TPM 2.0 Symmetric Primitives Commands
//!
//! This module implements the "Symmetric Primitives" commands defined in
//! **Section 15** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_EncryptDecrypt (Command)
#[doc(alias = "TPM2_EncryptDecrypt")]
#[doc(alias = "EncryptDecrypt_In")]
#[deprecated]
#[derive(Clone, Copy)]
pub struct EncryptDecrypt<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub decrypt: bool,
    pub mode: Option<TpmiAlgCipherMode>,
    pub iv_in: Tpm2bIv<'a>,
    pub in_data: Tpm2bMaxBuffer<'a>,
}
/// TPM2_EncryptDecrypt (Response)
#[doc(alias = "EncryptDecrypt_Out")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct EncryptDecryptRsp<'a> {
    pub out_data: Tpm2bMaxBuffer<'a>,
    pub iv_out: Tpm2bIv<'a>,
}

impl Command for EncryptDecrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::EncryptDecrypt;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = EncryptDecryptRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for EncryptDecrypt<'_> {
    const MAX_SIZE: usize = bool::MAX_SIZE
        + <Option<TpmiAlgCipherMode>>::MAX_SIZE
        + Tpm2bIv::MAX_SIZE
        + Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; EncryptDecrypt::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.decrypt, dst, 0);
        let count = marshal_helper(&self.mode, dst, count);
        let count = marshal_helper(&self.iv_in, dst, count);
        marshal_helper(&self.in_data, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for EncryptDecrypt<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            decrypt: Unmarshal::unmarshal(src)?,
            mode: Unmarshal::unmarshal(src)?,
            iv_in: Unmarshal::unmarshal(src)?,
            in_data: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for EncryptDecryptRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for EncryptDecryptRsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + Tpm2bIv::MAX_SIZE;
    type MaxBuffer = [u8; EncryptDecryptRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_data, dst, 0);
        marshal_helper(&self.iv_out, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for EncryptDecryptRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
            iv_out: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_EncryptDecrypt2 (Command)
#[doc(alias = "TPM2_EncryptDecrypt2")]
#[doc(alias = "EncryptDecrypt2_In")]
#[derive(Clone, Copy)]
pub struct EncryptDecrypt2<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub in_data: Tpm2bMaxBuffer<'a>,
    pub decrypt: bool,
    pub mode: Option<TpmiAlgCipherMode>,
    pub iv_in: Tpm2bIv<'a>,
}
/// TPM2_EncryptDecrypt2 (Response)
#[doc(alias = "EncryptDecrypt2_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct EncryptDecrypt2Rsp<'a> {
    pub out_data: Tpm2bMaxBuffer<'a>,
    pub iv_out: Tpm2bIv<'a>,
}

impl Command for EncryptDecrypt2<'_> {
    const CMD_CODE: TpmCc = TpmCc::EncryptDecrypt2;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = EncryptDecrypt2Rsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for EncryptDecrypt2<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE
        + bool::MAX_SIZE
        + <Option<TpmiAlgCipherMode>>::MAX_SIZE
        + Tpm2bIv::MAX_SIZE;
    type MaxBuffer = [u8; EncryptDecrypt2::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_data, dst, 0);
        let count = marshal_helper(&self.decrypt, dst, count);
        let count = marshal_helper(&self.mode, dst, count);
        marshal_helper(&self.iv_in, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for EncryptDecrypt2<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            in_data: Unmarshal::unmarshal(src)?,
            decrypt: Unmarshal::unmarshal(src)?,
            mode: Unmarshal::unmarshal(src)?,
            iv_in: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for EncryptDecrypt2Rsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for EncryptDecrypt2Rsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + Tpm2bIv::MAX_SIZE;
    type MaxBuffer = [u8; EncryptDecrypt2Rsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_data, dst, 0);
        marshal_helper(&self.iv_out, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for EncryptDecrypt2Rsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
            iv_out: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Hash (Command)
#[doc(alias = "TPM2_Hash")]
#[doc(alias = "Hash_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Hash<'a> {
    pub data: Tpm2bMaxBuffer<'a>,
    pub hash_alg: TpmiAlgHash,
    pub hierarchy: Handle,
}
/// TPM2_Hash (Response)
#[doc(alias = "Hash_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct HashRsp<'a> {
    pub out_hash: Tpm2bDigest<'a>,
    pub validation: TpmtTkHashcheck<'a>,
}

impl Command for Hash<'_> {
    const CMD_CODE: TpmCc = TpmCc::Hash;
    type Handles<'a>
        = [EntityHandle<'a>; 0]
    where
        Self: 'a;
    type Response<'a> = HashRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for Hash<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + TpmiAlgHash::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Hash::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.data, dst, 0);
        let count = marshal_helper(&self.hash_alg, dst, count);
        marshal_helper(&self.hierarchy, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for Hash<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            data: Unmarshal::unmarshal(src)?,
            hash_alg: Unmarshal::unmarshal(src)?,
            hierarchy: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for HashRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for HashRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + TpmtTkHashcheck::MAX_SIZE;
    type MaxBuffer = [u8; HashRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_hash, dst, 0);
        marshal_helper(&self.validation, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for HashRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_hash: Unmarshal::unmarshal(src)?,
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_HMAC (Command)
#[doc(alias = "TPM2_HMAC")]
#[doc(alias = "HMAC_In")]
#[derive(Clone, Copy)]
pub struct HMAC<'a> {
    pub handle: ObjectHandle<'a>,
    pub buffer: Tpm2bMaxBuffer<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}
/// TPM2_HMAC (Response)
#[doc(alias = "HMAC_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct HMACRsp<'a> {
    pub out_hmac: Tpm2bDigest<'a>,
}

impl Command for HMAC<'_> {
    const CMD_CODE: TpmCc = TpmCc::HMAC;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = HMACRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.handle.into()]
    }
}
impl Marshal for HMAC<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; HMAC::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.buffer, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for HMAC<'a> {
    fn unmarshal_with_handles(
        [handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle: handle.try_into()?,
            buffer: Unmarshal::unmarshal(src)?,
            hash_alg: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for HMACRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for HMACRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; HMACRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_hmac.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for HMACRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_hmac: Unmarshal::unmarshal(src)?,
        })
    }
}
