//! TPM 2.0 Symmetric Primitives Commands
//!
//! This module implements the "Symmetric Primitives" commands defined in
//! **Section 15** of the TPM 2.0 Specification.
//!
//! These commands perform symmetric block cipher encryption, decryption,
//! and MAC computations.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.
#![allow(deprecated)] // So we can define the now-deprecated `EncryptDecrypt` command / impls.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 15.2 TPM2_EncryptDecrypt (Command)
#[doc(alias = "TPM2_EncryptDecrypt")]
#[doc(alias = "EncryptDecrypt_In")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecrypt<'a> {
    pub key_handle: Handle,
    pub decrypt: bool,
    pub mode: Option<TpmiAlgCipherMode>,
    pub iv_in: Tpm2bIv<'a>,
    pub in_data: Tpm2bMaxBuffer<'a>,
}
/// [TPM2.0 1.83] 15.2 TPM2_EncryptDecrypt (Response)
#[doc(alias = "EncryptDecrypt_Out")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecryptRsp<'a> {
    pub out_data: Tpm2bMaxBuffer<'a>,
    pub iv_out: Tpm2bIv<'a>,
}

impl Command for EncryptDecrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::EncryptDecrypt;
    type Response<'a> = EncryptDecryptRsp<'a>;
}
impl Message for EncryptDecrypt<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.key_handle]
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
impl<'a> UnmarshalMessage<'a> for EncryptDecrypt<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle,
            decrypt: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            mode: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            iv_in: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            in_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

impl Message for EncryptDecryptRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for EncryptDecryptRsp<'a> {
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

/// [TPM2.0 1.83] 15.3 TPM2_EncryptDecrypt2 (Command)
#[doc(alias = "TPM2_EncryptDecrypt2")]
#[doc(alias = "EncryptDecrypt2_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecrypt2<'a> {
    pub key_handle: Handle,
    pub in_data: Tpm2bMaxBuffer<'a>,
    pub decrypt: bool,
    pub mode: Option<TpmiAlgCipherMode>,
    pub iv_in: Tpm2bIv<'a>,
}
/// [TPM2.0 1.83] 15.3 TPM2_EncryptDecrypt2 (Response)
#[doc(alias = "EncryptDecrypt2_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecrypt2Rsp<'a> {
    pub out_data: Tpm2bMaxBuffer<'a>,
    pub iv_out: Tpm2bIv<'a>,
}

impl Command for EncryptDecrypt2<'_> {
    const CMD_CODE: TpmCc = TpmCc::EncryptDecrypt2;
    type Response<'a> = EncryptDecrypt2Rsp<'a>;
}
impl Message for EncryptDecrypt2<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.key_handle]
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
impl<'a> UnmarshalMessage<'a> for EncryptDecrypt2<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle,
            in_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            decrypt: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            mode: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            iv_in: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

impl Message for EncryptDecrypt2Rsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for EncryptDecrypt2Rsp<'a> {
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

/// [TPM2.0 1.83] 15.4 TPM2_Hash (Command)
#[doc(alias = "TPM2_Hash")]
#[doc(alias = "Hash_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Hash<'a> {
    pub data: Tpm2bMaxBuffer<'a>,
    pub hash_alg: TpmiAlgHash,
    pub hierarchy: Handle,
}
/// [TPM2.0 1.83] 15.4 TPM2_Hash (Response)
#[doc(alias = "Hash_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HashRsp<'a> {
    pub out_hash: Tpm2bDigest<'a>,
    pub validation: TpmtTkHashcheck<'a>,
}

impl Command for Hash<'_> {
    const CMD_CODE: TpmCc = TpmCc::Hash;
    type Response<'a> = HashRsp<'a>;
}
impl Message for Hash<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
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
impl<'a> UnmarshalMessage<'a> for Hash<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hash_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            // `hierarchy` is a `TPMI_RH_HIERARCHY+` command parameter (not a
            // handle), so its range is validated here.
            hierarchy: TpmiRhHierarchy::unmarshal(src)
                .map_err(|e| e.in_parameter(3))?
                .0,
        })
    }
}

impl Message for HashRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for HashRsp<'a> {
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

/// [TPM2.0 1.83] 15.5 TPM2_HMAC (Command)
///
/// This also covers `TPM2_MAC` (15.6), which shares the same command code
/// (see "Shared `HMAC` / `MAC` Command Codes" in the [`commands`](crate::commands)
/// module docs).
#[doc(alias = "TPM2_HMAC")]
#[doc(alias = "HMAC_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HMAC<'a> {
    pub handle: Handle,
    pub buffer: Tpm2bMaxBuffer<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}
/// [TPM2.0 1.83] 15.5 TPM2_HMAC (Response)
#[doc(alias = "HMAC_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HMACRsp<'a> {
    pub out_hmac: Tpm2bDigest<'a>,
}

impl Command for HMAC<'_> {
    const CMD_CODE: TpmCc = TpmCc::HMAC;
    type Response<'a> = HMACRsp<'a>;
}
impl Message for HMAC<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.handle]
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
impl<'a> UnmarshalMessage<'a> for HMAC<'a> {
    fn unmarshal_with_handles(
        [handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle,
            buffer: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hash_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Message for HMACRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for HMACRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_hmac: Unmarshal::unmarshal(src)?,
        })
    }
}
