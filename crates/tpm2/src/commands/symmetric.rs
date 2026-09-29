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

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 15.2 TPM2_EncryptDecrypt (Command)
#[doc(alias = "TPM2_EncryptDecrypt")]
#[doc(alias = "EncryptDecrypt_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecrypt<'a> {
    pub decrypt: bool,
    pub mode: Option<TpmiAlgCipherMode>,
    pub iv_in: Tpm2bIv<'a>,
    pub in_data: Tpm2bMaxBuffer<'a>,
}

impl Marshal for EncryptDecrypt<'_> {
    const MAX_SIZE: usize = bool::MAX_SIZE
        + Option::<TpmiAlgCipherMode>::MAX_SIZE
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

impl<'a> Unmarshal<'a> for EncryptDecrypt<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            decrypt: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            mode: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            iv_in: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            in_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecryptHandles {
    pub key_handle: Handle,
}

impl Marshal for EncryptDecryptHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for EncryptDecryptHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 15.2 TPM2_EncryptDecrypt (Response)
#[doc(alias = "EncryptDecrypt_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecryptRsp<'a> {
    pub out_data: Tpm2bMaxBuffer<'a>,
    pub iv_out: Tpm2bIv<'a>,
}

impl Marshal for EncryptDecryptRsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + Tpm2bIv::MAX_SIZE;
    type MaxBuffer = [u8; EncryptDecryptRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_data, dst, 0);
        marshal_helper(&self.iv_out, dst, count)
    }
}

impl<'a> Unmarshal<'a> for EncryptDecryptRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
            iv_out: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for EncryptDecrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::EncryptDecrypt;
    type Handles = EncryptDecryptHandles;
    type Response<'a> = EncryptDecryptRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 15.3 TPM2_EncryptDecrypt2 (Command)
#[doc(alias = "TPM2_EncryptDecrypt2")]
#[doc(alias = "EncryptDecrypt2_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecrypt2<'a> {
    pub in_data: Tpm2bMaxBuffer<'a>,
    pub decrypt: bool,
    pub mode: Option<TpmiAlgCipherMode>,
    pub iv_in: Tpm2bIv<'a>,
}

impl Marshal for EncryptDecrypt2<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE
        + bool::MAX_SIZE
        + Option::<TpmiAlgCipherMode>::MAX_SIZE
        + Tpm2bIv::MAX_SIZE;
    type MaxBuffer = [u8; EncryptDecrypt2::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_data, dst, 0);
        let count = marshal_helper(&self.decrypt, dst, count);
        let count = marshal_helper(&self.mode, dst, count);
        marshal_helper(&self.iv_in, dst, count)
    }
}

impl<'a> Unmarshal<'a> for EncryptDecrypt2<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            decrypt: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            mode: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            iv_in: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecrypt2Handles {
    pub key_handle: Handle,
}

impl Marshal for EncryptDecrypt2Handles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for EncryptDecrypt2Handles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 15.3 TPM2_EncryptDecrypt2 (Response)
#[doc(alias = "EncryptDecrypt2_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncryptDecrypt2Rsp<'a> {
    pub out_data: Tpm2bMaxBuffer<'a>,
    pub iv_out: Tpm2bIv<'a>,
}

impl Marshal for EncryptDecrypt2Rsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + Tpm2bIv::MAX_SIZE;
    type MaxBuffer = [u8; EncryptDecrypt2Rsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_data, dst, 0);
        marshal_helper(&self.iv_out, dst, count)
    }
}

impl<'a> Unmarshal<'a> for EncryptDecrypt2Rsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
            iv_out: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for EncryptDecrypt2<'_> {
    const CMD_CODE: TpmCc = TpmCc::EncryptDecrypt2;
    type Handles = EncryptDecrypt2Handles;
    type Response<'a> = EncryptDecrypt2Rsp<'a>;
    type RespHandles = ();
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

impl Marshal for Hash<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + TpmiAlgHash::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Hash::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.data, dst, 0);
        let count = marshal_helper(&self.hash_alg, dst, count);
        marshal_helper(&self.hierarchy, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Hash<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let data = Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?;
        let hash_alg = Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?;
        let hierarchy = TpmiRhHierarchy::unmarshal(src)
            .map_err(|e| e.in_parameter(3))?
            .0;
        Ok(Self {
            data,
            hash_alg,
            hierarchy,
        })
    }
}

impl Command for Hash<'_> {
    const CMD_CODE: TpmCc = TpmCc::Hash;
    type Handles = ();
    type Response<'a> = HashRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 15.4 TPM2_Hash (Response)
#[doc(alias = "Hash_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct HashRsp<'a> {
    pub out_hash: Tpm2bDigest<'a>,
    pub validation: TpmtTkHashcheck<'a>,
}

impl Marshal for HashRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + TpmtTkHashcheck::MAX_SIZE;
    type MaxBuffer = [u8; HashRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_hash, dst, 0);
        marshal_helper(&self.validation, dst, count)
    }
}

impl<'a> Unmarshal<'a> for HashRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_hash: Unmarshal::unmarshal(src)?,
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 15.5 TPM2_HMAC (Command)
#[doc(alias = "TPM2_HMAC")]
#[doc(alias = "HMAC_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Hmac<'a> {
    pub buffer: Tpm2bMaxBuffer<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}

impl Marshal for Hmac<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; Hmac::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Hmac::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.buffer, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Hmac<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            buffer: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hash_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HmacHandles {
    pub handle: Handle,
}

impl Marshal for HmacHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for HmacHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 15.5 TPM2_HMAC (Response)
#[doc(alias = "HMAC_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HmacRsp<'a> {
    pub out_hmac: Tpm2bDigest<'a>,
}

impl Marshal for HmacRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; HmacRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_hmac.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for HmacRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_hmac: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Hmac<'_> {
    const CMD_CODE: TpmCc = TpmCc::Hmac;
    type Handles = HmacHandles;
    type Response<'a> = HmacRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct MACHandles {
    pub handle: Handle,
}

impl Marshal for MACHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for MACHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 15.6 TPM2_MAC (Command)
#[doc(alias = "TPM2_MAC")]
#[doc(alias = "MAC_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct MAC<'a> {
    pub buffer: Tpm2bMaxBuffer<'a>,
    pub in_scheme: Option<TpmiAlgMacScheme>,
}

impl Marshal for MAC<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmiAlgMacScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; MAC::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.buffer, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}

impl<'a> Unmarshal<'a> for MAC<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            buffer: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 15.6 TPM2_MAC (Response)
#[doc(alias = "MAC_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct MACRsp<'a> {
    pub out_mac: Tpm2bDigest<'a>,
}

impl Marshal for MACRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; MACRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_mac.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for MACRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_mac: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for MAC<'_> {
    const CMD_CODE: TpmCc = TpmCc::MAC;
    type Handles = MACHandles;
    type Response<'a> = MACRsp<'a>;
    type RespHandles = ();
}
