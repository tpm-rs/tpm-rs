//! TPM 2.0 Non-volatile Storage Commands
//!
//! This module implements the "Non-volatile Storage" commands defined in
//! **Section 31** of the TPM 2.0 Specification.
//!
//! These commands allow defining, undefining, reading from, writing to, and locking
//! NV indices on the TPM.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVDefineSpaceHandles {
    pub auth_handle: Handle,
}
impl Marshal for NVDefineSpaceHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVDefineSpaceHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhProvision::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 31.3 TPM2_NV_DefineSpace (Command)
#[doc(alias = "TPM2_NV_DefineSpace")]
#[doc(alias = "NV_DefineSpace_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVDefineSpace<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub public_info: Tpm2bNvPublic<'a>,
}
impl Marshal for NVDefineSpace<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + Tpm2bNvPublic::MAX_SIZE;
    type MaxBuffer = [u8; NVDefineSpace::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.public_info, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVDefineSpace<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            public_info: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Command for NVDefineSpace<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVDefineSpace;
    type Handles = NVDefineSpaceHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVUndefineSpaceHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVUndefineSpaceHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVUndefineSpaceHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhProvision::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            nv_index: TpmiRhNvDefinedIndex::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 31.4 TPM2_NV_UndefineSpace (Command)
#[doc(alias = "TPM2_NV_UndefineSpace")]
#[doc(alias = "NV_UndefineSpace_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVUndefineSpace {}
impl Marshal for NVUndefineSpace {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for NVUndefineSpace {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for NVUndefineSpace {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpace;
    type Handles = NVUndefineSpaceHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVUndefineSpaceSpecialHandles {
    pub nv_index: Handle,
    pub platform: Handle,
}
impl Marshal for NVUndefineSpaceSpecialHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nv_index, dst, 0);
        marshal_helper(&self.platform, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVUndefineSpaceSpecialHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_index: TpmiRhNvDefinedIndex::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            platform: TpmiRhPlatform::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 31.5 TPM2_NV_UndefineSpaceSpecial (Command)
#[doc(alias = "TPM2_NV_UndefineSpaceSpecial")]
#[doc(alias = "NV_UndefineSpaceSpecial_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVUndefineSpaceSpecial {}
impl Marshal for NVUndefineSpaceSpecial {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for NVUndefineSpaceSpecial {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for NVUndefineSpaceSpecial {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Handles = NVUndefineSpaceSpecialHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadPublicHandles {
    pub nv_index: Handle,
}
impl Marshal for NVReadPublicHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.nv_index.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVReadPublicHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.6 TPM2_NV_ReadPublic (Response)
#[doc(alias = "NV_ReadPublic_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadPublicRsp<'a> {
    pub nv_public: Tpm2bNvPublic<'a>,
    pub nv_name: Tpm2bName<'a>,
}
impl Marshal for NVReadPublicRsp<'_> {
    const MAX_SIZE: usize = Tpm2bNvPublic::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; NVReadPublicRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nv_public, dst, 0);
        marshal_helper(&self.nv_name, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVReadPublicRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_public: Unmarshal::unmarshal(src)?,
            nv_name: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 31.6 TPM2_NV_ReadPublic (Command)
#[doc(alias = "TPM2_NV_ReadPublic")]
#[doc(alias = "NV_ReadPublic_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadPublic {}
impl Marshal for NVReadPublic {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for NVReadPublic {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for NVReadPublic {
    const CMD_CODE: TpmCc = TpmCc::NVReadPublic;
    type Handles = NVReadPublicHandles;
    type Response<'a> = NVReadPublicRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVWriteHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVWriteHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVWriteHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.7 TPM2_NV_Write (Command)
#[doc(alias = "TPM2_NV_Write")]
#[doc(alias = "NV_Write_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct NVWrite<'a> {
    pub data: crate::Tpm2bMaxNvBuffer<'a>,
    pub offset: u16,
}
impl Marshal for NVWrite<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bMaxNvBuffer>::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; NVWrite::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.data, dst, 0);
        marshal_helper(&self.offset, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVWrite<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Command for NVWrite<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVWrite;
    type Handles = NVWriteHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVIncrementHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVIncrementHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVIncrementHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.8 TPM2_NV_Increment (Command)
#[doc(alias = "TPM2_NV_Increment")]
#[doc(alias = "NV_Increment_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVIncrement {}
impl Marshal for NVIncrement {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for NVIncrement {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for NVIncrement {
    const CMD_CODE: TpmCc = TpmCc::NVIncrement;
    type Handles = NVIncrementHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVExtendHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVExtendHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVExtendHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.9 TPM2_NV_Extend (Command)
#[doc(alias = "TPM2_NV_Extend")]
#[doc(alias = "NV_Extend_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct NVExtend<'a> {
    pub data: crate::Tpm2bMaxNvBuffer<'a>,
}
impl Marshal for NVExtend<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bMaxNvBuffer>::MAX_SIZE;
    type MaxBuffer = [u8; NVExtend::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVExtend<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for NVExtend<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVExtend;
    type Handles = NVExtendHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVSetBitsHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVSetBitsHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVSetBitsHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.10 TPM2_NV_SetBits (Command)
#[doc(alias = "TPM2_NV_SetBits")]
#[doc(alias = "NV_SetBits_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVSetBits {
    pub bits: u64,
}
impl Marshal for NVSetBits {
    const MAX_SIZE: usize = u64::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.bits.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVSetBits {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            bits: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for NVSetBits {
    const CMD_CODE: TpmCc = TpmCc::NVSetBits;
    type Handles = NVSetBitsHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVWriteLockHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVWriteLockHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVWriteLockHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.11 TPM2_NV_WriteLock (Command)
#[doc(alias = "TPM2_NV_WriteLock")]
#[doc(alias = "NV_WriteLock_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVWriteLock {}
impl Marshal for NVWriteLock {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for NVWriteLock {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for NVWriteLock {
    const CMD_CODE: TpmCc = TpmCc::NVWriteLock;
    type Handles = NVWriteLockHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVGlobalWriteLockHandles {
    pub auth_handle: Handle,
}
impl Marshal for NVGlobalWriteLockHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVGlobalWriteLockHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhProvision::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 31.12 TPM2_NV_GlobalWriteLock (Command)
#[doc(alias = "TPM2_NV_GlobalWriteLock")]
#[doc(alias = "NV_GlobalWriteLock_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVGlobalWriteLock {}
impl Marshal for NVGlobalWriteLock {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for NVGlobalWriteLock {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for NVGlobalWriteLock {
    const CMD_CODE: TpmCc = TpmCc::NVGlobalWriteLock;
    type Handles = NVGlobalWriteLockHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVReadHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVReadHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.13 TPM2_NV_Read (Response)
#[doc(alias = "NV_Read_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct NVReadRsp<'a> {
    pub data: crate::Tpm2bMaxNvBuffer<'a>,
}
impl Marshal for NVReadRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bMaxNvBuffer>::MAX_SIZE;
    type MaxBuffer = [u8; NVReadRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVReadRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            data: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 31.13 TPM2_NV_Read (Command)
#[doc(alias = "TPM2_NV_Read")]
#[doc(alias = "NV_Read_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVRead {
    pub size: u16,
    pub offset: u16,
}
impl Marshal for NVRead {
    const MAX_SIZE: usize = u16::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.size, dst, 0);
        marshal_helper(&self.offset, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVRead {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            size: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Command for NVRead {
    const CMD_CODE: TpmCc = TpmCc::NVRead;
    type Handles = NVReadHandles;
    type Response<'a> = NVReadRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadLockHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVReadLockHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVReadLockHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.14 TPM2_NV_ReadLock (Command)
#[doc(alias = "TPM2_NV_ReadLock")]
#[doc(alias = "NV_ReadLock_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadLock {}
impl Marshal for NVReadLock {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for NVReadLock {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for NVReadLock {
    const CMD_CODE: TpmCc = TpmCc::NVReadLock;
    type Handles = NVReadLockHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVChangeAuthHandles {
    pub nv_index: Handle,
}
impl Marshal for NVChangeAuthHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.nv_index.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVChangeAuthHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.15 TPM2_NV_ChangeAuth (Command)
#[doc(alias = "TPM2_NV_ChangeAuth")]
#[doc(alias = "NV_ChangeAuth_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct NVChangeAuth<'a> {
    pub new_auth: crate::Tpm2bAuth<'a>,
}
impl Marshal for NVChangeAuth<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bAuth>::MAX_SIZE;
    type MaxBuffer = [u8; NVChangeAuth::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_auth.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVChangeAuth<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            new_auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for NVChangeAuth<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVChangeAuth;
    type Handles = NVChangeAuthHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVCertifyHandles {
    pub sign_handle: Handle,
    pub auth_handle: Handle,
    pub nv_index: Handle,
}
impl Marshal for NVCertifyHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.sign_handle, dst, 0);
        let count = marshal_helper(&self.auth_handle, dst, count);
        marshal_helper(&self.nv_index, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVCertifyHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(3))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.16 TPM2_NV_Certify (Response)
#[doc(alias = "NV_Certify_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct NVCertifyRsp<'a> {
    pub certify_info: crate::Tpm2bAttest<'a>,
    pub signature: Option<crate::TpmtSignature<'a>>,
}

impl<'a> Marshal for NVCertifyRsp<'a> {
    const MAX_SIZE: usize =
        <crate::Tpm2bAttest>::MAX_SIZE + <Option<crate::TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; NVCertifyRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.certify_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVCertifyRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            certify_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 31.16 TPM2_NV_Certify (Command)
#[doc(alias = "TPM2_NV_Certify")]
#[doc(alias = "NV_Certify_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct NVCertify<'a> {
    pub qualifying_data: crate::Tpm2bData<'a>,
    pub in_scheme: Option<crate::TpmtSigScheme>,
    pub size: u16,
    pub offset: u16,
}
impl Marshal for NVCertify<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE
        + <Option<crate::TpmtSigScheme>>::MAX_SIZE
        + u16::MAX_SIZE
        + u16::MAX_SIZE;
    type MaxBuffer = [u8; NVCertify::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        let count = marshal_helper(&self.size, dst, count);
        marshal_helper(&self.offset, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVCertify<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            size: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

impl Command for NVCertify<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVCertify;
    type Handles = NVCertifyHandles;
    type Response<'a> = NVCertifyRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVDefineSpace2Handles {
    pub auth_handle: Handle,
}

impl Marshal for NVDefineSpace2Handles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVDefineSpace2Handles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhProvision::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 31.17 TPM2_NV_DefineSpace2 (Command)
#[doc(alias = "TPM2_NV_DefineSpace2")]
#[doc(alias = "NV_DefineSpace2_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVDefineSpace2<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub public_info: Tpm2bNvPublic2<'a>,
}

impl Marshal for NVDefineSpace2<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + Tpm2bNvPublic2::MAX_SIZE;
    type MaxBuffer = [u8; NVDefineSpace2::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.public_info, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVDefineSpace2<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            public_info: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Command for NVDefineSpace2<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVDefineSpace2;
    type Handles = NVDefineSpace2Handles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadPublic2Handles {
    pub nv_index: Handle,
}

impl Marshal for NVReadPublic2Handles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.nv_index.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for NVReadPublic2Handles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 31.18 TPM2_NV_ReadPublic2 (Command)
#[doc(alias = "TPM2_NV_ReadPublic2")]
#[doc(alias = "NV_ReadPublic2_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadPublic2 {}

impl Marshal for NVReadPublic2 {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for NVReadPublic2 {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

/// [TPM2.0 1.83] 31.18 TPM2_NV_ReadPublic2 (Response)
#[doc(alias = "NV_ReadPublic2_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct NVReadPublic2Rsp<'a> {
    pub nv_public: Tpm2bNvPublic2<'a>,
    pub nv_name: Tpm2bName<'a>,
}

impl Marshal for NVReadPublic2Rsp<'_> {
    const MAX_SIZE: usize = Tpm2bNvPublic2::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; NVReadPublic2Rsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nv_public, dst, 0);
        marshal_helper(&self.nv_name, dst, count)
    }
}

impl<'a> Unmarshal<'a> for NVReadPublic2Rsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_public: Unmarshal::unmarshal(src)?,
            nv_name: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for NVReadPublic2 {
    const CMD_CODE: TpmCc = TpmCc::NVReadPublic2;
    type Handles = NVReadPublic2Handles;
    type Response<'a> = NVReadPublic2Rsp<'a>;
    type RespHandles = ();
}
