//! TPM 2.0 Non-volatile Storage Commands
//!
//! This module implements the "Non-volatile Storage" commands defined in
//! **Section 31** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_NV_DefineSpace (Command)
#[doc(alias = "TPM2_NV_DefineSpace")]
#[doc(alias = "NV_DefineSpace_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVDefineSpace<'a> {
    pub auth_handle: Handle,
    pub auth: Tpm2bAuth<'a>,
    pub public_info: Tpm2bNvPublic<'a>,
}

impl Command for NVDefineSpace<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVDefineSpace;
    type Response<'a> = ();
}
impl Message for NVDefineSpace<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle]
    }
}
impl Marshal for NVDefineSpace<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + Tpm2bNvPublic::MAX_SIZE;
    type MaxBuffer = [u8; NVDefineSpace::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.public_info, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVDefineSpace<'a> {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            auth: Unmarshal::unmarshal(src)?,
            public_info: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_UndefineSpace (Command)
#[doc(alias = "TPM2_NV_UndefineSpace")]
#[doc(alias = "NV_UndefineSpace_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVUndefineSpace {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}

impl Command for NVUndefineSpace {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpace;
    type Response<'a> = ();
}
impl Message for NVUndefineSpace {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVUndefineSpace {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVUndefineSpace {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
        })
    }
}

/// TPM2_NV_UndefineSpaceSpecial (Command)
#[doc(alias = "TPM2_NV_UndefineSpaceSpecial")]
#[doc(alias = "NV_UndefineSpaceSpecial_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVUndefineSpaceSpecial {
    pub nv_index: Handle,
    pub platform: Handle,
}

impl Command for NVUndefineSpaceSpecial {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Response<'a> = ();
}
impl Message for NVUndefineSpaceSpecial {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.nv_index, self.platform]
    }
}
impl Marshal for NVUndefineSpaceSpecial {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVUndefineSpaceSpecial {
    fn unmarshal_with_handles(
        [nv_index, platform]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { nv_index, platform })
    }
}

/// TPM2_NV_ReadPublic (Command)
#[doc(alias = "TPM2_NV_ReadPublic")]
#[doc(alias = "NV_ReadPublic_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadPublic {
    pub nv_index: Handle,
}
/// TPM2_NV_ReadPublic (Response)
#[doc(alias = "NV_ReadPublic_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadPublicRsp<'a> {
    pub nv_public: Tpm2bNvPublic<'a>,
    pub nv_name: Tpm2bName<'a>,
}

impl Command for NVReadPublic {
    const CMD_CODE: TpmCc = TpmCc::NVReadPublic;
    type Response<'a> = NVReadPublicRsp<'a>;
}
impl Message for NVReadPublic {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.nv_index]
    }
}
impl Marshal for NVReadPublic {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVReadPublic {
    fn unmarshal_with_handles(
        [nv_index]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { nv_index })
    }
}

impl Message for NVReadPublicRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for NVReadPublicRsp<'_> {
    const MAX_SIZE: usize = Tpm2bNvPublic::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; NVReadPublicRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nv_public, dst, 0);
        marshal_helper(&self.nv_name, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVReadPublicRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_public: Unmarshal::unmarshal(src)?,
            nv_name: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_Write (Command)
#[doc(alias = "TPM2_NV_Write")]
#[doc(alias = "NV_Write_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVWrite<'a> {
    pub auth_handle: Handle,
    pub nv_index: Handle,
    pub data: Tpm2bMaxNvBuffer<'a>,
    pub offset: u16,
}

impl Command for NVWrite<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVWrite;
    type Response<'a> = ();
}
impl Message for NVWrite<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVWrite<'_> {
    const MAX_SIZE: usize = Tpm2bMaxNvBuffer::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; NVWrite::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.data, dst, 0);
        marshal_helper(&self.offset, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVWrite<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
            data: Unmarshal::unmarshal(src)?,
            offset: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_Increment (Command)
#[doc(alias = "TPM2_NV_Increment")]
#[doc(alias = "NV_Increment_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVIncrement {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}

impl Command for NVIncrement {
    const CMD_CODE: TpmCc = TpmCc::NVIncrement;
    type Response<'a> = ();
}
impl Message for NVIncrement {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVIncrement {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVIncrement {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
        })
    }
}

/// TPM2_NV_Extend (Command)
#[doc(alias = "TPM2_NV_Extend")]
#[doc(alias = "NV_Extend_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVExtend<'a> {
    pub auth_handle: Handle,
    pub nv_index: Handle,
    pub data: Tpm2bMaxNvBuffer<'a>,
}

impl Command for NVExtend<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVExtend;
    type Response<'a> = ();
}
impl Message for NVExtend<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVExtend<'_> {
    const MAX_SIZE: usize = Tpm2bMaxNvBuffer::MAX_SIZE;
    type MaxBuffer = [u8; NVExtend::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.data.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for NVExtend<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
            data: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_SetBits (Command)
#[doc(alias = "TPM2_NV_SetBits")]
#[doc(alias = "NV_SetBits_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVSetBits {
    pub auth_handle: Handle,
    pub nv_index: Handle,
    pub bits: u64,
}

impl Command for NVSetBits {
    const CMD_CODE: TpmCc = TpmCc::NVSetBits;
    type Response<'a> = ();
}
impl Message for NVSetBits {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVSetBits {
    const MAX_SIZE: usize = u64::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.bits.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for NVSetBits {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
            bits: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_WriteLock (Command)
#[doc(alias = "TPM2_NV_WriteLock")]
#[doc(alias = "NV_WriteLock_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVWriteLock {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}

impl Command for NVWriteLock {
    const CMD_CODE: TpmCc = TpmCc::NVWriteLock;
    type Response<'a> = ();
}
impl Message for NVWriteLock {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVWriteLock {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVWriteLock {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
        })
    }
}

/// TPM2_NV_GlobalWriteLock (Command)
#[doc(alias = "TPM2_NV_GlobalWriteLock")]
#[doc(alias = "NV_GlobalWriteLock_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVGlobalWriteLock {
    pub auth_handle: Handle,
}

impl Command for NVGlobalWriteLock {
    const CMD_CODE: TpmCc = TpmCc::NVGlobalWriteLock;
    type Response<'a> = ();
}
impl Message for NVGlobalWriteLock {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle]
    }
}
impl Marshal for NVGlobalWriteLock {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVGlobalWriteLock {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { auth_handle })
    }
}

/// TPM2_NV_Read (Command)
#[doc(alias = "TPM2_NV_Read")]
#[doc(alias = "NV_Read_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVRead {
    pub auth_handle: Handle,
    pub nv_index: Handle,
    pub size: u16,
    pub offset: u16,
}
/// TPM2_NV_Read (Response)
#[doc(alias = "NV_Read_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadRsp<'a> {
    pub data: Tpm2bMaxNvBuffer<'a>,
}

impl Command for NVRead {
    const CMD_CODE: TpmCc = TpmCc::NVRead;
    type Response<'a> = NVReadRsp<'a>;
}
impl Message for NVRead {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVRead {
    const MAX_SIZE: usize = u16::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.size, dst, 0);
        marshal_helper(&self.offset, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVRead {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
            size: Unmarshal::unmarshal(src)?,
            offset: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for NVReadRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for NVReadRsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxNvBuffer::MAX_SIZE;
    type MaxBuffer = [u8; NVReadRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.data.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for NVReadRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            data: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_ReadLock (Command)
#[doc(alias = "TPM2_NV_ReadLock")]
#[doc(alias = "NV_ReadLock_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadLock {
    pub auth_handle: Handle,
    pub nv_index: Handle,
}

impl Command for NVReadLock {
    const CMD_CODE: TpmCc = TpmCc::NVReadLock;
    type Response<'a> = ();
}
impl Message for NVReadLock {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVReadLock {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVReadLock {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
        })
    }
}

/// TPM2_NV_ChangeAuth (Command)
#[doc(alias = "TPM2_NV_ChangeAuth")]
#[doc(alias = "NV_ChangeAuth_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVChangeAuth<'a> {
    pub nv_index: Handle,
    pub new_auth: Tpm2bAuth<'a>,
}

impl Command for NVChangeAuth<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVChangeAuth;
    type Response<'a> = ();
}
impl Message for NVChangeAuth<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.nv_index]
    }
}
impl Marshal for NVChangeAuth<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE;
    type MaxBuffer = [u8; NVChangeAuth::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_auth.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for NVChangeAuth<'a> {
    fn unmarshal_with_handles(
        [nv_index]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_index,
            new_auth: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_Certify (Command)
#[doc(alias = "TPM2_NV_Certify")]
#[doc(alias = "NV_Certify_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVCertify<'a> {
    pub sign_handle: Handle,
    pub auth_handle: Handle,
    pub nv_index: Handle,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub size: u16,
    pub offset: u16,
}
/// TPM2_NV_Certify (Response)
#[doc(alias = "NV_Certify_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVCertifyRsp<'a> {
    pub certify_info: Tpm2bAttest<'a>,
    pub signature: TpmtSignature<'a>,
}

impl Command for NVCertify<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVCertify;
    type Response<'a> = NVCertifyRsp<'a>;
}
impl Message for NVCertify<'_> {
    type Handles = [Handle; 3];
    fn handles(&self) -> Self::Handles {
        [self.sign_handle, self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVCertify<'_> {
    const MAX_SIZE: usize =
        Tpm2bData::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE + u16::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; NVCertify::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        let count = marshal_helper(&self.size, dst, count);
        marshal_helper(&self.offset, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVCertify<'a> {
    fn unmarshal_with_handles(
        [sign_handle, auth_handle, nv_index]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle,
            auth_handle,
            nv_index,
            qualifying_data: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
            size: Unmarshal::unmarshal(src)?,
            offset: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for NVCertifyRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for NVCertifyRsp<'_> {
    const MAX_SIZE: usize = Tpm2bAttest::MAX_SIZE + TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; NVCertifyRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.certify_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVCertifyRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            certify_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}
