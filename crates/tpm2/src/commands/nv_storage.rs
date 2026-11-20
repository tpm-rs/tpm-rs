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
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle.into()]
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
        [auth_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.handle,
            auth: Unmarshal::unmarshal(src)?,
            public_info: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_UndefineSpace (Command)
#[doc(alias = "TPM2_NV_UndefineSpace")]
#[doc(alias = "NV_UndefineSpace_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVUndefineSpace<'a> {
    pub auth_handle: Handle,
    pub nv_index: NamedHandle<'a>,
}

impl Command for NVUndefineSpace<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpace;
    type Response<'a> = ();
}
impl Message for NVUndefineSpace<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle.into(), self.nv_index]
    }
}
impl Marshal for NVUndefineSpace<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVUndefineSpace<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.handle,
            nv_index,
        })
    }
}

/// TPM2_NV_UndefineSpaceSpecial (Command)
#[doc(alias = "TPM2_NV_UndefineSpaceSpecial")]
#[doc(alias = "NV_UndefineSpaceSpecial_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVUndefineSpaceSpecial<'a> {
    pub nv_index: NamedHandle<'a>,
    pub platform: Handle,
}

impl Command for NVUndefineSpaceSpecial<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Response<'a> = ();
}
impl Message for NVUndefineSpaceSpecial<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.nv_index, self.platform.into()]
    }
}
impl Marshal for NVUndefineSpaceSpecial<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVUndefineSpaceSpecial<'a> {
    fn unmarshal_with_handles(
        [nv_index, platform]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_index,
            platform: platform.handle,
        })
    }
}

/// TPM2_NV_ReadPublic (Command)
#[doc(alias = "TPM2_NV_ReadPublic")]
#[doc(alias = "NV_ReadPublic_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadPublic<'a> {
    pub nv_index: NamedHandle<'a>,
}
/// TPM2_NV_ReadPublic (Response)
#[doc(alias = "NV_ReadPublic_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadPublicRsp<'a> {
    pub nv_public: Tpm2bNvPublic<'a>,
    pub nv_name: Tpm2bName<'a>,
}

impl Command for NVReadPublic<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVReadPublic;
    type Response<'a> = NVReadPublicRsp<'a>;
}
impl Message for NVReadPublic<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.nv_index]
    }
}
impl Marshal for NVReadPublic<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVReadPublic<'a> {
    fn unmarshal_with_handles(
        [nv_index]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { nv_index })
    }
}

impl Message for NVReadPublicRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
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
        []: Self::Handles<'a>,
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
    pub auth_handle: NamedHandle<'a>,
    pub nv_index: NamedHandle<'a>,
    pub data: Tpm2bMaxNvBuffer<'a>,
    pub offset: u16,
}

impl Command for NVWrite<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVWrite;
    type Response<'a> = ();
}
impl Message for NVWrite<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
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
        [auth_handle, nv_index]: Self::Handles<'a>,
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
pub struct NVIncrement<'a> {
    pub auth_handle: NamedHandle<'a>,
    pub nv_index: NamedHandle<'a>,
}

impl Command for NVIncrement<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVIncrement;
    type Response<'a> = ();
}
impl Message for NVIncrement<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVIncrement<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVIncrement<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles<'a>,
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
    pub auth_handle: NamedHandle<'a>,
    pub nv_index: NamedHandle<'a>,
    pub data: Tpm2bMaxNvBuffer<'a>,
}

impl Command for NVExtend<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVExtend;
    type Response<'a> = ();
}
impl Message for NVExtend<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
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
        [auth_handle, nv_index]: Self::Handles<'a>,
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
pub struct NVSetBits<'a> {
    pub auth_handle: NamedHandle<'a>,
    pub nv_index: NamedHandle<'a>,
    pub bits: u64,
}

impl Command for NVSetBits<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVSetBits;
    type Response<'a> = ();
}
impl Message for NVSetBits<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVSetBits<'_> {
    const MAX_SIZE: usize = u64::MAX_SIZE;
    type MaxBuffer = [u8; NVSetBits::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.bits.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for NVSetBits<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles<'a>,
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
pub struct NVWriteLock<'a> {
    pub auth_handle: NamedHandle<'a>,
    pub nv_index: NamedHandle<'a>,
}

impl Command for NVWriteLock<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVWriteLock;
    type Response<'a> = ();
}
impl Message for NVWriteLock<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVWriteLock<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVWriteLock<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles<'a>,
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
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle.into()]
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
        [auth_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.handle,
        })
    }
}

/// TPM2_NV_Read (Command)
#[doc(alias = "TPM2_NV_Read")]
#[doc(alias = "NV_Read_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVRead<'a> {
    pub auth_handle: NamedHandle<'a>,
    pub nv_index: NamedHandle<'a>,
    pub size: u16,
    pub offset: u16,
}
/// TPM2_NV_Read (Response)
#[doc(alias = "NV_Read_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadRsp<'a> {
    pub data: Tpm2bMaxNvBuffer<'a>,
}

impl Command for NVRead<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVRead;
    type Response<'a> = NVReadRsp<'a>;
}
impl Message for NVRead<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVRead<'_> {
    const MAX_SIZE: usize = u16::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; NVRead::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.size, dst, 0);
        marshal_helper(&self.offset, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVRead<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles<'a>,
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
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
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
        []: Self::Handles<'a>,
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
pub struct NVReadLock<'a> {
    pub auth_handle: NamedHandle<'a>,
    pub nv_index: NamedHandle<'a>,
}

impl Command for NVReadLock<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVReadLock;
    type Response<'a> = ();
}
impl Message for NVReadLock<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle, self.nv_index]
    }
}
impl Marshal for NVReadLock<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVReadLock<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index]: Self::Handles<'a>,
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
    pub nv_index: NamedHandle<'a>,
    pub new_auth: Tpm2bAuth<'a>,
}

impl Command for NVChangeAuth<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVChangeAuth;
    type Response<'a> = ();
}
impl Message for NVChangeAuth<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
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
        [nv_index]: Self::Handles<'a>,
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
    pub sign_handle: NamedHandle<'a>,
    pub auth_handle: NamedHandle<'a>,
    pub nv_index: NamedHandle<'a>,
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
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for NVCertify<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVCertify;
    type Response<'a> = NVCertifyRsp<'a>;
}
impl Message for NVCertify<'_> {
    const NUM_HANDLES: usize = 3;
    type Handles<'a>
        = [NamedHandle<'a>; 3]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
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
        [sign_handle, auth_handle, nv_index]: Self::Handles<'a>,
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
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for NVCertifyRsp<'_> {
    const MAX_SIZE: usize = Tpm2bAttest::MAX_SIZE + <Option<TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; NVCertifyRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.certify_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVCertifyRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            certify_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_DefineSpace2 (Command)
#[doc(alias = "TPM2_NV_DefineSpace2")]
#[doc(alias = "NV_DefineSpace2_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVDefineSpace2<'a> {
    pub auth_handle: Handle,
    pub auth: Tpm2bAuth<'a>,
    pub public_info: Tpm2bNvPublic2<'a>,
}

impl Command for NVDefineSpace2<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVDefineSpace2;
    type Response<'a> = ();
}
impl Message for NVDefineSpace2<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle.into()]
    }
}
impl Marshal for NVDefineSpace2<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + Tpm2bNvPublic2::MAX_SIZE;
    type MaxBuffer = [u8; NVDefineSpace2::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.public_info, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVDefineSpace2<'a> {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.handle,
            auth: Unmarshal::unmarshal(src)?,
            public_info: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_NV_ReadPublic2 (Command)
#[doc(alias = "TPM2_NV_ReadPublic2")]
#[doc(alias = "NV_ReadPublic2_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadPublic2<'a> {
    pub nv_index: NamedHandle<'a>,
}
/// TPM2_NV_ReadPublic2 (Response)
#[doc(alias = "NV_ReadPublic2_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct NVReadPublic2Rsp<'a> {
    pub nv_public: Tpm2bNvPublic2<'a>,
    pub nv_name: Tpm2bName<'a>,
}

impl Command for NVReadPublic2<'_> {
    const CMD_CODE: TpmCc = TpmCc::NVReadPublic2;
    type Response<'a> = NVReadPublic2Rsp<'a>;
}
impl Message for NVReadPublic2<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.nv_index]
    }
}
impl Marshal for NVReadPublic2<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for NVReadPublic2<'a> {
    fn unmarshal_with_handles(
        [nv_index]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { nv_index })
    }
}

impl Message for NVReadPublic2Rsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for NVReadPublic2Rsp<'_> {
    const MAX_SIZE: usize = Tpm2bNvPublic2::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; NVReadPublic2Rsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nv_public, dst, 0);
        marshal_helper(&self.nv_name, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for NVReadPublic2Rsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_public: Unmarshal::unmarshal(src)?,
            nv_name: Unmarshal::unmarshal(src)?,
        })
    }
}
