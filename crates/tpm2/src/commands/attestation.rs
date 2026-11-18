//! TPM 2.0 Attestation Commands
//!
//! This module implements the "Attestation Commands" commands defined in
//! **Section 18** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_Certify (Command)
#[doc(alias = "TPM2_Certify")]
#[doc(alias = "Certify_In")]
#[derive(Clone, Copy)]
pub struct Certify<'a> {
    pub object_handle: ObjectHandle<'a>,
    pub sign_handle: EntityHandle<'a>,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
}
/// TPM2_Certify (Response)
#[doc(alias = "Certify_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct CertifyRsp<'a> {
    pub certify_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for Certify<'_> {
    const CMD_CODE: TpmCc = TpmCc::Certify;
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = CertifyRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.object_handle.into(), self.sign_handle]
    }
}
impl Marshal for Certify<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; Certify::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for Certify<'a> {
    fn unmarshal_with_handles(
        [object_handle, sign_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: object_handle.try_into()?,
            sign_handle,
            qualifying_data: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for CertifyRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for CertifyRsp<'_> {
    const MAX_SIZE: usize = Tpm2bAttest::MAX_SIZE + <Option<TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; CertifyRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.certify_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for CertifyRsp<'a> {
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

/// TPM2_CertifyCreation (Command)
#[doc(alias = "TPM2_CertifyCreation")]
#[doc(alias = "CertifyCreation_In")]
#[derive(Clone, Copy)]
pub struct CertifyCreation<'a> {
    pub sign_handle: EntityHandle<'a>,
    pub object_handle: ObjectHandle<'a>,
    pub qualifying_data: Tpm2bData<'a>,
    pub creation_hash: Tpm2bDigest<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub creation_ticket: TpmtTkCreation<'a>,
}
/// TPM2_CertifyCreation (Response)
#[doc(alias = "CertifyCreation_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct CertifyCreationRsp<'a> {
    pub certify_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for CertifyCreation<'_> {
    const CMD_CODE: TpmCc = TpmCc::CertifyCreation;
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = CertifyCreationRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.sign_handle, self.object_handle.into()]
    }
}
impl Marshal for CertifyCreation<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + <Option<TpmtSigScheme>>::MAX_SIZE
        + TpmtTkCreation::MAX_SIZE;
    type MaxBuffer = [u8; CertifyCreation::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        let count = marshal_helper(&self.creation_hash, dst, count);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.creation_ticket, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for CertifyCreation<'a> {
    fn unmarshal_with_handles(
        [sign_handle, object_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle,
            object_handle: object_handle.try_into()?,
            qualifying_data: Unmarshal::unmarshal(src)?,
            creation_hash: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
            creation_ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for CertifyCreationRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for CertifyCreationRsp<'_> {
    const MAX_SIZE: usize = Tpm2bAttest::MAX_SIZE + <Option<TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; CertifyCreationRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.certify_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for CertifyCreationRsp<'a> {
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

/// TPM2_Quote (Command)
#[doc(alias = "TPM2_Quote")]
#[doc(alias = "Quote_In")]
#[derive(Clone, Copy)]
pub struct Quote<'a> {
    pub sign_handle: EntityHandle<'a>,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub pcr_select: TpmlPcrSelection,
}
/// TPM2_Quote (Response)
#[doc(alias = "Quote_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct QuoteRsp<'a> {
    pub quoted: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for Quote<'_> {
    const CMD_CODE: TpmCc = TpmCc::Quote;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = QuoteRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.sign_handle]
    }
}
impl Marshal for Quote<'_> {
    const MAX_SIZE: usize =
        Tpm2bData::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE + TpmlPcrSelection::MAX_SIZE;
    type MaxBuffer = [u8; Quote::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.pcr_select, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for Quote<'a> {
    fn unmarshal_with_handles(
        [sign_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle,
            qualifying_data: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
            pcr_select: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for QuoteRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for QuoteRsp<'_> {
    const MAX_SIZE: usize = Tpm2bAttest::MAX_SIZE + <Option<TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; QuoteRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.quoted, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for QuoteRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            quoted: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_GetSessionAuditDigest (Command)
#[doc(alias = "TPM2_GetSessionAuditDigest")]
#[doc(alias = "GetSessionAuditDigest_In")]
#[derive(Clone, Copy)]
pub struct GetSessionAuditDigest<'a> {
    pub privacy_admin_handle: Handle,
    pub sign_handle: EntityHandle<'a>,
    pub session_handle: Handle,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
}
/// TPM2_GetSessionAuditDigest (Response)
#[doc(alias = "GetSessionAuditDigest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetSessionAuditDigestRsp<'a> {
    pub audit_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for GetSessionAuditDigest<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetSessionAuditDigest;
    type Handles<'a>
        = [EntityHandle<'a>; 3]
    where
        Self: 'a;
    type Response<'a> = GetSessionAuditDigestRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [
            EntityHandle::Handle(self.privacy_admin_handle),
            self.sign_handle,
            EntityHandle::Handle(self.session_handle),
        ]
    }
}
impl Marshal for GetSessionAuditDigest<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; GetSessionAuditDigest::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for GetSessionAuditDigest<'a> {
    fn unmarshal_with_handles(
        [privacy_admin_handle, sign_handle, session_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_admin_handle: privacy_admin_handle.try_into()?,
            sign_handle,
            session_handle: session_handle.try_into()?,
            qualifying_data: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for GetSessionAuditDigestRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for GetSessionAuditDigestRsp<'_> {
    const MAX_SIZE: usize = Tpm2bAttest::MAX_SIZE + <Option<TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; GetSessionAuditDigestRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.audit_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for GetSessionAuditDigestRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            audit_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_GetCommandAuditDigest (Command)
#[doc(alias = "TPM2_GetCommandAuditDigest")]
#[doc(alias = "GetCommandAuditDigest_In")]
#[derive(Clone, Copy)]
pub struct GetCommandAuditDigest<'a> {
    pub privacy_handle: Handle,
    pub sign_handle: EntityHandle<'a>,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
}
/// TPM2_GetCommandAuditDigest (Response)
#[doc(alias = "GetCommandAuditDigest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetCommandAuditDigestRsp<'a> {
    pub audit_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for GetCommandAuditDigest<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetCommandAuditDigest;
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = GetCommandAuditDigestRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.privacy_handle), self.sign_handle]
    }
}
impl Marshal for GetCommandAuditDigest<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; GetCommandAuditDigest::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for GetCommandAuditDigest<'a> {
    fn unmarshal_with_handles(
        [privacy_handle, sign_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_handle: privacy_handle.try_into()?,
            sign_handle,
            qualifying_data: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for GetCommandAuditDigestRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for GetCommandAuditDigestRsp<'_> {
    const MAX_SIZE: usize = Tpm2bAttest::MAX_SIZE + <Option<TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; GetCommandAuditDigestRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.audit_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for GetCommandAuditDigestRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            audit_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_GetTime (Command)
#[doc(alias = "TPM2_GetTime")]
#[doc(alias = "GetTime_In")]
#[derive(Clone, Copy)]
pub struct GetTime<'a> {
    pub privacy_admin_handle: Handle,
    pub sign_handle: EntityHandle<'a>,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
}
/// TPM2_GetTime (Response)
#[doc(alias = "GetTime_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetTimeRsp<'a> {
    pub time_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for GetTime<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetTime;
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = GetTimeRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [
            EntityHandle::Handle(self.privacy_admin_handle),
            self.sign_handle,
        ]
    }
}
impl Marshal for GetTime<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; GetTime::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for GetTime<'a> {
    fn unmarshal_with_handles(
        [privacy_admin_handle, sign_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_admin_handle: privacy_admin_handle.try_into()?,
            sign_handle,
            qualifying_data: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for GetTimeRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for GetTimeRsp<'_> {
    const MAX_SIZE: usize = Tpm2bAttest::MAX_SIZE + <Option<TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; GetTimeRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.time_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for GetTimeRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            time_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}
