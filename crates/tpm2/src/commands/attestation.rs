//! TPM 2.0 Attestation Commands
//!
//! This module implements the "Attestation Commands" commands defined in
//! **Section 18** of the TPM 2.0 Specification.
//!
//! These commands provide a mechanism for the TPM to sign assertions about internal TPM
//! objects, keys, session status, or clock info (attestation).
//!
//! Each command includes its request (handles first, then parameters), its
//! response, and the [`Command`] / [`Message`] / [`UnmarshalMessage`] trait
//! implementations.
#![allow(deprecated)] // So we can define the now-deprecated CertifyX509 / impls.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 18.2 TPM2_Certify (Command)
#[doc(alias = "TPM2_Certify")]
#[doc(alias = "Certify_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Certify<'a> {
    pub object_handle: Handle,
    pub sign_handle: Handle,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
}
/// [TPM2.0 1.83] 18.2 TPM2_Certify (Response)
#[doc(alias = "Certify_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct CertifyRsp<'a> {
    pub certify_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for Certify<'_> {
    const CMD_CODE: TpmCc = TpmCc::Certify;
    type Response<'a> = CertifyRsp<'a>;
}
impl Message for Certify<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.object_handle, self.sign_handle]
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
impl<'a> UnmarshalMessage<'a> for Certify<'a> {
    fn unmarshal_with_handles(
        [object_handle, sign_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle,
            sign_handle,
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Message for CertifyRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for CertifyRsp<'a> {
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

/// [TPM2.0 1.83] 18.3 TPM2_CertifyCreation (Command)
#[doc(alias = "TPM2_CertifyCreation")]
#[doc(alias = "CertifyCreation_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct CertifyCreation<'a> {
    pub sign_handle: Handle,
    pub object_handle: Handle,
    pub qualifying_data: Tpm2bData<'a>,
    pub creation_hash: Tpm2bDigest<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub creation_ticket: TpmtTkCreation<'a>,
}
/// [TPM2.0 1.83] 18.3 TPM2_CertifyCreation (Response)
#[doc(alias = "CertifyCreation_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct CertifyCreationRsp<'a> {
    pub certify_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for CertifyCreation<'_> {
    const CMD_CODE: TpmCc = TpmCc::CertifyCreation;
    type Response<'a> = CertifyCreationRsp<'a>;
}
impl Message for CertifyCreation<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.sign_handle, self.object_handle]
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
impl<'a> UnmarshalMessage<'a> for CertifyCreation<'a> {
    fn unmarshal_with_handles(
        [sign_handle, object_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle,
            object_handle,
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            creation_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            creation_ticket: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

impl Message for CertifyCreationRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for CertifyCreationRsp<'a> {
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

/// [TPM2.0 1.83] 18.4 TPM2_Quote (Command)
#[doc(alias = "TPM2_Quote")]
#[doc(alias = "Quote_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Quote<'a> {
    pub sign_handle: Handle,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub pcr_select: TpmlPcrSelection,
}
/// [TPM2.0 1.83] 18.4 TPM2_Quote (Response)
#[doc(alias = "Quote_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct QuoteRsp<'a> {
    pub quoted: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for Quote<'_> {
    const CMD_CODE: TpmCc = TpmCc::Quote;
    type Response<'a> = QuoteRsp<'a>;
}
impl Message for Quote<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
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
impl<'a> UnmarshalMessage<'a> for Quote<'a> {
    fn unmarshal_with_handles(
        [sign_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle,
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            pcr_select: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

impl Message for QuoteRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for QuoteRsp<'a> {
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

/// [TPM2.0 1.83] 18.5 TPM2_GetSessionAuditDigest (Command)
#[doc(alias = "TPM2_GetSessionAuditDigest")]
#[doc(alias = "GetSessionAuditDigest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetSessionAuditDigest<'a> {
    pub privacy_admin_handle: Handle,
    pub sign_handle: Handle,
    pub session_handle: Handle,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
}
/// [TPM2.0 1.83] 18.5 TPM2_GetSessionAuditDigest (Response)
#[doc(alias = "GetSessionAuditDigest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetSessionAuditDigestRsp<'a> {
    pub audit_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for GetSessionAuditDigest<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetSessionAuditDigest;
    type Response<'a> = GetSessionAuditDigestRsp<'a>;
}
impl Message for GetSessionAuditDigest<'_> {
    type Handles = [Handle; 3];
    fn handles(&self) -> Self::Handles {
        [
            self.privacy_admin_handle,
            self.sign_handle,
            self.session_handle,
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
impl<'a> UnmarshalMessage<'a> for GetSessionAuditDigest<'a> {
    fn unmarshal_with_handles(
        [privacy_admin_handle, sign_handle, session_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_admin_handle,
            sign_handle,
            session_handle,
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Message for GetSessionAuditDigestRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for GetSessionAuditDigestRsp<'a> {
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

/// [TPM2.0 1.83] 18.6 TPM2_GetCommandAuditDigest (Command)
#[doc(alias = "TPM2_GetCommandAuditDigest")]
#[doc(alias = "GetCommandAuditDigest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetCommandAuditDigest<'a> {
    pub privacy_handle: Handle,
    pub sign_handle: Handle,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
}
/// [TPM2.0 1.83] 18.6 TPM2_GetCommandAuditDigest (Response)
#[doc(alias = "GetCommandAuditDigest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetCommandAuditDigestRsp<'a> {
    pub audit_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for GetCommandAuditDigest<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetCommandAuditDigest;
    type Response<'a> = GetCommandAuditDigestRsp<'a>;
}
impl Message for GetCommandAuditDigest<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.privacy_handle, self.sign_handle]
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
impl<'a> UnmarshalMessage<'a> for GetCommandAuditDigest<'a> {
    fn unmarshal_with_handles(
        [privacy_handle, sign_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_handle,
            sign_handle,
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Message for GetCommandAuditDigestRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for GetCommandAuditDigestRsp<'a> {
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

/// [TPM2.0 1.83] 18.7 TPM2_GetTime (Command)
#[doc(alias = "TPM2_GetTime")]
#[doc(alias = "GetTime_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetTime<'a> {
    pub privacy_admin_handle: Handle,
    pub sign_handle: Handle,
    pub qualifying_data: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
}
/// [TPM2.0 1.83] 18.7 TPM2_GetTime (Response)
#[doc(alias = "GetTime_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetTimeRsp<'a> {
    pub time_info: Tpm2bAttest<'a>,
    pub signature: Option<TpmtSignature<'a>>,
}

impl Command for GetTime<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetTime;
    type Response<'a> = GetTimeRsp<'a>;
}
impl Message for GetTime<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.privacy_admin_handle, self.sign_handle]
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
impl<'a> UnmarshalMessage<'a> for GetTime<'a> {
    fn unmarshal_with_handles(
        [privacy_admin_handle, sign_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_admin_handle,
            sign_handle,
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Message for GetTimeRsp<'_> {
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
impl<'a> UnmarshalMessage<'a> for GetTimeRsp<'a> {
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

/// [TPM2.0 1.83] 18.8 TPM2_CertifyX509 (Command)
#[doc(alias = "TPM2_CertifyX509")]
#[doc(alias = "CertifyX509_In")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct CertifyX509<'a> {
    pub object_handle: Handle,
    pub sign_handle: Handle,
    pub reserved: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub partial_certificate: Tpm2bMaxBuffer<'a>,
}
/// [TPM2.0 1.83] 18.8 TPM2_CertifyX509 (Response)
#[doc(alias = "CertifyX509_Out")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct CertifyX509Rsp<'a> {
    pub added_to_certificate: Tpm2bMaxBuffer<'a>,
    pub tbs_digest: Tpm2bDigest<'a>,
    pub signature: TpmtSignature<'a>,
}

impl Command for CertifyX509<'_> {
    const CMD_CODE: TpmCc = TpmCc::CertifyX509;
    type Response<'a> = CertifyX509Rsp<'a>;
}
impl Message for CertifyX509<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.object_handle, self.sign_handle]
    }
}
impl Marshal for CertifyX509<'_> {
    const MAX_SIZE: usize =
        Tpm2bData::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE + Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; CertifyX509::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.reserved, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.partial_certificate, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for CertifyX509<'a> {
    fn unmarshal_with_handles(
        [object_handle, sign_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle,
            sign_handle,
            reserved: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            partial_certificate: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

impl Message for CertifyX509Rsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for CertifyX509Rsp<'_> {
    const MAX_SIZE: usize =
        Tpm2bMaxBuffer::MAX_SIZE + Tpm2bDigest::MAX_SIZE + TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; CertifyX509Rsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.added_to_certificate, dst, 0);
        let count = marshal_helper(&self.tbs_digest, dst, count);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for CertifyX509Rsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            added_to_certificate: Unmarshal::unmarshal(src)?,
            tbs_digest: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}
