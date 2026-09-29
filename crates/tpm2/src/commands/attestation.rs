//! TPM 2.0 Attestation Commands
//!
//! This module implements the "Attestation Commands" defined in
//! **Section 18** of the TPM 2.0 Specification.
//!
//! These commands provide a mechanism for the TPM to sign assertions about internal TPM
//! objects, keys, session status, or clock info (attestation).
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct CertifyHandles {
    pub object_handle: Handle,
    pub sign_handle: Handle,
}
impl Marshal for CertifyHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.object_handle, dst, 0);
        marshal_helper(&self.sign_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CertifyHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            sign_handle: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 18.2 TPM2_Certify (Command)
#[doc(alias = "TPM2_Certify")]
#[doc(alias = "Certify_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Certify<'a> {
    pub qualifying_data: crate::Tpm2bData<'a>,
    pub in_scheme: Option<crate::TpmtSigScheme>,
}
impl Marshal for Certify<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE + <Option<crate::TpmtSigScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; Certify::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Certify<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 18.2 TPM2_Certify (Response)
#[doc(alias = "Certify_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CertifyRsp<'a> {
    pub certify_info: crate::Tpm2bAttest<'a>,
    pub signature: Option<crate::TpmtSignature<'a>>,
}

impl<'a> Marshal for CertifyRsp<'a> {
    const MAX_SIZE: usize =
        <crate::Tpm2bAttest>::MAX_SIZE + <Option<crate::TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; CertifyRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.certify_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CertifyRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            certify_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Certify<'_> {
    const CMD_CODE: TpmCc = TpmCc::Certify;
    type Handles = CertifyHandles;
    type Response<'a> = CertifyRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct CertifyCreationHandles {
    pub sign_handle: Handle,
    pub object_handle: Handle,
}
impl Marshal for CertifyCreationHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.sign_handle, dst, 0);
        marshal_helper(&self.object_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CertifyCreationHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            object_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 18.3 TPM2_CertifyCreation (Command)
#[doc(alias = "TPM2_CertifyCreation")]
#[doc(alias = "CertifyCreation_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CertifyCreation<'a> {
    pub qualifying_data: crate::Tpm2bData<'a>,
    pub creation_hash: crate::Tpm2bDigest<'a>,
    pub in_scheme: Option<crate::TpmtSigScheme>,
    pub creation_ticket: crate::TpmtTkCreation<'a>,
}
impl Marshal for CertifyCreation<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE
        + <crate::Tpm2bDigest>::MAX_SIZE
        + <Option<crate::TpmtSigScheme>>::MAX_SIZE
        + <crate::TpmtTkCreation>::MAX_SIZE;
    type MaxBuffer = [u8; CertifyCreation::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        let count = marshal_helper(&self.creation_hash, dst, count);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.creation_ticket, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CertifyCreation<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            creation_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            creation_ticket: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

/// [TPM2.0 1.83] 18.3 TPM2_CertifyCreation (Response)
#[doc(alias = "CertifyCreation_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CertifyCreationRsp<'a> {
    pub certify_info: crate::Tpm2bAttest<'a>,
    pub signature: Option<crate::TpmtSignature<'a>>,
}

impl<'a> Marshal for CertifyCreationRsp<'a> {
    const MAX_SIZE: usize =
        <crate::Tpm2bAttest>::MAX_SIZE + <Option<crate::TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; CertifyCreationRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.certify_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CertifyCreationRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            certify_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for CertifyCreation<'_> {
    const CMD_CODE: TpmCc = TpmCc::CertifyCreation;
    type Handles = CertifyCreationHandles;
    type Response<'a> = CertifyCreationRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Default, Debug, Eq)]
pub struct QuoteHandles {
    pub sign_handle: Handle,
}
impl Marshal for QuoteHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sign_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for QuoteHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 18.4 TPM2_Quote (Command)
#[doc(alias = "TPM2_Quote")]
#[doc(alias = "Quote_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Quote<'a> {
    pub qualifying_data: crate::Tpm2bData<'a>,
    pub in_scheme: Option<crate::TpmtSigScheme>,
    pub pcr_select: crate::TpmlPcrSelection,
}
impl Marshal for Quote<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE
        + <Option<crate::TpmtSigScheme>>::MAX_SIZE
        + <crate::TpmlPcrSelection>::MAX_SIZE;
    type MaxBuffer = [u8; Quote::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.pcr_select, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Quote<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            pcr_select: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 18.4 TPM2_Quote (Response)
#[doc(alias = "Quote_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct QuoteRsp<'a> {
    pub quoted: crate::Tpm2bAttest<'a>,
    pub signature: Option<crate::TpmtSignature<'a>>,
}

impl<'a> Marshal for QuoteRsp<'a> {
    const MAX_SIZE: usize =
        <crate::Tpm2bAttest>::MAX_SIZE + <Option<crate::TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; QuoteRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.quoted, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for QuoteRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            quoted: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Quote<'_> {
    const CMD_CODE: TpmCc = TpmCc::Quote;
    type Handles = QuoteHandles;
    type Response<'a> = QuoteRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetSessionAuditDigestHandles {
    pub privacy_admin_handle: Handle,
    pub sign_handle: Handle,
    pub session_handle: Handle,
}
impl Marshal for GetSessionAuditDigestHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.privacy_admin_handle, dst, 0);
        let count = marshal_helper(&self.sign_handle, dst, count);
        marshal_helper(&self.session_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetSessionAuditDigestHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_admin_handle: TpmiRhEndorsement::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            sign_handle: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
            session_handle: TpmiShHmac::unmarshal(src).map_err(|e| e.in_handle(3))?.0,
        })
    }
}

/// [TPM2.0 1.83] 18.5 TPM2_GetSessionAuditDigest (Command)
#[doc(alias = "TPM2_GetSessionAuditDigest")]
#[doc(alias = "GetSessionAuditDigest_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct GetSessionAuditDigest<'a> {
    pub qualifying_data: crate::Tpm2bData<'a>,
    pub in_scheme: Option<crate::TpmtSigScheme>,
}
impl Marshal for GetSessionAuditDigest<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE + <Option<crate::TpmtSigScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; GetSessionAuditDigest::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetSessionAuditDigest<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 18.5 TPM2_GetSessionAuditDigest (Response)
#[doc(alias = "GetSessionAuditDigest_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct GetSessionAuditDigestRsp<'a> {
    pub audit_info: crate::Tpm2bAttest<'a>,
    pub signature: Option<crate::TpmtSignature<'a>>,
}

impl<'a> Marshal for GetSessionAuditDigestRsp<'a> {
    const MAX_SIZE: usize =
        <crate::Tpm2bAttest>::MAX_SIZE + <Option<crate::TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; GetSessionAuditDigestRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.audit_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetSessionAuditDigestRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            audit_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for GetSessionAuditDigest<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetSessionAuditDigest;
    type Handles = GetSessionAuditDigestHandles;
    type Response<'a> = GetSessionAuditDigestRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetCommandAuditDigestHandles {
    pub privacy_admin_handle: Handle,
    pub sign_handle: Handle,
}
impl Marshal for GetCommandAuditDigestHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.privacy_admin_handle, dst, 0);
        marshal_helper(&self.sign_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetCommandAuditDigestHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_admin_handle: TpmiRhEndorsement::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            sign_handle: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 18.6 TPM2_GetCommandAuditDigest (Command)
#[doc(alias = "TPM2_GetCommandAuditDigest")]
#[doc(alias = "GetCommandAuditDigest_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct GetCommandAuditDigest<'a> {
    pub qualifying_data: crate::Tpm2bData<'a>,
    pub in_scheme: Option<crate::TpmtSigScheme>,
}
impl Marshal for GetCommandAuditDigest<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE + <Option<crate::TpmtSigScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; GetCommandAuditDigest::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetCommandAuditDigest<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 18.6 TPM2_GetCommandAuditDigest (Response)
#[doc(alias = "GetCommandAuditDigest_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct GetCommandAuditDigestRsp<'a> {
    pub audit_info: crate::Tpm2bAttest<'a>,
    pub signature: Option<crate::TpmtSignature<'a>>,
}

impl<'a> Marshal for GetCommandAuditDigestRsp<'a> {
    const MAX_SIZE: usize =
        <crate::Tpm2bAttest>::MAX_SIZE + <Option<crate::TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; GetCommandAuditDigestRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.audit_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetCommandAuditDigestRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            audit_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for GetCommandAuditDigest<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetCommandAuditDigest;
    type Handles = GetCommandAuditDigestHandles;
    type Response<'a> = GetCommandAuditDigestRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetTimeHandles {
    pub privacy_admin_handle: Handle,
    pub sign_handle: Handle,
}
impl Marshal for GetTimeHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.privacy_admin_handle, dst, 0);
        marshal_helper(&self.sign_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetTimeHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            privacy_admin_handle: TpmiRhEndorsement::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            sign_handle: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 18.7 TPM2_GetTime (Command)
#[doc(alias = "TPM2_GetTime")]
#[doc(alias = "GetTime_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct GetTime<'a> {
    pub qualifying_data: crate::Tpm2bData<'a>,
    pub in_scheme: Option<crate::TpmtSigScheme>,
}
impl Marshal for GetTime<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE + <Option<crate::TpmtSigScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; GetTime::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.qualifying_data, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetTime<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            qualifying_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 18.7 TPM2_GetTime (Response)
#[doc(alias = "GetTime_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct GetTimeRsp<'a> {
    pub time_info: crate::Tpm2bAttest<'a>,
    pub signature: Option<crate::TpmtSignature<'a>>,
}

impl<'a> Marshal for GetTimeRsp<'a> {
    const MAX_SIZE: usize =
        <crate::Tpm2bAttest>::MAX_SIZE + <Option<crate::TpmtSignature>>::MAX_SIZE;
    type MaxBuffer = [u8; GetTimeRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.time_info, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetTimeRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            time_info: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for GetTime<'_> {
    const CMD_CODE: TpmCc = TpmCc::GetTime;
    type Handles = GetTimeHandles;
    type Response<'a> = GetTimeRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct CertifyX509Handles {
    pub object_handle: Handle,
    pub sign_handle: Handle,
}

impl Marshal for CertifyX509Handles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.object_handle, dst, 0);
        marshal_helper(&self.sign_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CertifyX509Handles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            sign_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 18.8 TPM2_CertifyX509 (Command)
#[doc(alias = "TPM2_CertifyX509")]
#[doc(alias = "CertifyX509_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CertifyX509<'a> {
    pub reserved: Tpm2bData<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub partial_certificate: Tpm2bMaxBuffer<'a>,
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

impl<'a> Unmarshal<'a> for CertifyX509<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            reserved: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            partial_certificate: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 18.8 TPM2_CertifyX509 (Response)
#[doc(alias = "CertifyX509_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct CertifyX509Rsp<'a> {
    pub added_to_certificate: Tpm2bMaxBuffer<'a>,
    pub tbs_digest: Tpm2bDigest<'a>,
    pub signature: TpmtSignature<'a>,
}

impl<'a> Marshal for CertifyX509Rsp<'a> {
    const MAX_SIZE: usize =
        Tpm2bMaxBuffer::MAX_SIZE + Tpm2bDigest::MAX_SIZE + <TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; CertifyX509Rsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.added_to_certificate, dst, 0);
        let count = marshal_helper(&self.tbs_digest, dst, count);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CertifyX509Rsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            added_to_certificate: Unmarshal::unmarshal(src)?,
            tbs_digest: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for CertifyX509<'_> {
    const CMD_CODE: TpmCc = TpmCc::CertifyX509;
    type Handles = CertifyX509Handles;
    type Response<'a> = CertifyX509Rsp<'a>;
    type RespHandles = ();
}
