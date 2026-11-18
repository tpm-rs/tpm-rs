//! TPM 2.0 Signing and Signature Verification Commands
//!
//! This module implements the "Signing and Signature Verification" commands defined in
//! **Section 20** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_VerifySignature (Command)
#[doc(alias = "TPM2_VerifySignature")]
#[doc(alias = "VerifySignature_In")]
#[deprecated]
#[derive(Clone, Copy)]
pub struct VerifySignature<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub digest: Tpm2bDigest<'a>,
    pub signature: TpmtSignature<'a>,
}
/// TPM2_VerifySignature (Response)
#[doc(alias = "VerifySignature_Out")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct VerifySignatureRsp<'a> {
    pub validation: TpmtTkVerified<'a>,
}

impl Command for VerifySignature<'_> {
    const CMD_CODE: TpmCc = TpmCc::VerifySignature;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = VerifySignatureRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for VerifySignature<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; VerifySignature::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.digest, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for VerifySignature<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            digest: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for VerifySignatureRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for VerifySignatureRsp<'_> {
    const MAX_SIZE: usize = TpmtTkVerified::MAX_SIZE;
    type MaxBuffer = [u8; VerifySignatureRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.validation.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for VerifySignatureRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Sign (Command)
#[doc(alias = "TPM2_Sign")]
#[doc(alias = "Sign_In")]
#[deprecated]
#[derive(Clone, Copy)]
pub struct Sign<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub digest: Tpm2bDigest<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub validation: TpmtTkHashcheck<'a>,
}
/// TPM2_Sign (Response)
#[doc(alias = "Sign_Out")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SignRsp<'a> {
    pub signature: TpmtSignature<'a>,
}

impl Command for Sign<'_> {
    const CMD_CODE: TpmCc = TpmCc::Sign;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = SignRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for Sign<'_> {
    const MAX_SIZE: usize =
        Tpm2bDigest::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE + TpmtTkHashcheck::MAX_SIZE;
    type MaxBuffer = [u8; Sign::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.digest, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.validation, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for Sign<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            digest: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for SignRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for SignRsp<'_> {
    const MAX_SIZE: usize = TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; SignRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.signature.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for SignRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_SignSequenceComplete (Command)
#[doc(alias = "TPM2_SignSequenceComplete")]
#[doc(alias = "SignSequenceComplete_In")]
#[derive(Clone, Copy)]
pub struct SignSequenceComplete<'a> {
    pub sequence_handle: SequenceHandle,
    pub key_handle: ObjectHandle<'a>,
    pub buffer: Tpm2bMaxBuffer<'a>,
}
/// TPM2_SignSequenceComplete (Response)
#[doc(alias = "SignSequenceComplete_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SignSequenceCompleteRsp<'a> {
    pub signature: TpmtSignature<'a>,
}

impl Command for SignSequenceComplete<'_> {
    const CMD_CODE: TpmCc = TpmCc::SignSequenceComplete;
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = SignSequenceCompleteRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.sequence_handle.into(), self.key_handle.into()]
    }
}
impl Marshal for SignSequenceComplete<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; SignSequenceComplete::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.buffer.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for SignSequenceComplete<'a> {
    fn unmarshal_with_handles(
        [sequence_handle, key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: sequence_handle.try_into()?,
            key_handle: key_handle.try_into()?,
            buffer: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for SignSequenceCompleteRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for SignSequenceCompleteRsp<'_> {
    const MAX_SIZE: usize = TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; SignSequenceCompleteRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.signature.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for SignSequenceCompleteRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_VerifySequenceComplete (Command)
#[doc(alias = "TPM2_VerifySequenceComplete")]
#[doc(alias = "VerifySequenceComplete_In")]
#[derive(Clone, Copy)]
pub struct VerifySequenceComplete<'a> {
    pub sequence_handle: SequenceHandle,
    pub key_handle: ObjectHandle<'a>,
    pub signature: TpmtSignature<'a>,
}
/// TPM2_VerifySequenceComplete (Response)
#[doc(alias = "VerifySequenceComplete_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct VerifySequenceCompleteRsp<'a> {
    pub validation: TpmtTkVerified<'a>,
}

impl Command for VerifySequenceComplete<'_> {
    const CMD_CODE: TpmCc = TpmCc::VerifySequenceComplete;
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = VerifySequenceCompleteRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.sequence_handle.into(), self.key_handle.into()]
    }
}
impl Marshal for VerifySequenceComplete<'_> {
    const MAX_SIZE: usize = TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; VerifySequenceComplete::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.signature.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for VerifySequenceComplete<'a> {
    fn unmarshal_with_handles(
        [sequence_handle, key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: sequence_handle.try_into()?,
            key_handle: key_handle.try_into()?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for VerifySequenceCompleteRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for VerifySequenceCompleteRsp<'_> {
    const MAX_SIZE: usize = TpmtTkVerified::MAX_SIZE;
    type MaxBuffer = [u8; VerifySequenceCompleteRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.validation.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for VerifySequenceCompleteRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_SignDigest (Command)
#[doc(alias = "TPM2_SignDigest")]
#[doc(alias = "SignDigest_In")]
#[derive(Clone, Copy)]
pub struct SignDigest<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub context: Tpm2bSignatureCtx<'a>,
    pub digest: Tpm2bDigest<'a>,
    pub validation: TpmtTkHashcheck<'a>,
}
/// TPM2_SignDigest (Response)
#[doc(alias = "SignDigest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SignDigestRsp<'a> {
    pub signature: TpmtSignature<'a>,
}

impl Command for SignDigest<'_> {
    const CMD_CODE: TpmCc = TpmCc::SignDigest;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = SignDigestRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for SignDigest<'_> {
    const MAX_SIZE: usize =
        Tpm2bSignatureCtx::MAX_SIZE + Tpm2bDigest::MAX_SIZE + TpmtTkHashcheck::MAX_SIZE;
    type MaxBuffer = [u8; SignDigest::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.context, dst, 0);
        let count = marshal_helper(&self.digest, dst, count);
        marshal_helper(&self.validation, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for SignDigest<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            context: Unmarshal::unmarshal(src)?,
            digest: Unmarshal::unmarshal(src)?,
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for SignDigestRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for SignDigestRsp<'_> {
    const MAX_SIZE: usize = TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; SignDigestRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.signature.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for SignDigestRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_VerifyDigestSignature (Command)
#[doc(alias = "TPM2_VerifyDigestSignature")]
#[doc(alias = "VerifyDigestSignature_In")]
#[derive(Clone, Copy)]
pub struct VerifyDigestSignature<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub context: Tpm2bSignatureCtx<'a>,
    pub digest: Tpm2bDigest<'a>,
    pub signature: TpmtSignature<'a>,
}
/// TPM2_VerifyDigestSignature (Response)
#[doc(alias = "VerifyDigestSignature_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct VerifyDigestSignatureRsp<'a> {
    pub validation: TpmtTkVerified<'a>,
}

impl Command for VerifyDigestSignature<'_> {
    const CMD_CODE: TpmCc = TpmCc::VerifyDigestSignature;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = VerifyDigestSignatureRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for VerifyDigestSignature<'_> {
    const MAX_SIZE: usize =
        Tpm2bSignatureCtx::MAX_SIZE + Tpm2bDigest::MAX_SIZE + TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; VerifyDigestSignature::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.context, dst, 0);
        let count = marshal_helper(&self.digest, dst, count);
        marshal_helper(&self.signature, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for VerifyDigestSignature<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            context: Unmarshal::unmarshal(src)?,
            digest: Unmarshal::unmarshal(src)?,
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for VerifyDigestSignatureRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for VerifyDigestSignatureRsp<'_> {
    const MAX_SIZE: usize = TpmtTkVerified::MAX_SIZE;
    type MaxBuffer = [u8; VerifyDigestSignatureRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.validation.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for VerifyDigestSignatureRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}
