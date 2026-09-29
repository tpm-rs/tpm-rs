//! TPM 2.0 Signing and Signature Verification Commands
//!
//! This module implements the "Signing and Signature Verification" commands defined in
//! **Section 20** of the TPM 2.0 Specification.
//!
//! These commands support verifying cryptographic signatures or producing a signature validation
//! ticket.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 20.2 TPM2_VerifySignature (Command)
#[doc(alias = "TPM2_VerifySignature")]
#[doc(alias = "VerifySignature_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct VerifySignature<'a> {
    pub digest: Tpm2bDigest<'a>,
    pub signature: TpmtSignature<'a>,
}

impl<'a> Marshal for VerifySignature<'a> {
    const MAX_SIZE: usize = <Tpm2bDigest>::MAX_SIZE + <TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; VerifySignature::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.digest, dst, 0);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for VerifySignature<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            digest: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            signature: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl<'a> Command for VerifySignature<'a> {
    const CMD_CODE: TpmCc = TpmCc::VerifySignature;
    type Handles = VerifySignatureHandles;
    type Response<'b> = VerifySignatureRsp<'b>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VerifySignatureHandles {
    pub key_handle: Handle,
}
impl Marshal for VerifySignatureHandles {
    const MAX_SIZE: usize = <Handle>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VerifySignatureHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 20.2 TPM2_VerifySignature (Response)
#[doc(alias = "VerifySignature_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct VerifySignatureRsp<'a> {
    pub validation: TpmtTkVerified<'a>,
}
impl Marshal for VerifySignatureRsp<'_> {
    const MAX_SIZE: usize = <TpmtTkVerified>::MAX_SIZE;
    type MaxBuffer = [u8; VerifySignatureRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.validation.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VerifySignatureRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 20.5 TPM2_Sign (Command)
#[doc(alias = "TPM2_Sign")]
#[doc(alias = "Sign_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct Sign<'a> {
    pub digest: Tpm2bDigest<'a>,
    pub in_scheme: Option<TpmtSigScheme>,
    pub validation: TpmtTkHashcheck<'a>,
}
impl Marshal for Sign<'_> {
    const MAX_SIZE: usize =
        <Tpm2bDigest>::MAX_SIZE + <Option<TpmtSigScheme>>::MAX_SIZE + <TpmtTkHashcheck>::MAX_SIZE;
    type MaxBuffer = [u8; Sign::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.digest, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.validation, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Sign<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            digest: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            validation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SignHandles {
    pub key_handle: Handle,
}
impl Marshal for SignHandles {
    const MAX_SIZE: usize = <Handle>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SignHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 20.5 TPM2_Sign (Response)
#[doc(alias = "Sign_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct SignRsp<'a> {
    pub signature: TpmtSignature<'a>,
}

impl<'a> Marshal for SignRsp<'a> {
    const MAX_SIZE: usize = <TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; SignRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.signature.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SignRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Sign<'_> {
    const CMD_CODE: TpmCc = TpmCc::Sign;
    type Handles = SignHandles;
    type Response<'a> = SignRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VerifySequenceCompleteHandles {
    pub sequence_handle: Handle,
    pub key_handle: Handle,
}

impl Marshal for VerifySequenceCompleteHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.sequence_handle, dst, 0);
        marshal_helper(&self.key_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for VerifySequenceCompleteHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 20.3 TPM2_VerifySequenceComplete (Command)
#[doc(alias = "TPM2_VerifySequenceComplete")]
#[doc(alias = "VerifySequenceComplete_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct VerifySequenceComplete<'a> {
    pub signature: TpmtSignature<'a>,
}

impl<'a> Marshal for VerifySequenceComplete<'a> {
    const MAX_SIZE: usize = <TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; VerifySequenceComplete::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.signature.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VerifySequenceComplete<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            signature: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 20.3 TPM2_VerifySequenceComplete (Response)
#[doc(alias = "VerifySequenceComplete_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct VerifySequenceCompleteRsp<'a> {
    pub validation: TpmtTkVerified<'a>,
}

impl Marshal for VerifySequenceCompleteRsp<'_> {
    const MAX_SIZE: usize = <TpmtTkVerified>::MAX_SIZE;
    type MaxBuffer = [u8; VerifySequenceCompleteRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.validation.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VerifySequenceCompleteRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

impl<'a> Command for VerifySequenceComplete<'a> {
    const CMD_CODE: TpmCc = TpmCc::VerifySequenceComplete;
    type Handles = VerifySequenceCompleteHandles;
    type Response<'b> = VerifySequenceCompleteRsp<'b>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VerifyDigestSignatureHandles {
    pub key_handle: Handle,
}

impl Marshal for VerifyDigestSignatureHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VerifyDigestSignatureHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 20.4 TPM2_VerifyDigestSignature (Command)
#[doc(alias = "TPM2_VerifyDigestSignature")]
#[doc(alias = "VerifyDigestSignature_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct VerifyDigestSignature<'a> {
    pub context: Tpm2bSignatureCtx<'a>,
    pub digest: Tpm2bDigest<'a>,
    pub signature: TpmtSignature<'a>,
}

impl<'a> Marshal for VerifyDigestSignature<'a> {
    const MAX_SIZE: usize =
        Tpm2bSignatureCtx::MAX_SIZE + Tpm2bDigest::MAX_SIZE + <TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; VerifyDigestSignature::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.context, dst, 0);
        let count = marshal_helper(&self.digest, dst, count);
        marshal_helper(&self.signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for VerifyDigestSignature<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            context: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            digest: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            signature: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 20.4 TPM2_VerifyDigestSignature (Response)
#[doc(alias = "VerifyDigestSignature_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct VerifyDigestSignatureRsp<'a> {
    pub validation: TpmtTkVerified<'a>,
}

impl Marshal for VerifyDigestSignatureRsp<'_> {
    const MAX_SIZE: usize = <TpmtTkVerified>::MAX_SIZE;
    type MaxBuffer = [u8; VerifyDigestSignatureRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.validation.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VerifyDigestSignatureRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

impl<'a> Command for VerifyDigestSignature<'a> {
    const CMD_CODE: TpmCc = TpmCc::VerifyDigestSignature;
    type Handles = VerifyDigestSignatureHandles;
    type Response<'b> = VerifyDigestSignatureRsp<'b>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SignSequenceCompleteHandles {
    pub sequence_handle: Handle,
    pub key_handle: Handle,
}

impl Marshal for SignSequenceCompleteHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.sequence_handle, dst, 0);
        marshal_helper(&self.key_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for SignSequenceCompleteHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 20.6 TPM2_SignSequenceComplete (Command)
#[doc(alias = "TPM2_SignSequenceComplete")]
#[doc(alias = "SignSequenceComplete_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct SignSequenceComplete<'a> {
    pub buffer: Tpm2bMaxBuffer<'a>,
}

impl Marshal for SignSequenceComplete<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; SignSequenceComplete::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.buffer.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SignSequenceComplete<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            buffer: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 20.6 TPM2_SignSequenceComplete (Response)
#[doc(alias = "SignSequenceComplete_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct SignSequenceCompleteRsp<'a> {
    pub signature: TpmtSignature<'a>,
}

impl<'a> Marshal for SignSequenceCompleteRsp<'a> {
    const MAX_SIZE: usize = <TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; SignSequenceCompleteRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.signature.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SignSequenceCompleteRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for SignSequenceComplete<'_> {
    const CMD_CODE: TpmCc = TpmCc::SignSequenceComplete;
    type Handles = SignSequenceCompleteHandles;
    type Response<'a> = SignSequenceCompleteRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SignDigestHandles {
    pub key_handle: Handle,
}

impl Marshal for SignDigestHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SignDigestHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 20.7 TPM2_SignDigest (Command)
#[doc(alias = "TPM2_SignDigest")]
#[doc(alias = "SignDigest_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct SignDigest<'a> {
    pub context: Tpm2bSignatureCtx<'a>,
    pub digest: Tpm2bDigest<'a>,
    pub validation: TpmtTkHashcheck<'a>,
}

impl Marshal for SignDigest<'_> {
    const MAX_SIZE: usize =
        Tpm2bSignatureCtx::MAX_SIZE + Tpm2bDigest::MAX_SIZE + <TpmtTkHashcheck>::MAX_SIZE;
    type MaxBuffer = [u8; SignDigest::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.context, dst, 0);
        let count = marshal_helper(&self.digest, dst, count);
        marshal_helper(&self.validation, dst, count)
    }
}

impl<'a> Unmarshal<'a> for SignDigest<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            context: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            digest: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            validation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 20.7 TPM2_SignDigest (Response)
#[doc(alias = "SignDigest_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct SignDigestRsp<'a> {
    pub signature: TpmtSignature<'a>,
}

impl<'a> Marshal for SignDigestRsp<'a> {
    const MAX_SIZE: usize = <TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; SignDigestRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.signature.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SignDigestRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            signature: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for SignDigest<'_> {
    const CMD_CODE: TpmCc = TpmCc::SignDigest;
    type Handles = SignDigestHandles;
    type Response<'a> = SignDigestRsp<'a>;
    type RespHandles = ();
}
