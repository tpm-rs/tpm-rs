//! TPM 2.0 Asymmetric Primitives Commands
//!
//! This module implements the "Asymmetric Primitives" commands defined in
//! **Section 14** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_ECDH_KeyGen (Command)
#[doc(alias = "TPM2_ECDH_KeyGen")]
#[doc(alias = "ECDH_KeyGen_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECDHKeyGen {
    pub key_handle: Handle,
}
/// TPM2_ECDH_KeyGen (Response)
#[doc(alias = "ECDH_KeyGen_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECDHKeyGenRsp<'a> {
    pub z_point: Tpm2bEccPoint<'a>,
    pub pub_point: Tpm2bEccPoint<'a>,
}

impl Command for ECDHKeyGen {
    const CMD_CODE: TpmCc = TpmCc::ECDHKeyGen;
    type Response<'a> = ECDHKeyGenRsp<'a>;
}
impl Message for ECDHKeyGen {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.key_handle]
    }
}
impl Marshal for ECDHKeyGen {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for ECDHKeyGen {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { key_handle })
    }
}

impl Message for ECDHKeyGenRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ECDHKeyGenRsp<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE + Tpm2bEccPoint::MAX_SIZE;
    type MaxBuffer = [u8; ECDHKeyGenRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.z_point, dst, 0);
        marshal_helper(&self.pub_point, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for ECDHKeyGenRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            z_point: Unmarshal::unmarshal(src)?,
            pub_point: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ECDH_ZGen (Command)
#[doc(alias = "TPM2_ECDH_ZGen")]
#[doc(alias = "ECDH_ZGen_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECDHZGen<'a> {
    pub key_handle: Handle,
    pub in_point: Tpm2bEccPoint<'a>,
}
/// TPM2_ECDH_ZGen (Response)
#[doc(alias = "ECDH_ZGen_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECDHZGenRsp<'a> {
    pub out_point: Tpm2bEccPoint<'a>,
}

impl Command for ECDHZGen<'_> {
    const CMD_CODE: TpmCc = TpmCc::ECDHZGen;
    type Response<'a> = ECDHZGenRsp<'a>;
}
impl Message for ECDHZGen<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.key_handle]
    }
}
impl Marshal for ECDHZGen<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE;
    type MaxBuffer = [u8; ECDHZGen::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.in_point.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ECDHZGen<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle,
            in_point: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for ECDHZGenRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ECDHZGenRsp<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE;
    type MaxBuffer = [u8; ECDHZGenRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_point.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ECDHZGenRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_point: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ECC_Parameters (Command)
#[doc(alias = "TPM2_ECC_Parameters")]
#[doc(alias = "ECC_Parameters_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECCParameters {
    pub curve_id: TpmEccCurve,
}
/// TPM2_ECC_Parameters (Response)
#[doc(alias = "ECC_Parameters_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECCParametersRsp<'a> {
    pub parameters: TpmsAlgorithmDetailEcc<'a>,
}

impl Command for ECCParameters {
    const CMD_CODE: TpmCc = TpmCc::ECCParameters;
    type Response<'a> = ECCParametersRsp<'a>;
}
impl Message for ECCParameters {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ECCParameters {
    const MAX_SIZE: usize = TpmEccCurve::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.curve_id.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ECCParameters {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            curve_id: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for ECCParametersRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ECCParametersRsp<'_> {
    const MAX_SIZE: usize = TpmsAlgorithmDetailEcc::MAX_SIZE;
    type MaxBuffer = [u8; ECCParametersRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.parameters.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ECCParametersRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parameters: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ECC_Encrypt (Command)
#[doc(alias = "TPM2_ECC_Encrypt")]
#[doc(alias = "ECC_Encrypt_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECCEncrypt<'a> {
    pub key_handle: Handle,
    pub plain_text: Tpm2bMaxBuffer<'a>,
    pub in_scheme: Option<TpmtKdfScheme>,
}
/// TPM2_ECC_Encrypt (Response)
#[doc(alias = "ECC_Encrypt_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECCEncryptRsp<'a> {
    pub c1: Tpm2bEccPoint<'a>,
    pub c2: Tpm2bMaxBuffer<'a>,
    pub c3: Tpm2bDigest<'a>,
}

impl Command for ECCEncrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::ECCEncrypt;
    type Response<'a> = ECCEncryptRsp<'a>;
}
impl Message for ECCEncrypt<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.key_handle]
    }
}
impl Marshal for ECCEncrypt<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmtKdfScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; ECCEncrypt::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.plain_text, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for ECCEncrypt<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle,
            plain_text: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for ECCEncryptRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ECCEncryptRsp<'_> {
    const MAX_SIZE: usize =
        Tpm2bEccPoint::MAX_SIZE + Tpm2bMaxBuffer::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; ECCEncryptRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.c1, dst, 0);
        let count = marshal_helper(&self.c2, dst, count);
        marshal_helper(&self.c3, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for ECCEncryptRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            c1: Unmarshal::unmarshal(src)?,
            c2: Unmarshal::unmarshal(src)?,
            c3: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ECC_Decrypt (Command)
#[doc(alias = "TPM2_ECC_Decrypt")]
#[doc(alias = "ECC_Decrypt_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECCDecrypt<'a> {
    pub key_handle: Handle,
    pub c1: Tpm2bEccPoint<'a>,
    pub c2: Tpm2bMaxBuffer<'a>,
    pub c3: Tpm2bDigest<'a>,
    pub in_scheme: Option<TpmtKdfScheme>,
}
/// TPM2_ECC_Decrypt (Response)
#[doc(alias = "ECC_Decrypt_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECCDecryptRsp<'a> {
    pub plain_text: Tpm2bMaxBuffer<'a>,
}

impl Command for ECCDecrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::ECCDecrypt;
    type Response<'a> = ECCDecryptRsp<'a>;
}
impl Message for ECCDecrypt<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.key_handle]
    }
}
impl Marshal for ECCDecrypt<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE
        + Tpm2bMaxBuffer::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + <Option<TpmtKdfScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; ECCDecrypt::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.c1, dst, 0);
        let count = marshal_helper(&self.c2, dst, count);
        let count = marshal_helper(&self.c3, dst, count);
        marshal_helper(&self.in_scheme, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for ECCDecrypt<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle,
            c1: Unmarshal::unmarshal(src)?,
            c2: Unmarshal::unmarshal(src)?,
            c3: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for ECCDecryptRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ECCDecryptRsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; ECCDecryptRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.plain_text.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ECCDecryptRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            plain_text: Unmarshal::unmarshal(src)?,
        })
    }
}
