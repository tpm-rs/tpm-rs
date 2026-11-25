//! TPM 2.0 Asymmetric Primitives Commands
//!
//! This module implements the "Asymmetric Primitives" commands defined in
//! **Section 14** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_RSA_Encrypt (Command)
#[doc(alias = "TPM2_RSA_Encrypt")]
#[doc(alias = "RSA_Encrypt_In")]
#[derive(Clone, Copy)]
pub struct RSAEncrypt<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub message: Tpm2bPublicKeyRsa<'a>,
    pub in_scheme: Option<TpmtRsaDecrypt>,
    pub label: Tpm2bData<'a>,
}
/// TPM2_RSA_Encrypt (Response)
#[doc(alias = "RSA_Encrypt_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct RSAEncryptRsp<'a> {
    pub out_data: Tpm2bPublicKeyRsa<'a>,
}

impl Command for RSAEncrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::RSAEncrypt;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = RSAEncryptRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for RSAEncrypt<'_> {
    const MAX_SIZE: usize =
        Tpm2bPublicKeyRsa::MAX_SIZE + <Option<TpmtRsaDecrypt>>::MAX_SIZE + Tpm2bData::MAX_SIZE;
    type MaxBuffer = [u8; RSAEncrypt::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.message, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.label, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for RSAEncrypt<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            message: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
            label: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for RSAEncryptRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for RSAEncryptRsp<'_> {
    const MAX_SIZE: usize = Tpm2bPublicKeyRsa::MAX_SIZE;
    type MaxBuffer = [u8; RSAEncryptRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_data.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for RSAEncryptRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_RSA_Decrypt (Command)
#[doc(alias = "TPM2_RSA_Decrypt")]
#[doc(alias = "RSA_Decrypt_In")]
#[derive(Clone, Copy)]
pub struct RSADecrypt<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub cipher_text: Tpm2bPublicKeyRsa<'a>,
    pub in_scheme: Option<TpmtRsaDecrypt>,
    pub label: Tpm2bData<'a>,
}
/// TPM2_RSA_Decrypt (Response)
#[doc(alias = "RSA_Decrypt_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct RSADecryptRsp<'a> {
    pub message: Tpm2bPublicKeyRsa<'a>,
}

impl Command for RSADecrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::RSADecrypt;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = RSADecryptRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for RSADecrypt<'_> {
    const MAX_SIZE: usize =
        Tpm2bPublicKeyRsa::MAX_SIZE + <Option<TpmtRsaDecrypt>>::MAX_SIZE + Tpm2bData::MAX_SIZE;
    type MaxBuffer = [u8; RSADecrypt::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.cipher_text, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.label, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for RSADecrypt<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            cipher_text: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
            label: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for RSADecryptRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for RSADecryptRsp<'_> {
    const MAX_SIZE: usize = Tpm2bPublicKeyRsa::MAX_SIZE;
    type MaxBuffer = [u8; RSADecryptRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.message.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for RSADecryptRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            message: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ECDH_KeyGen (Command)
#[doc(alias = "TPM2_ECDH_KeyGen")]
#[doc(alias = "ECDH_KeyGen_In")]
#[derive(Clone, Copy)]
pub struct ECDHKeyGen<'a> {
    pub key_handle: ObjectHandle<'a>,
}
/// TPM2_ECDH_KeyGen (Response)
#[doc(alias = "ECDH_KeyGen_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECDHKeyGenRsp<'a> {
    pub z_point: Tpm2bEccPoint<'a>,
    pub pub_point: Tpm2bEccPoint<'a>,
}

impl Command for ECDHKeyGen<'_> {
    const CMD_CODE: TpmCc = TpmCc::ECDHKeyGen;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ECDHKeyGenRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for ECDHKeyGen<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for ECDHKeyGen<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
        })
    }
}

impl Response for ECDHKeyGenRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for ECDHKeyGenRsp<'a> {
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
#[derive(Clone, Copy)]
pub struct ECDHZGen<'a> {
    pub key_handle: ObjectHandle<'a>,
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
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ECDHZGenRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for ECDHZGen<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE;
    type MaxBuffer = [u8; ECDHZGen::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.in_point.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for ECDHZGen<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            in_point: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for ECDHZGenRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for ECDHZGenRsp<'a> {
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
    type Handles<'a>
        = [EntityHandle<'a>; 0]
    where
        Self: 'a;
    type Response<'a> = ECCParametersRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
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
impl<'a> UnmarshalCommand<'a> for ECCParameters {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            curve_id: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for ECCParametersRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for ECCParametersRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parameters: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ZGen_2Phase (Command)
#[doc(alias = "TPM2_ZGen_2Phase")]
#[doc(alias = "ZGen_2Phase_In")]
#[derive(Clone, Copy)]
pub struct ZGen2Phase<'a> {
    pub key_a: ObjectHandle<'a>,
    pub in_qs_b: Tpm2bEccPoint<'a>,
    pub in_qe_b: Tpm2bEccPoint<'a>,
    pub in_scheme: TpmiEccKeyExchange,
    pub counter: u16,
}
/// TPM2_ZGen_2Phase (Response)
#[doc(alias = "ZGen_2Phase_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ZGen2PhaseRsp<'a> {
    pub out_z1: Tpm2bEccPoint<'a>,
    pub out_z2: Tpm2bEccPoint<'a>,
}

impl Command for ZGen2Phase<'_> {
    const CMD_CODE: TpmCc = TpmCc::ZGen2Phase;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ZGen2PhaseRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_a.into()]
    }
}
impl Marshal for ZGen2Phase<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE
        + Tpm2bEccPoint::MAX_SIZE
        + TpmiEccKeyExchange::MAX_SIZE
        + u16::MAX_SIZE;
    type MaxBuffer = [u8; ZGen2Phase::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_qs_b, dst, 0);
        let count = marshal_helper(&self.in_qe_b, dst, count);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.counter, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for ZGen2Phase<'a> {
    fn unmarshal_with_handles(
        [key_a]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_a: key_a.try_into()?,
            in_qs_b: Unmarshal::unmarshal(src)?,
            in_qe_b: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
            counter: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for ZGen2PhaseRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ZGen2PhaseRsp<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE + Tpm2bEccPoint::MAX_SIZE;
    type MaxBuffer = [u8; ZGen2PhaseRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_z1, dst, 0);
        marshal_helper(&self.out_z2, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for ZGen2PhaseRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_z1: Unmarshal::unmarshal(src)?,
            out_z2: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ECC_Encrypt (Command)
#[doc(alias = "TPM2_ECC_Encrypt")]
#[doc(alias = "ECC_Encrypt_In")]
#[derive(Clone, Copy)]
pub struct ECCEncrypt<'a> {
    pub key_handle: ObjectHandle<'a>,
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
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ECCEncryptRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
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
impl<'a> UnmarshalCommand<'a> for ECCEncrypt<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            plain_text: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for ECCEncryptRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for ECCEncryptRsp<'a> {
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
#[derive(Clone, Copy)]
pub struct ECCDecrypt<'a> {
    pub key_handle: ObjectHandle<'a>,
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
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ECCDecryptRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
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
impl<'a> UnmarshalCommand<'a> for ECCDecrypt<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            c1: Unmarshal::unmarshal(src)?,
            c2: Unmarshal::unmarshal(src)?,
            c3: Unmarshal::unmarshal(src)?,
            in_scheme: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for ECCDecryptRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for ECCDecryptRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            plain_text: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Encapsulate (Command)
#[doc(alias = "TPM2_Encapsulate")]
#[doc(alias = "Encapsulate_In")]
#[derive(Clone, Copy)]
pub struct Encapsulate<'a> {
    pub key_handle: ObjectHandle<'a>,
}
/// TPM2_Encapsulate (Response)
#[doc(alias = "Encapsulate_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct EncapsulateRsp<'a> {
    pub shared_secret: Tpm2bSharedSecret<'a>,
    pub ciphertext: Tpm2bKemCiphertext<'a>,
}

impl Command for Encapsulate<'_> {
    const CMD_CODE: TpmCc = TpmCc::Encapsulate;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = EncapsulateRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for Encapsulate<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for Encapsulate<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
        })
    }
}

impl Response for EncapsulateRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for EncapsulateRsp<'_> {
    const MAX_SIZE: usize = Tpm2bSharedSecret::MAX_SIZE + Tpm2bKemCiphertext::MAX_SIZE;
    type MaxBuffer = [u8; EncapsulateRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.shared_secret, dst, 0);
        marshal_helper(&self.ciphertext, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for EncapsulateRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            shared_secret: Unmarshal::unmarshal(src)?,
            ciphertext: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Decapsulate (Command)
#[doc(alias = "TPM2_Decapsulate")]
#[doc(alias = "Decapsulate_In")]
#[derive(Clone, Copy)]
pub struct Decapsulate<'a> {
    pub key_handle: ObjectHandle<'a>,
    pub ciphertext: Tpm2bKemCiphertext<'a>,
}
/// TPM2_Decapsulate (Response)
#[doc(alias = "Decapsulate_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct DecapsulateRsp<'a> {
    pub shared_secret: Tpm2bSharedSecret<'a>,
}

impl Command for Decapsulate<'_> {
    const CMD_CODE: TpmCc = TpmCc::Decapsulate;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = DecapsulateRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.key_handle.into()]
    }
}
impl Marshal for Decapsulate<'_> {
    const MAX_SIZE: usize = Tpm2bKemCiphertext::MAX_SIZE;
    type MaxBuffer = [u8; Decapsulate::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.ciphertext.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for Decapsulate<'a> {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: key_handle.try_into()?,
            ciphertext: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for DecapsulateRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for DecapsulateRsp<'_> {
    const MAX_SIZE: usize = Tpm2bSharedSecret::MAX_SIZE;
    type MaxBuffer = [u8; DecapsulateRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.shared_secret.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for DecapsulateRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            shared_secret: Unmarshal::unmarshal(src)?,
        })
    }
}
