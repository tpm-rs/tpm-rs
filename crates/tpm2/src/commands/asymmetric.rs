//! TPM 2.0 Asymmetric Primitives Commands
//!
//! This module implements the "Asymmetric Primitives" commands defined in
//! **Section 14** of the TPM 2.0 Specification.
//!
//! These commands provide:
//! - RSA encryption and decryption
//! - ECC key generation and ECDH key agreement
//! - ECC parameter queries
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 14.2 TPM2_RSA_Encrypt (Command)
#[doc(alias = "TPM2_RSA_Encrypt")]
#[doc(alias = "RSA_Encrypt_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct RSAEncrypt<'a> {
    pub message: Tpm2bPublicKeyRsa<'a>,
    pub in_scheme: Option<TpmtRsaDecrypt>,
    pub label: crate::Tpm2bData<'a>,
}
impl Marshal for RSAEncrypt<'_> {
    const MAX_SIZE: usize = Tpm2bPublicKeyRsa::MAX_SIZE
        + <Option<TpmtRsaDecrypt>>::MAX_SIZE
        + <crate::Tpm2bData>::MAX_SIZE;
    type MaxBuffer = [u8; RSAEncrypt::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.message, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.label, dst, count)
    }
}

impl<'a> Unmarshal<'a> for RSAEncrypt<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            message: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            label: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct RSAEncryptHandles {
    pub key_handle: crate::constants::Handle,
}
impl Marshal for RSAEncryptHandles {
    const MAX_SIZE: usize = <crate::constants::Handle>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for RSAEncryptHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.2 TPM2_RSA_Encrypt (Response)
#[doc(alias = "RSA_Encrypt_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct RSAEncryptRsp<'a> {
    pub out_data: crate::Tpm2bPublicKeyRsa<'a>,
}
impl Marshal for RSAEncryptRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPublicKeyRsa>::MAX_SIZE;
    type MaxBuffer = [u8; RSAEncryptRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for RSAEncryptRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for RSAEncrypt<'_> {
    const CMD_CODE: crate::constants::TpmCc = crate::constants::TpmCc::RSAEncrypt;
    type Handles = RSAEncryptHandles;
    type Response<'a> = RSAEncryptRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 14.3 TPM2_RSA_Decrypt (Command)
#[doc(alias = "TPM2_RSA_Decrypt")]
#[doc(alias = "RSA_Decrypt_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct RSADecrypt<'a> {
    pub cipher_text: crate::Tpm2bPublicKeyRsa<'a>,
    pub in_scheme: Option<crate::TpmtRsaDecrypt>,
    pub label: crate::Tpm2bData<'a>,
}
impl Marshal for RSADecrypt<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPublicKeyRsa>::MAX_SIZE
        + <Option<crate::TpmtRsaDecrypt>>::MAX_SIZE
        + <crate::Tpm2bData>::MAX_SIZE;
    type MaxBuffer = [u8; RSADecrypt::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.cipher_text, dst, 0);
        let count = marshal_helper(&self.in_scheme, dst, count);
        marshal_helper(&self.label, dst, count)
    }
}

impl<'a> Unmarshal<'a> for RSADecrypt<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            cipher_text: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            label: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct RSADecryptHandles {
    pub key_handle: crate::constants::Handle,
}
impl Marshal for RSADecryptHandles {
    const MAX_SIZE: usize = <crate::constants::Handle>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for RSADecryptHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.3 TPM2_RSA_Decrypt (Response)
#[doc(alias = "RSA_Decrypt_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct RSADecryptRsp<'a> {
    pub message: crate::Tpm2bPublicKeyRsa<'a>,
}
impl Marshal for RSADecryptRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPublicKeyRsa>::MAX_SIZE;
    type MaxBuffer = [u8; RSADecryptRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.message.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for RSADecryptRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            message: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for RSADecrypt<'_> {
    const CMD_CODE: crate::constants::TpmCc = crate::constants::TpmCc::RSADecrypt;
    type Handles = RSADecryptHandles;
    type Response<'a> = RSADecryptRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 14.4 TPM2_ECDH_KeyGen (Command)
#[doc(alias = "TPM2_ECDH_KeyGen")]
#[doc(alias = "ECDH_KeyGen_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ECDHKeyGen {}
impl Marshal for ECDHKeyGen {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for ECDHKeyGen {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ECDHKeyGenHandles {
    pub key_handle: crate::constants::Handle,
}
impl Marshal for ECDHKeyGenHandles {
    const MAX_SIZE: usize = <crate::constants::Handle>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECDHKeyGenHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.4 TPM2_ECDH_KeyGen (Response)
#[doc(alias = "ECDH_KeyGen_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ECDHKeyGenRsp<'a> {
    pub z_point: crate::Tpm2bEccPoint<'a>,
    pub pub_point: crate::Tpm2bEccPoint<'a>,
}
impl Marshal for ECDHKeyGenRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bEccPoint>::MAX_SIZE + <crate::Tpm2bEccPoint>::MAX_SIZE;
    type MaxBuffer = [u8; ECDHKeyGenRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.z_point, dst, 0);
        marshal_helper(&self.pub_point, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ECDHKeyGenRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            z_point: Unmarshal::unmarshal(src)?,
            pub_point: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ECDHKeyGen {
    const CMD_CODE: crate::constants::TpmCc = crate::constants::TpmCc::ECDHKeyGen;
    type Handles = ECDHKeyGenHandles;
    type Response<'a> = ECDHKeyGenRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 14.5 TPM2_ECDH_ZGen (Command)
#[doc(alias = "TPM2_ECDH_ZGen")]
#[doc(alias = "ECDH_ZGen_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ECDHZGen<'a> {
    pub in_point: crate::Tpm2bEccPoint<'a>,
}
impl Marshal for ECDHZGen<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bEccPoint>::MAX_SIZE;
    type MaxBuffer = [u8; ECDHZGen::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.in_point.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECDHZGen<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let in_point: crate::Tpm2bEccPoint =
            Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?;
        Ok(Self { in_point })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ECDHZGenHandles {
    pub key_handle: crate::constants::Handle,
}
impl Marshal for ECDHZGenHandles {
    const MAX_SIZE: usize = <crate::constants::Handle>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECDHZGenHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.5 TPM2_ECDH_ZGen (Response)
#[doc(alias = "ECDH_ZGen_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ECDHZGenRsp<'a> {
    pub out_point: crate::Tpm2bEccPoint<'a>,
}
impl Marshal for ECDHZGenRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bEccPoint>::MAX_SIZE;
    type MaxBuffer = [u8; ECDHZGenRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_point.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECDHZGenRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_point: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ECDHZGen<'_> {
    const CMD_CODE: crate::constants::TpmCc = crate::constants::TpmCc::ECDHZGen;
    type Handles = ECDHZGenHandles;
    type Response<'a> = ECDHZGenRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 14.6 TPM2_ECC_Parameters (Command)
#[doc(alias = "TPM2_ECC_Parameters")]
#[doc(alias = "ECC_Parameters_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECCParameters {
    pub curve_id: crate::TpmEccCurve,
}
impl Marshal for ECCParameters {
    const MAX_SIZE: usize = <crate::TpmEccCurve>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.curve_id.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECCParameters {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            curve_id: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 14.6 TPM2_ECC_Parameters (Response)
#[doc(alias = "ECC_Parameters_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECCParametersRsp<'a> {
    pub parameters: crate::TpmsAlgorithmDetailEcc<'a>,
}
impl Marshal for ECCParametersRsp<'_> {
    const MAX_SIZE: usize = <crate::TpmsAlgorithmDetailEcc>::MAX_SIZE;
    type MaxBuffer = [u8; ECCParametersRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.parameters.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECCParametersRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parameters: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ECCParameters {
    const CMD_CODE: crate::constants::TpmCc = crate::constants::TpmCc::ECCParameters;
    type Handles = ();
    type Response<'a> = ECCParametersRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ZGen2PhaseHandles {
    pub key_a: Handle,
}

impl Marshal for ZGen2PhaseHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_a.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ZGen2PhaseHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_a: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.7 TPM2_ZGen_2Phase (Command)
#[doc(alias = "TPM2_ZGen_2Phase")]
#[doc(alias = "ZGen_2Phase_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ZGen2Phase<'a> {
    pub in_qs_b: Tpm2bEccPoint<'a>,
    pub in_qe_b: Tpm2bEccPoint<'a>,
    pub in_scheme: TpmiEccKeyExchange,
    pub counter: u16,
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

impl<'a> Unmarshal<'a> for ZGen2Phase<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_qs_b: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_qe_b: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            counter: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

/// [TPM2.0 1.83] 14.7 TPM2_ZGen_2Phase (Response)
#[doc(alias = "ZGen_2Phase_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ZGen2PhaseRsp<'a> {
    pub out_z1: Tpm2bEccPoint<'a>,
    pub out_z2: Tpm2bEccPoint<'a>,
}

impl Marshal for ZGen2PhaseRsp<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE + Tpm2bEccPoint::MAX_SIZE;
    type MaxBuffer = [u8; ZGen2PhaseRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_z1, dst, 0);
        marshal_helper(&self.out_z2, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ZGen2PhaseRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_z1: Unmarshal::unmarshal(src)?,
            out_z2: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ZGen2Phase<'_> {
    const CMD_CODE: TpmCc = TpmCc::ZGen2Phase;
    type Handles = ZGen2PhaseHandles;
    type Response<'a> = ZGen2PhaseRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ECCEncryptHandles {
    pub key_handle: Handle,
}

impl Marshal for ECCEncryptHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECCEncryptHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.8 TPM2_ECC_Encrypt (Command)
#[doc(alias = "TPM2_ECC_Encrypt")]
#[doc(alias = "ECC_Encrypt_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ECCEncrypt<'a> {
    pub plain_text: Tpm2bMaxBuffer<'a>,
    pub in_scheme: Option<TpmtKdfScheme>,
}

impl Marshal for ECCEncrypt<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmtKdfScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; ECCEncrypt::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.plain_text, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ECCEncrypt<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            plain_text: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 14.8 TPM2_ECC_Encrypt (Response)
#[doc(alias = "ECC_Encrypt_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ECCEncryptRsp<'a> {
    pub c1: Tpm2bEccPoint<'a>,
    pub c2: Tpm2bMaxBuffer<'a>,
    pub c3: Tpm2bDigest<'a>,
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

impl<'a> Unmarshal<'a> for ECCEncryptRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            c1: Unmarshal::unmarshal(src)?,
            c2: Unmarshal::unmarshal(src)?,
            c3: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ECCEncrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::ECCEncrypt;
    type Handles = ECCEncryptHandles;
    type Response<'a> = ECCEncryptRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ECCDecryptHandles {
    pub key_handle: Handle,
}

impl Marshal for ECCDecryptHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECCDecryptHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.9 TPM2_ECC_Decrypt (Command)
#[doc(alias = "TPM2_ECC_Decrypt")]
#[doc(alias = "ECC_Decrypt_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ECCDecrypt<'a> {
    pub c1: Tpm2bEccPoint<'a>,
    pub c2: Tpm2bMaxBuffer<'a>,
    pub c3: Tpm2bDigest<'a>,
    pub in_scheme: Option<TpmtKdfScheme>,
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

impl<'a> Unmarshal<'a> for ECCDecrypt<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            c1: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            c2: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            c3: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

/// [TPM2.0 1.83] 14.9 TPM2_ECC_Decrypt (Response)
#[doc(alias = "ECC_Decrypt_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ECCDecryptRsp<'a> {
    pub plain_text: Tpm2bMaxBuffer<'a>,
}

impl Marshal for ECCDecryptRsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; ECCDecryptRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.plain_text.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECCDecryptRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            plain_text: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ECCDecrypt<'_> {
    const CMD_CODE: TpmCc = TpmCc::ECCDecrypt;
    type Handles = ECCDecryptHandles;
    type Response<'a> = ECCDecryptRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncapsulateHandles {
    pub key_handle: Handle,
}

impl Marshal for EncapsulateHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for EncapsulateHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.10 TPM2_Encapsulate (Command)
#[doc(alias = "TPM2_Encapsulate")]
#[doc(alias = "Encapsulate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Encapsulate {}

impl Marshal for Encapsulate {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for Encapsulate {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

/// [TPM2.0 1.83] 14.10 TPM2_Encapsulate (Response)
#[doc(alias = "Encapsulate_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EncapsulateRsp<'a> {
    pub shared_secret: Tpm2bSharedSecret<'a>,
    pub ciphertext: Tpm2bKemCiphertext<'a>,
}

impl Marshal for EncapsulateRsp<'_> {
    const MAX_SIZE: usize = Tpm2bSharedSecret::MAX_SIZE + Tpm2bKemCiphertext::MAX_SIZE;
    type MaxBuffer = [u8; EncapsulateRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.shared_secret, dst, 0);
        marshal_helper(&self.ciphertext, dst, count)
    }
}

impl<'a> Unmarshal<'a> for EncapsulateRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            shared_secret: Unmarshal::unmarshal(src)?,
            ciphertext: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Encapsulate {
    const CMD_CODE: TpmCc = TpmCc::Encapsulate;
    type Handles = EncapsulateHandles;
    type Response<'a> = EncapsulateRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct DecapsulateHandles {
    pub key_handle: Handle,
}

impl Marshal for DecapsulateHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for DecapsulateHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 14.11 TPM2_Decapsulate (Command)
#[doc(alias = "TPM2_Decapsulate")]
#[doc(alias = "Decapsulate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Decapsulate<'a> {
    pub ciphertext: Tpm2bKemCiphertext<'a>,
}

impl Marshal for Decapsulate<'_> {
    const MAX_SIZE: usize = Tpm2bKemCiphertext::MAX_SIZE;
    type MaxBuffer = [u8; Decapsulate::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.ciphertext.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Decapsulate<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            ciphertext: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 14.11 TPM2_Decapsulate (Response)
#[doc(alias = "Decapsulate_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct DecapsulateRsp<'a> {
    pub shared_secret: Tpm2bSharedSecret<'a>,
}

impl Marshal for DecapsulateRsp<'_> {
    const MAX_SIZE: usize = Tpm2bSharedSecret::MAX_SIZE;
    type MaxBuffer = [u8; DecapsulateRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.shared_secret.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for DecapsulateRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            shared_secret: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Decapsulate<'_> {
    const CMD_CODE: TpmCc = TpmCc::Decapsulate;
    type Handles = DecapsulateHandles;
    type Response<'a> = DecapsulateRsp<'a>;
    type RespHandles = ();
}
