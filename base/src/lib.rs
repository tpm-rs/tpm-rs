#![allow(dead_code)]
use crate::{constants::*, errors::*, marshal::*};
use core::mem::size_of;
use marshal_derive::Marshal;
use zerocopy::byteorder::big_endian::*;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub type TpmaLocality = u8;

pub type Tpm2AlgId = U16;
pub type Tpm2KeyBits = U16;
pub type Tpm2St = u16;

pub type Tpm2Generated = u32;
pub type Tpm2Handle = u32;
pub type TpmaNv = u32;

pub type TpmiAlgHash = Tpm2AlgId;
pub type TpmiAlgKdf = Tpm2AlgId;
pub type TpmiAlgPublic = Tpm2AlgId;
pub type TpmiAlgSymMode = Tpm2AlgId;
pub type TpmiAlgSymObject = Tpm2AlgId;
pub type TpmiAlgKeyedhashScheme = Tpm2AlgId;
pub type TpmiAlgRsaScheme = Tpm2AlgId;
pub type TpmiAlgEccScheme = Tpm2AlgId;
pub type TpmiAlgAsymScheme = Tpm2AlgId;

pub type TpmiRhNvIndex = Tpm2Handle;

pub type Tpm2EccCurve = U16;
pub type TpmiEccCurve = Tpm2EccCurve;

pub type TpmiYesNo = u8;
pub type TpmiStAttest = Tpm2St;

pub type TpmiAesKeyBits = Tpm2KeyBits;
pub type TpmiSm4KeyBits = Tpm2KeyBits;
pub type TpmiCamelliaKeyBits = Tpm2KeyBits;
pub type TpmiRsaKeyBits = Tpm2KeyBits;

pub type TpmaObject = U32;

mod constants;
mod errors;
mod marshal;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsEmpty;

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuHa {
    sha: [u8; constants::TPM2_SHA_DIGEST_SIZE as usize],
    sha1: [u8; constants::TPM2_SHA1_DIGEST_SIZE as usize],
    sha256: [u8; constants::TPM2_SHA256_DIGEST_SIZE as usize],
    sha384: [u8; constants::TPM2_SHA384_DIGEST_SIZE as usize],
    sha512: [u8; constants::TPM2_SHA512_DIGEST_SIZE as usize],
    sm3_256: [u8; constants::TPM2_SM3_256_DIGEST_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtHa {
    pub hash_alg: TpmiAlgHash,
    pub digest: TpmuHa,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuName {
    pub digest: TpmtHa,
    pub handle: Tpm2Handle,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDigest {
    size: U16,
    pub buffer: [u8; size_of::<TpmuHa>()],
}

type Tpm2bNonce = Tpm2bDigest;
type Tpm2bOperand = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bData {
    size: U16,
    pub buffer: [u8; size_of::<TpmuHa>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEvent {
    size: U16,
    pub buffer: [u8; 1024],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxBuffer {
    size: U16,
    pub buffer: [u8; constants::TPM2_MAX_DIGEST_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxNvBuffer {
    size: U16,
    pub buffer: [u8; constants::TPM2_MAX_NV_BUFFER_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIv {
    size: U16,
    pub buffer: [u8; constants::TPM2_MAX_SYM_BLOCK_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bName {
    size: U16,
    pub name: [u8; size_of::<TpmuName>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxCapBuffer {
    size: U16,
    pub buffer: [u8; constants::TPM2_MAX_CAP_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsClockInfo {
    pub clock: U64,
    pub reset_count: U32,
    pub restart_count: U32,
    pub safe: TpmiYesNo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmsPcrSelection {
    pub hash: TpmiAlgHash,
    pub sizeof_select: u8,
    #[length(sizeof_select)]
    pub pcr_select: [u8; constants::TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlPcrSelection {
    // TODO: Make this BE and handle gracefully in Marshal.
    pub count: u32,
    #[length(count)]
    pub pcr_selections: [TpmsPcrSelection; constants::TPM2_NUM_PCR_BANKS as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsQuoteInfo {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsCreationInfo {
    pub object_name: Tpm2bName,
    pub creation_hash: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsCertifyInfo {
    pub name: Tpm2bName,
    pub qualified_name: Tpm2bName,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsCommandAuditInfo {
    pub audit_counter: u64,
    pub digest_alg: Tpm2AlgId,
    pub audit_digest: Tpm2bDigest,
    pub command_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsSessionAuditInfo {
    pub exclusive_session: TpmiYesNo,
    pub session_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsTimeInfo {
    pub time: U64,
    pub clock_info: TpmsClockInfo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsNvCertifyInfo {
    pub index_name: Tpm2bName,
    pub offset: U16,
    pub nv_contents: Tpm2bMaxNvBuffer,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TPMU_ATTEST {
    pub certify: TpmsCertifyInfo,
    pub creation: TpmsCreationInfo,
    pub quote: TpmsQuoteInfo,
    pub command_audit: TpmsCommandAuditInfo,
    pub session_audit: TpmsSessionAuditInfo,
    pub time: TpmsTimeAttestInfo,
    pub nv: TpmsNvCertifyInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsAttest {
    pub magic: Tpm2Generated,
    pub tipe: TpmiStAttest, /* type is a reserved word, rename to tipe */
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: TPMU_ATTEST,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bAttest {
    size: U16,
    pub attestation_data: [u8; size_of::<TpmsAttest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSymKey {
    size: U16,
    pub buffer: [u8; constants::TPM2_MAX_SYM_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bLabel {
    size: U16,
    pub buffer: [u8; constants::TPM2_LABEL_MAX_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsDerive {
    pub label: Tpm2bLabel,
    pub context: Tpm2bLabel,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDerive {
    size: U16,
    pub buffer: [u8; size_of::<TpmsDerive>()],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuSensitiveCreate {
    pub create: [u8; constants::TPM2_MAX_SYM_DATA as usize],
    pub derive: TpmsDerive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveData {
    size: U16,
    pub buffer: [u8; size_of::<TpmuSensitiveCreate>()],
}

pub type Tpm2bAuth = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bAuth,
    pub data: Tpm2bSensitiveData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveCreate {
    size: U16,
    pub sensitive: [u8; size_of::<TpmsSensitiveCreate>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublicKeyRsa {
    size: U16,
    pub buffer: [u8; constants::TPM2_MAX_RSA_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateKeyRsa {
    size: U16,
    pub buffer: [u8; (constants::TPM2_MAX_RSA_KEY_BYTES / 2) as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccParameter {
    size: U16,
    pub buffer: [u8; constants::TPM2_MAX_ECC_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccPoint {
    size: U16,
    pub point: [u8; size_of::<TpmsEccPoint>()],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuEncryptedSecret {
    pub ecc: [u8; size_of::<TpmsEccPoint>()],
    pub rsa: [u8; constants::TPM2_MAX_RSA_KEY_BYTES as usize],
    pub symmetric: [u8; size_of::<Tpm2bDigest>()],
    pub keyed_hash: [u8; size_of::<Tpm2bDigest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEncryptedSecret {
    size: U16,
    pub secret: [u8; size_of::<TpmuEncryptedSecret>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: TpmiAlgKdf,
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuSchemeKeyedHash {
    pub hmac: TpmsSchemeHmac,
    pub exclusive_or: TpmsSchemeXor,
    pub null: TpmsEmpty,
}
impl TpmuSchemeKeyedHash {
    fn try_marshal(
        &self,
        selector: TpmiAlgKeyedhashScheme,
        buffer: &mut [u8],
    ) -> Result<usize, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_HMAC => unsafe { self.hmac.try_marshal(buffer) },
            TPM2_ALG_XOR => unsafe { self.exclusive_or.try_marshal(buffer) },
            TPM2_ALG_NONE => Ok(0),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }

    fn try_unmarshal(
        selector: TpmiAlgKeyedhashScheme,
        buffer: &mut UnmarshalBuf,
    ) -> Result<Self, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_HMAC => Ok(TpmuSchemeKeyedHash {
                hmac: TpmsSchemeHmac::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_XOR => Ok(TpmuSchemeKeyedHash {
                exclusive_or: TpmsSchemeXor::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_NONE => Ok(TpmuSchemeKeyedHash { null: TpmsEmpty {} }),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmtKeyedHashScheme {
    pub scheme: TpmiAlgKeyedhashScheme,
    #[selector(scheme)]
    pub details: TpmuSchemeKeyedHash,
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmsKeyedHashParms {
    pub scheme: TpmtKeyedHashScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuSymKeyBits {
    pub aes: TpmiAesKeyBits,
    pub sm4: TpmiSm4KeyBits,
    pub camellia: TpmiCamelliaKeyBits,
    pub sym: Tpm2KeyBits,
    pub exclusive_or: TpmiAlgHash,
    pub null: TpmsEmpty,
}
impl TpmuSymKeyBits {
    fn try_marshal(&self, selector: TpmiAlgSymObject, buffer: &mut [u8]) -> Result<usize, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_AES => unsafe { self.aes.try_marshal(buffer) },
            TPM2_ALG_SM4 => unsafe { self.sm4.try_marshal(buffer) },
            TPM2_ALG_CAMELLIA => unsafe { self.camellia.try_marshal(buffer) },
            TPM2_ALG_XOR => unsafe { self.exclusive_or.try_marshal(buffer) },
            TPM2_ALG_NONE => Ok(0),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
    fn try_unmarshal(
        selector: TpmiAlgSymObject,
        buffer: &mut UnmarshalBuf,
    ) -> Result<Self, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_AES => Ok(TpmuSymKeyBits {
                aes: TpmiAesKeyBits::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_SM4 => Ok(TpmuSymKeyBits {
                sm4: TpmiSm4KeyBits::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_CAMELLIA => Ok(TpmuSymKeyBits {
                camellia: TpmiCamelliaKeyBits::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_XOR => Ok(TpmuSymKeyBits {
                exclusive_or: TpmiAlgHash::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_NONE => Ok(TpmuSymKeyBits { null: TpmsEmpty {} }),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuSymMode {
    pub aes: TpmiAlgSymMode,
    pub sm4: TpmiAlgSymMode,
    pub camellia: TpmiAlgSymMode,
    pub sym: TpmiAlgSymMode,
    pub exclusive_or: TpmsEmpty,
    pub null: TpmsEmpty,
}
impl TpmuSymMode {
    fn try_marshal(&self, selector: TpmiAlgSymObject, buffer: &mut [u8]) -> Result<usize, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_AES => unsafe { self.aes.try_marshal(buffer) },
            TPM2_ALG_SM4 => unsafe { self.sm4.try_marshal(buffer) },
            TPM2_ALG_CAMELLIA => unsafe { self.camellia.try_marshal(buffer) },
            TPM2_ALG_XOR | TPM2_ALG_NONE => Ok(0),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
    fn try_unmarshal(
        selector: TpmiAlgSymObject,
        buffer: &mut UnmarshalBuf,
    ) -> Result<Self, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_AES => Ok(TpmuSymMode {
                aes: TpmiAlgSymMode::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_SM4 => Ok(TpmuSymMode {
                sm4: TpmiAlgSymMode::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_CAMELLIA => Ok(TpmuSymMode {
                camellia: TpmiAlgSymMode::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_XOR => Ok(TpmuSymMode {
                exclusive_or: TpmsEmpty {},
            }),
            TPM2_ALG_NONE => Ok(TpmuSymMode { null: TpmsEmpty {} }),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmtSymDefObject {
    pub algorithm: TpmiAlgSymObject,
    #[selector(algorithm)]
    pub key_bits: TpmuSymKeyBits,
    #[selector(algorithm)]
    pub mode: TpmuSymMode,
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmsSymCipherParms {
    pub sym: TpmtSymDefObject,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct TpmsSchemeHash {
    pub hash_alg: TpmiAlgHash,
}

pub type TpmsKeySchemeEcdh = TpmsSchemeHash;
pub type TpmsKeySchemeEcmqv = TpmsSchemeHash;
pub type TpmsSigSchemeRsassa = TpmsSchemeHash;
pub type TpmsSigSchemeRsapss = TpmsSchemeHash;
pub type TpmsSigSchemeEcdsa = TpmsSchemeHash;
pub type TpmsSigSchemeSm2 = TpmsSchemeHash;
pub type TpmsSigSchemeEcschnorr = TpmsSchemeHash;
pub type TpmsSigSchemeEcdaa = TpmsSchemeHash;
pub type TpmsEncSchemeOaep = TpmsSchemeHash;
pub type TpmsEncSchemeRsaes = TpmsEmpty;

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuAsymScheme {
    pub ecdh: TpmsKeySchemeEcdh,
    pub ecmqv: TpmsKeySchemeEcmqv,
    pub rsassa: TpmsSigSchemeRsassa,
    pub rsapss: TpmsSigSchemeRsapss,
    pub ecdsa: TpmsSigSchemeEcdsa,
    pub ecdaa: TpmsSigSchemeEcdaa,
    pub sm2: TpmsSigSchemeSm2,
    pub ecschnorr: TpmsSigSchemeEcschnorr,
    pub rsaes: TpmsEncSchemeRsaes,
    pub oaep: TpmsEncSchemeOaep,
    pub any_sig: TpmsSchemeHash,
    pub null: TpmsEmpty,
}
impl TpmuAsymScheme {
    fn try_marshal(&self, selector: TpmiAlgAsymScheme, buffer: &mut [u8]) -> Result<usize, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_ECDH => unsafe { self.ecdh.try_marshal(buffer) },
            TPM2_ALG_ECMQV => unsafe { self.ecmqv.try_marshal(buffer) },
            TPM2_ALG_RSASSA => unsafe { self.rsassa.try_marshal(buffer) },
            TPM2_ALG_ECDSA => unsafe { self.ecdsa.try_marshal(buffer) },
            TPM2_ALG_ECDAA => unsafe { self.ecdaa.try_marshal(buffer) },
            TPM2_ALG_SM2 => unsafe { self.sm2.try_marshal(buffer) },
            TPM2_ALG_ECSCHNORR => unsafe { self.ecschnorr.try_marshal(buffer) },
            TPM2_ALG_OAEP => unsafe { self.oaep.try_marshal(buffer) },
            TPM2_ALG_RSAES | TPM2_ALG_NONE => Ok(0),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
    fn try_unmarshal(
        selector: TpmiAlgAsymScheme,
        buffer: &mut UnmarshalBuf,
    ) -> Result<Self, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_ECDH => Ok(TpmuAsymScheme {
                ecdh: TpmsKeySchemeEcdh::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_ECMQV => Ok(TpmuAsymScheme {
                ecmqv: TpmsKeySchemeEcmqv::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_RSASSA => Ok(TpmuAsymScheme {
                rsassa: TpmsSigSchemeRsassa::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_ECDSA => Ok(TpmuAsymScheme {
                ecdsa: TpmsSigSchemeEcdsa::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_ECDAA => Ok(TpmuAsymScheme {
                ecdaa: TpmsSigSchemeEcdaa::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_SM2 => Ok(TpmuAsymScheme {
                sm2: TpmsSigSchemeSm2::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_ECSCHNORR => Ok(TpmuAsymScheme {
                ecschnorr: TpmsSigSchemeEcschnorr::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_OAEP => Ok(TpmuAsymScheme {
                oaep: TpmsEncSchemeOaep::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_RSAES => Ok(TpmuAsymScheme {
                rsaes: TpmsEmpty {},
            }),
            TPM2_ALG_NONE => Ok(TpmuAsymScheme { null: TpmsEmpty {} }),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmtRsaScheme {
    pub scheme: TpmiAlgRsaScheme,
    #[selector(scheme)]
    pub details: TpmuAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: U32,
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmtEccScheme {
    pub scheme: TpmiAlgEccScheme,
    #[selector(scheme)]
    pub details: TpmuAsymScheme,
}

pub type TpmsSchemeMgf1 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_56a = TpmsSchemeHash;
pub type TpmsSchemeKdf2 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_108 = TpmsSchemeHash;

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuKdfScheme {
    pub mgf1: TpmsSchemeMgf1,
    pub kdf1_sp800_56a: TpmsSchemeKdf1Sp800_56a,
    pub kdf2: TpmsSchemeKdf2,
    pub kdf1_sp800_108: TpmsSchemeKdf1Sp800_108,
    pub null: TpmsEmpty,
}
impl TpmuKdfScheme {
    fn try_marshal(&self, selector: TpmiAlgKdf, buffer: &mut [u8]) -> Result<usize, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_MGF1 => unsafe { self.mgf1.try_marshal(buffer) },
            TPM2_ALG_KDF1_SP800_56A => unsafe { self.kdf1_sp800_56a.try_marshal(buffer) },
            TPM2_ALG_KDF2 => unsafe { self.kdf2.try_marshal(buffer) },
            TPM2_ALG_KDF1_SP800_108 => unsafe { self.kdf1_sp800_108.try_marshal(buffer) },
            TPM2_ALG_NONE => Ok(0),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }

    fn try_unmarshal(selector: TpmiAlgKdf, buffer: &mut UnmarshalBuf) -> Result<Self, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_MGF1 => Ok(TpmuKdfScheme {
                mgf1: TpmsSchemeMgf1::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_KDF1_SP800_56A => Ok(TpmuKdfScheme {
                kdf1_sp800_56a: TpmsSchemeKdf1Sp800_56a::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_KDF2 => Ok(TpmuKdfScheme {
                kdf2: TpmsSchemeKdf2::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_KDF1_SP800_108 => Ok(TpmuKdfScheme {
                kdf1_sp800_108: TpmsSchemeKdf1Sp800_108::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_NONE => Ok(TpmuKdfScheme { null: TpmsEmpty {} }),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmtKdfScheme {
    pub scheme: TpmiAlgKdf,
    #[selector(scheme)]
    pub details: TpmuKdfScheme,
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmiEccCurve,
    pub kdf: TpmtKdfScheme,
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmtAsymScheme {
    pub scheme: TpmiAlgAsymScheme,
    #[selector(scheme)]
    pub details: TpmuAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmsAsymParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuPublicParms {
    pub keyed_hash_detail: TpmsKeyedHashParms,
    pub sym_detail: TpmsSymCipherParms,
    pub rsa_detail: TpmsRsaParms,
    pub ecc_detail: TpmsEccParms,
    pub asym_detail: TpmsAsymParms,
}
impl TpmuPublicParms {
    fn try_marshal(&self, selector: TpmiAlgPublic, buffer: &mut [u8]) -> Result<usize, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_KEYEDHASH => unsafe { self.keyed_hash_detail.try_marshal(buffer) },
            TPM2_ALG_SYMCIPHER => unsafe { self.sym_detail.try_marshal(buffer) },
            TPM2_ALG_RSA => unsafe { self.rsa_detail.try_marshal(buffer) },
            TPM2_ALG_ECC => unsafe { self.ecc_detail.try_marshal(buffer) },
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
    fn try_unmarshal(selector: TpmiAlgPublic, buffer: &mut UnmarshalBuf) -> Result<Self, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_KEYEDHASH => Ok(TpmuPublicParms {
                keyed_hash_detail: TpmsKeyedHashParms::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_SYMCIPHER => Ok(TpmuPublicParms {
                sym_detail: TpmsSymCipherParms::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_RSA => Ok(TpmuPublicParms {
                rsa_detail: TpmsRsaParms::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_ECC => Ok(TpmuPublicParms {
                ecc_detail: TpmsEccParms::try_unmarshal(buffer)?,
            }),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuPublicId {
    pub keyed_hash: Tpm2bDigest,
    pub sym: Tpm2bDigest,
    pub rsa: Tpm2bPublicKeyRsa,
    pub ecc: TpmsEccPoint,
    pub derive: TpmsDerive,
}
impl TpmuPublicId {
    fn try_marshal(&self, selector: TpmiAlgPublic, buffer: &mut [u8]) -> Result<usize, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_KEYEDHASH => unsafe { self.keyed_hash.try_marshal(buffer) },
            TPM2_ALG_SYMCIPHER => unsafe { self.sym.try_marshal(buffer) },
            TPM2_ALG_RSA => unsafe { self.rsa.try_marshal(buffer) },
            TPM2_ALG_ECC => unsafe { self.ecc.try_marshal(buffer) },
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
    fn try_unmarshal(selector: TpmiAlgPublic, buffer: &mut UnmarshalBuf) -> Result<Self, Tpm2Rc> {
        match selector.get() {
            TPM2_ALG_KEYEDHASH => Ok(TpmuPublicId {
                keyed_hash: Tpm2bDigest::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_SYMCIPHER => Ok(TpmuPublicId {
                sym: Tpm2bDigest::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_RSA => Ok(TpmuPublicId {
                rsa: Tpm2bPublicKeyRsa::try_unmarshal(buffer)?,
            }),
            TPM2_ALG_ECC => Ok(TpmuPublicId {
                ecc: TpmsEccPoint::try_unmarshal(buffer)?,
            }),
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Marshal)]
pub struct TpmtPublic {
    pub tipe: TpmiAlgPublic,
    pub name_alg: TpmiAlgHash,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    #[selector(tipe)]
    pub parameters: TpmuPublicParms,
    #[selector(tipe)]
    pub unique: TpmuPublicId,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublic {
    size: U16,
    pub public_area: [u8; size_of::<TpmuPublicId>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bTemplate {
    size: U16,
    pub buffer: [u8; size_of::<TpmtPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateVendorSpecific {
    size: U16,
    pub buffer: [u8; constants::TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TPMU_SENSITIVE_COMPOSITE {
    pub rsa: Tpm2bPrivateKeyRsa,
    pub ecc: Tpm2bEccParameter,
    pub bits: Tpm2bSensitiveData,
    pub sym: Tpm2bSymKey,
    pub any: Tpm2bPrivateVendorSpecific,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtSensitive {
    pub sensitive_type: TpmiAlgPublic,
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TPMU_SENSITIVE_COMPOSITE,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitive {
    size: U16,
    pub sensitive_area: [u8; size_of::<TpmtSensitive>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct _PRIVATE {
    integrity_outer: Tpm2bDigest,
    integrity_inner: Tpm2bDigest,
    sensitive: Tpm2bSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivate {
    size: U16,
    pub buffer: [u8; size_of::<_PRIVATE>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsIdObject {
    pub integrity_hmac: Tpm2bDigest,
    pub enc_identity: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIdObject {
    size: U16,
    pub credential: [u8; size_of::<TpmsIdObject>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsNvPublic {
    pub nv_index: TpmiRhNvIndex,
    pub name_alg: TpmiAlgHash,
    pub attributes: TpmaNv,
    pub auth_policy: Tpm2bDigest,
    pub data_size: u16,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bNvPublic {
    size: U16,
    pub nv_public: [u8; size_of::<TpmsNvPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextSensitive {
    size: U16,
    pub buffer: [u8; constants::TPM2_MAX_CONTEXT_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsContextData {
    pub integrity: Tpm2bDigest,
    pub encrypted: Tpm2bContextSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextData {
    size: U16,
    pub buffer: [u8; size_of::<TpmsContextData>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsCreationData {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
    pub locality: TpmaLocality,
    pub parent_name_alg: Tpm2AlgId,
    pub parent_name: Tpm2bName,
    pub parent_qualified_name: Tpm2bName,
    pub outside_info: Tpm2bData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bCreationData {
    size: U16,
    pub creation_data: [u8; size_of::<TpmsCreationData>()],
}

// Helper for splitting up ranges of an unmarshal buffer.

pub trait Tpm2bSimple {
    const MAX_BUFFER_SIZE: usize;
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &[u8];
    fn from_bytes(buffer: &[u8]) -> Result<Self, Tpm2Rc>
    where
        Self: Sized;
}

macro_rules! impl_try_marshalable_tpm2b_simple {
    ($T:ty, $F:ident) => {
        impl Tpm2bSimple for $T {
            const MAX_BUFFER_SIZE: usize = size_of::<$T>() - size_of::<u16>();

            fn get_size(&self) -> u16 {
                self.size.get()
            }

            fn get_buffer(&self) -> &[u8] {
                &self.$F[0..self.get_size() as usize]
            }

            fn from_bytes(buffer: &[u8]) -> Result<Self, Tpm2Rc> {
                // Overflow check
                if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
                    return Err(TSS2_MU_RC_BAD_SIZE);
                }

                let mut dest: Self = Self {
                    size: U16::new(buffer.len() as u16),
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };
                dest.$F[..buffer.len()].copy_from_slice(buffer);
                Ok(dest)
            }
        }

        impl Marshalable for $T {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> Result<Self, Tpm2Rc> {
                let got_size = U16::try_unmarshal(buffer)?;
                // Ensure the buffer is large enough to fullfill the size indicated
                let sized_buffer = buffer.get(got_size.get() as usize);
                if !sized_buffer.is_some() {
                    return Err(TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                let mut dest: Self = Self {
                    size: got_size,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };

                // Make sure the size indicated isn't too large for the types buffer
                if sized_buffer.unwrap().len() > dest.$F.len() {
                    return Err(TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }
                dest.$F[..got_size.into()].copy_from_slice(&sized_buffer.unwrap());

                Ok(dest)
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> Result<usize, Tpm2Rc> {
                let used = self.size.try_marshal(buffer)?;
                let (_, rest) = buffer.split_at_mut(used);
                let buffer_marsh = self.get_size() as usize;
                if buffer_marsh > (core::cmp::max(Self::MAX_BUFFER_SIZE, rest.len())) {
                    return Err(TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }
                rest[..buffer_marsh].copy_from_slice(&self.$F[..buffer_marsh]);
                Ok(used + buffer_marsh)
            }
        }
    };
}

impl_try_marshalable_tpm2b_simple! {Tpm2bName, name}
impl_try_marshalable_tpm2b_simple! {Tpm2bAttest, attestation_data}
impl_try_marshalable_tpm2b_simple! {Tpm2bContextData, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bContextSensitive, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bData, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bDigest, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bEccParameter, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bEncryptedSecret, secret}
impl_try_marshalable_tpm2b_simple! {Tpm2bEvent, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bIdObject, credential}
impl_try_marshalable_tpm2b_simple! {Tpm2bIv, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bMaxBuffer, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bMaxNvBuffer, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivate, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivateKeyRsa, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivateVendorSpecific, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bPublicKeyRsa, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bSensitiveData, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bSymKey, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bTemplate, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bLabel, buffer}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    // Unfortunately, I didn't see a way to generate a function name easily, see
    // https://github.com/rust-lang/rust/issues/29599 for more details. So we just
    // generate the test body here.
    macro_rules! impl_test_tpm2b_simple {
        ($T:ty) => {
            const SIZE_OF_U16: usize = size_of::<u16>();
            const SIZE_OF_TYPE: usize = size_of::<$T>();
            const SIZE_OF_BUFFER: usize = SIZE_OF_TYPE - SIZE_OF_U16;

            /*
             * Generate arrays that are:
             *   - too small
             *   - smaller than buffer limit
             *   - same size as buffer limit
             *   - exceeding buffer limit
             */
            let mut too_small_size_buf: [u8; 1] = [0x00; 1];
            let mut smaller_size_buf: [u8; SIZE_OF_TYPE - 8] = [0xFF; SIZE_OF_TYPE - 8];
            let mut same_size_buf: [u8; SIZE_OF_TYPE] = [0xFF; SIZE_OF_TYPE];
            let mut bigger_size_buf: [u8; SIZE_OF_TYPE + 8] = [0xFF; SIZE_OF_TYPE + 8];

            let mut s = U16::from((smaller_size_buf.len() - SIZE_OF_U16) as u16);
            assert!(s.try_marshal(&mut smaller_size_buf).is_ok());

            s = U16::from((same_size_buf.len() - SIZE_OF_U16) as u16);
            assert!(s.try_marshal(&mut same_size_buf).is_ok());

            s = U16::from((bigger_size_buf.len() - SIZE_OF_U16) as u16);
            assert!(s.try_marshal(&mut bigger_size_buf).is_ok());

            // too small should fail
            let mut result: Result<$T, Tpm2Rc> =
                <$T>::try_unmarshal(&mut UnmarshalBuf::new(&too_small_size_buf));
            assert!(result.is_err());

            // bigger size should consume only the prefix
            result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&bigger_size_buf));
            assert!(result.is_err());

            // small, should be good
            result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&smaller_size_buf));
            assert!(result.is_ok());
            let mut digest = result.unwrap();
            assert_eq!(
                usize::from(digest.get_size()),
                smaller_size_buf.len() - SIZE_OF_U16
            );
            assert_eq!(digest.get_buffer(), &smaller_size_buf[SIZE_OF_U16..]);

            // same size should be good
            result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&same_size_buf));
            assert!(result.is_ok());
            digest = result.unwrap();
            assert_eq!(
                usize::from(digest.get_size()),
                same_size_buf.len() - size_of::<u16>()
            );
            assert_eq!(digest.get_buffer(), &same_size_buf[size_of::<u16>()..]);

            let mut mres = digest.try_marshal(&mut too_small_size_buf);
            assert!(mres.is_err());

            mres = digest.try_marshal(&mut same_size_buf);
            assert!(mres.is_ok());
            assert_eq!(mres.unwrap(), digest.get_size() as usize + SIZE_OF_U16);
            let mut new_digest =
                <$T>::try_unmarshal(&mut UnmarshalBuf::new(&same_size_buf)).unwrap();
            assert_eq!(digest, new_digest);

            mres = digest.try_marshal(&mut bigger_size_buf);
            assert!(mres.is_ok());
            assert_eq!(mres.unwrap(), digest.get_size() as usize + SIZE_OF_U16);
            new_digest =
                <$T>::try_unmarshal(&mut UnmarshalBuf::new(&bigger_size_buf[..SIZE_OF_TYPE]))
                    .unwrap();
            assert_eq!(digest, new_digest);
        };
    }

    #[test]
    fn test_try_unmarshal_tpm2b_name() {
        impl_test_tpm2b_simple! {Tpm2bName};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_attest() {
        impl_test_tpm2b_simple! {Tpm2bAttest};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_context_data() {
        impl_test_tpm2b_simple! {Tpm2bContextData};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_context_sensitive() {
        impl_test_tpm2b_simple! {Tpm2bContextSensitive};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_data() {
        impl_test_tpm2b_simple! {Tpm2bData};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_digest() {
        impl_test_tpm2b_simple! {Tpm2bDigest};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_ecc_parameter() {
        impl_test_tpm2b_simple! {Tpm2bEccParameter};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_encrypted_secret() {
        impl_test_tpm2b_simple! {Tpm2bEncryptedSecret};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_event() {
        impl_test_tpm2b_simple! {Tpm2bEvent};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_id_object() {
        impl_test_tpm2b_simple! {Tpm2bIdObject};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_iv() {
        impl_test_tpm2b_simple! {Tpm2bIv};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_max_buffer() {
        impl_test_tpm2b_simple! {Tpm2bMaxBuffer};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_max_nv_buffer() {
        impl_test_tpm2b_simple! {Tpm2bMaxNvBuffer};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_private() {
        impl_test_tpm2b_simple! {Tpm2bPrivate};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_private_key_rsa() {
        impl_test_tpm2b_simple! {Tpm2bPrivateKeyRsa};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_private_vendor_specific() {
        impl_test_tpm2b_simple! {Tpm2bPrivateVendorSpecific};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_public_key_rsa() {
        impl_test_tpm2b_simple! {Tpm2bPublicKeyRsa};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_sensitive_data() {
        impl_test_tpm2b_simple! {Tpm2bSensitiveData};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_sym_key() {
        impl_test_tpm2b_simple! {Tpm2bSymKey};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_template() {
        impl_test_tpm2b_simple! {Tpm2bTemplate};
    }

    #[test]
    fn test_marshal_struct_derive() {
        let name_buffer: [u8; 4] = [1, 2, 3, 4];
        let index_name = Tpm2bName::from_bytes(&name_buffer).unwrap();
        let nv_buffer = [24u8; 10];
        let nv_contents = Tpm2bMaxNvBuffer::from_bytes(&nv_buffer).unwrap();
        let info: TpmsNvCertifyInfo = TpmsNvCertifyInfo {
            index_name,
            offset: U16::new(10),
            nv_contents,
        };
        let mut marshal_buffer = [0u8; 48];
        let bytes = info.try_marshal(&mut marshal_buffer).unwrap();

        // Build the expected output manually.
        let mut expected = Vec::with_capacity(bytes);
        expected.extend_from_slice(&index_name.get_size().to_be_bytes());
        expected.extend_from_slice(&name_buffer);
        expected.extend_from_slice(&info.offset.get().to_be_bytes());
        expected.extend_from_slice(&nv_contents.get_size().to_be_bytes());
        expected.extend_from_slice(&nv_buffer);

        assert_eq!(expected.len(), bytes);
        assert_eq!(expected, marshal_buffer[..expected.len()]);

        let unmarshaled = TpmsNvCertifyInfo::try_unmarshal(&mut UnmarshalBuf::new(&marshal_buffer));
        assert_eq!(unmarshaled.unwrap(), info);
    }

    #[test]
    fn test_marshal_enum_override() {
        let hmac = TpmsSchemeHmac {
            hash_alg: U16::new(0xB),
        };
        let scheme = TpmtKeyedHashScheme {
            scheme: U16::from(TPM2_ALG_HMAC),
            details: TpmuSchemeKeyedHash { hmac },
        };
        let mut buffer = [0u8; size_of::<TpmtKeyedHashScheme>()];
        assert!(scheme.try_marshal(&mut buffer).is_ok());
    }

    #[test]
    fn test_marshal_tpmt_public() {
        let xor_sym_def_obj = TpmtSymDefObject {
            algorithm: U16::new(TPM2_ALG_XOR),
            key_bits: TpmuSymKeyBits {
                exclusive_or: U16::new(TPM2_ALG_SHA256),
            },
            mode: TpmuSymMode {
                exclusive_or: TpmsEmpty {},
            },
        };
        let mut buffer = [0u8; size_of::<TpmtSymDefObject>()];
        let mut marsh = xor_sym_def_obj.try_marshal(&mut buffer);
        // Because XOR does not populate TpmuSymMode, we have bytes left over.
        assert!(marsh.unwrap() < buffer.len());
        let rsa_scheme = TpmtRsaScheme {
            scheme: U16::new(TPM2_ALG_ECDSA),
            details: TpmuAsymScheme {
                ecdsa: TpmsSigSchemeEcdsa {
                    hash_alg: U16::from(TPM2_ALG_SHA256),
                },
            },
        };

        let rsa_parms = TpmsRsaParms {
            symmetric: xor_sym_def_obj,
            scheme: rsa_scheme,
            key_bits: U16::new(74),
            exponent: U32::new(2),
        };

        let pubkey_buf = [9u8; 24];
        let pubkey = Tpm2bPublicKeyRsa::from_bytes(&pubkey_buf).unwrap();

        let mut example = TpmtPublic {
            tipe: U16::new(TPM2_ALG_RSA),
            name_alg: U16::new(TPM2_ALG_SHA256),
            object_attributes: U32::new(6543),
            auth_policy: Tpm2bDigest::from_bytes(&[2, 2, 4, 4]).unwrap(),
            parameters: TpmuPublicParms {
                rsa_detail: rsa_parms,
            },
            unique: TpmuPublicId { rsa: pubkey },
        };

        // Test a round-trip marshaling and unmarshaling, confirm that we get the same output.
        let mut buffer = [0u8; 256];
        marsh = example.try_marshal(&mut buffer);
        assert!(marsh.is_ok());
        let expected: [u8; 54] = [
            0, 1, 0, 11, 0, 0, 25, 143, 0, 4, 2, 2, 4, 4, 0, 10, 0, 11, 0, 24, 0, 11, 0, 74, 0, 0,
            0, 2, 0, 24, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        ];
        assert_eq!(expected.len(), marsh.unwrap());
        assert_eq!(buffer[..expected.len()], expected);
        let unmarsh_buf = buffer.clone();
        let mut unmarsh = TpmtPublic::try_unmarshal(&mut UnmarshalBuf::new(&unmarsh_buf));
        let bytes_example = unmarsh.unwrap();
        assert_eq!(bytes_example.object_attributes, example.object_attributes);
        let mut remarsh_buffer = [1u8; 256];
        let remarsh = unmarsh.unwrap().try_marshal(&mut remarsh_buffer);
        assert_eq!(remarsh, marsh);
        assert_eq!(remarsh_buffer[..marsh.unwrap()], buffer[..marsh.unwrap()]);

        // Test invalid selector value.
        example.tipe = U16::new(TPM2_ALG_SHA256);
        assert_eq!(example.try_marshal(&mut buffer), Err(TPM2_RC_SELECTOR));
        unmarsh = TpmtPublic::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert_eq!(unmarsh.err(), Some(TPM2_RC_SELECTOR));
    }
}
