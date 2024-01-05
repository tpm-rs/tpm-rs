#![allow(dead_code, clippy::large_enum_variant)]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use crate::{constants::*, errors::*, marshal::*};
use core::mem::{align_of, size_of};
pub use tpm2_rs_errors as errors;
pub use tpm2_rs_marshal as marshal;

pub mod commands;
pub mod constants;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmaLocality(u8);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct Tpm2KeyBits(u16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct Tpm2Generated(u32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmaNv(u32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgHash(TPM2AlgID);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgKdf(TPM2AlgID);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgPublic(TPM2AlgID);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgSymMode(TPM2AlgID);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgSymObject(TPM2AlgID);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgKeyedhashScheme(TPM2AlgID);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgRsaScheme(TPM2AlgID);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgEccScheme(TPM2AlgID);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAlgAsymScheme(TPM2AlgID);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiRhNvIndex(u32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiEccCurve(u16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiYesNo(u8);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiStAttest(u16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAesKeyBits(u16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiSm4KeyBits(u16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiCamelliaKeyBits(u16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiRsaKeyBits(u16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmaObject(u32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmaAlgorithm(u32);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmaCc(u32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiStCommandTag(pub TPM2ST);

const TPM2_MAX_CAP_DATA: usize =
    TPM2_MAX_CAP_BUFFER as usize - size_of::<TPM2Cap>() - size_of::<u32>();
const TPM2_MAX_CAP_ALGS: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsAlgProperty>();
const TPM2_MAX_CAP_HANDLES: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2Handle>();
const TPM2_MAX_CAP_CC: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2CC>();
const TPM2_MAX_TPM_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedProperty>();
const TPM2_MAX_PCR_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPcrSelect>();
const TPM2_MAX_ECC_CURVES: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2ECCCurve>();
const TPM2_MAX_TAGGED_POLICIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPolicy>();

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEmpty;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtHa {
    Sha1([u8; constants::TPM2_SHA_DIGEST_SIZE as usize]) = TPM2AlgID::SHA1.0,
    Sha256([u8; constants::TPM2_SHA256_DIGEST_SIZE as usize]) = TPM2AlgID::SHA256.0,
    Sha384([u8; constants::TPM2_SHA384_DIGEST_SIZE as usize]) = TPM2AlgID::SHA384.0,
    Sha512([u8; constants::TPM2_SHA512_DIGEST_SIZE as usize]) = TPM2AlgID::SHA512.0,
    Sm3_256([u8; constants::TPM2_SM3_256_DIGEST_SIZE as usize]) = TPM2AlgID::SM3256.0,
}
impl TpmtHa {
    pub const fn union_size() -> usize {
        size_of::<TpmtHa>() - align_of::<TpmtHa>() - size_of::<u16>()
    }
}
impl Default for TpmtHa {
    fn default() -> Self {
        TpmtHa::Sha1([0; constants::TPM2_SHA1_DIGEST_SIZE as usize])
    }
}

#[repr(C, u16)]
enum TpmuName {
    Digest(TpmtHa),
    Handle(TPM2Handle),
}
impl TpmuName {
    pub const fn union_size() -> usize {
        size_of::<TpmuName>() - align_of::<TpmuName>() - size_of::<u16>()
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDigest {
    size: u16,
    pub buffer: [u8; TpmtHa::union_size()],
}

type Tpm2bNonce = Tpm2bDigest;
type Tpm2bOperand = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bData {
    size: u16,
    pub buffer: [u8; TpmtHa::union_size()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEvent {
    size: u16,
    pub buffer: [u8; 1024],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_DIGEST_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxNvBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_NV_BUFFER_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIv {
    size: u16,
    pub buffer: [u8; TPM2_MAX_SYM_BLOCK_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bName {
    size: u16,
    pub name: [u8; TpmuName::union_size()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxCapBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_CAP_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: TpmiYesNo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmsPcrSelection {
    pub hash: TpmiAlgHash,
    pub sizeof_select: u8,
    #[length(sizeof_select)]
    pub pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlPcrSelection {
    pub count: u32,
    #[length(count)]
    pub pcr_selections: [TpmsPcrSelection; TPM2_NUM_PCR_BANKS as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsQuoteInfo {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCreationInfo {
    pub object_name: Tpm2bName,
    pub creation_hash: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCertifyInfo {
    pub name: Tpm2bName,
    pub qualified_name: Tpm2bName,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmsCommandAuditInfo {
    pub audit_counter: u64,
    pub digest_alg: u16,
    pub audit_digest: Tpm2bDigest,
    pub command_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSessionAuditInfo {
    pub exclusive_session: TpmiYesNo,
    pub session_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsTimeInfo {
    pub time: u64,
    pub clock_info: TpmsClockInfo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsNvCertifyInfo {
    pub index_name: Tpm2bName,
    pub offset: u16,
    pub nv_contents: Tpm2bMaxNvBuffer,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub enum TpmuAttest {
    Certify(TpmsCertifyInfo) = TPM2ST::AttestCertify.0,
    Creation(TpmsCreationInfo) = TPM2ST::AttestCreation.0,
    Quote(TpmsQuoteInfo) = TPM2ST::AttestQuote.0,
    CommandAudit(TpmsCommandAuditInfo) = TPM2ST::AttestCommandAudit.0,
    SessionAudit(TpmsSessionAuditInfo) = TPM2ST::AttestSessionAudit.0,
    Time(TpmsTimeAttestInfo) = TPM2ST::AttestTime.0,
    Nv(TpmsNvCertifyInfo) = TPM2ST::AttestNV.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct TpmsAttest {
    pub magic: Tpm2Generated,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: TpmuAttest,
}
// Custom overload of Marshalable, because the selector for attested is {un}marshaled separate from the field.
impl Marshalable for TpmsAttest {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmResult<usize> {
        let mut written = 0;
        written += self.magic.try_marshal(&mut buffer[written..])?;
        written += self
            .attested
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.qualified_signer.try_marshal(&mut buffer[written..])?;
        written += self.extra_data.try_marshal(&mut buffer[written..])?;
        written += self.clock_info.try_marshal(&mut buffer[written..])?;
        written += self.firmware_version.try_marshal(&mut buffer[written..])?;
        written += self.attested.try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
        let magic = Tpm2Generated::try_unmarshal(buffer)?;
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmsAttest {
            magic,
            qualified_signer: Tpm2bName::try_unmarshal(buffer)?,
            extra_data: Tpm2bData::try_unmarshal(buffer)?,
            clock_info: TpmsClockInfo::try_unmarshal(buffer)?,
            firmware_version: u64::try_unmarshal(buffer)?,
            attested: TpmuAttest::try_unmarshal_variant(selector, buffer)?,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bAttest {
    size: u16,
    pub attestation_data: [u8; size_of::<TpmsAttest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSymKey {
    size: u16,
    pub buffer: [u8; TPM2_MAX_SYM_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bLabel {
    size: u16,
    pub buffer: [u8; TPM2_LABEL_MAX_BUFFER as usize],
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
    size: u16,
    pub buffer: [u8; size_of::<TpmsDerive>()],
}

#[repr(C, u16)]
enum TpmuSensitiveCreate {
    Create([u8; constants::TPM2_MAX_SYM_DATA as usize]),
    Derive(TpmsDerive),
}
impl TpmuSensitiveCreate {
    pub const fn union_size() -> usize {
        size_of::<TpmuSensitiveCreate>() - align_of::<TpmuSensitiveCreate>() - size_of::<u16>()
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveData {
    size: u16,
    pub buffer: [u8; TpmuSensitiveCreate::union_size()],
}

pub type Tpm2bAuth = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bAuth,
    pub data: Tpm2bSensitiveData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveCreate {
    size: u16,
    pub sensitive: [u8; size_of::<TpmsSensitiveCreate>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublicKeyRsa {
    size: u16,
    pub buffer: [u8; TPM2_MAX_RSA_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateKeyRsa {
    size: u16,
    pub buffer: [u8; (TPM2_MAX_RSA_KEY_BYTES / 2) as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccParameter {
    size: u16,
    pub buffer: [u8; TPM2_MAX_ECC_KEY_BYTES as usize],
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
    size: u16,
    pub point: [u8; size_of::<TpmsEccPoint>()],
}

#[repr(C, u16)]
enum TpmuEncryptedSecret {
    Ecc([u8; size_of::<TpmsEccPoint>()]),
    Rsa([u8; constants::TPM2_MAX_RSA_KEY_BYTES as usize]),
    Symmetric([u8; size_of::<Tpm2bDigest>()]),
    KeyedHash([u8; size_of::<Tpm2bDigest>()]),
}
impl TpmuEncryptedSecret {
    pub const fn union_size() -> usize {
        size_of::<TpmuEncryptedSecret>() - align_of::<TpmuEncryptedSecret>() - size_of::<u16>()
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEncryptedSecret {
    size: u16,
    pub secret: [u8; TpmuEncryptedSecret::union_size()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: TpmiAlgKdf,
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtKeyedHashScheme {
    Hmac(TpmsSchemeHmac) = TPM2AlgID::HMAC.0,
    ExclusiveOr(TpmsSchemeXor) = TPM2AlgID::XOR.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsKeyedHashParms {
    pub scheme: TpmtKeyedHashScheme,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtSymDefObject {
    Aes(TpmiAesKeyBits, TpmiAlgSymMode) = TPM2AlgID::AES.0,
    Sm4(TpmiSm4KeyBits, TpmiAlgSymMode) = TPM2AlgID::SM4.0,
    Camellia(TpmiCamelliaKeyBits, TpmiAlgSymMode) = TPM2AlgID::Camellia.0,
    ExclusiveOr(TpmiAlgHash, TpmsEmpty) = TPM2AlgID::XOR.0,
    Null(TpmsEmpty, TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSymCipherParms {
    pub sym: TpmtSymDefObject,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtRsaScheme {
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Rsaes(TpmsEncSchemeRsaes) = TPM2AlgID::RSAES.0,
    Oaep(TpmsEncSchemeOaep) = TPM2AlgID::OAEP.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: u32,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtEccScheme {
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Ecdh(TpmsKeySchemeEcdh) = TPM2AlgID::ECDH.0,
    Ecmqv(TpmsKeySchemeEcmqv) = TPM2AlgID::ECMQV.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

pub type TpmsSchemeMgf1 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_56a = TpmsSchemeHash;
pub type TpmsSchemeKdf2 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_108 = TpmsSchemeHash;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtKdfScheme {
    Mgf1(TpmsSchemeMgf1) = TPM2AlgID::MGF1.0,
    Kdf1Sp800_56a(TpmsSchemeKdf1Sp800_56a) = TPM2AlgID::KDF1SP80056A.0,
    Kdf2(TpmsSchemeKdf2) = TPM2AlgID::KDF2.0,
    Kdf1Sp800_108(TpmsSchemeKdf1Sp800_108) = TPM2AlgID::KDF1SP800108.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmiEccCurve,
    pub kdf: TpmtKdfScheme,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtAsymScheme {
    Ecdh(TpmsKeySchemeEcdh) = TPM2AlgID::ECDH.0,
    Ecmqv(TpmsKeySchemeEcmqv) = TPM2AlgID::ECMQV.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Rsaes(TpmsEncSchemeRsaes) = TPM2AlgID::RSAES.0,
    Oaep(TpmsEncSchemeOaep) = TPM2AlgID::OAEP.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsAsymParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtAsymScheme,
}

#[repr(C)]
union TpmuPublicId {
    pub keyed_hash: Tpm2bDigest,
    pub sym: Tpm2bDigest,
    pub rsa: Tpm2bPublicKeyRsa,
    pub ecc: TpmsEccPoint,
    pub derive: TpmsDerive,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum PublicParmsAndId {
    KeyedHash(TpmsKeyedHashParms, Tpm2bDigest) = TPM2AlgID::KeyedHash.0,
    Sym(TpmsSymCipherParms, Tpm2bDigest) = TPM2AlgID::SymCipher.0,
    Rsa(TpmsRsaParms, Tpm2bPublicKeyRsa) = TPM2AlgID::RSA.0,
    Ecc(TpmsEccParms, TpmsEccPoint) = TPM2AlgID::ECC.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmtPublic {
    pub name_alg: TpmiAlgHash,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parms_and_id: PublicParmsAndId,
}
// Custom overload of Marshalable, because the selector for parms_and_id is {un}marshaled first.
impl Marshalable for TpmtPublic {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmResult<usize> {
        let mut written = 0;
        written += self
            .parms_and_id
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.name_alg.try_marshal(&mut buffer[written..])?;
        written += self.object_attributes.try_marshal(&mut buffer[written..])?;
        written += self.auth_policy.try_marshal(&mut buffer[written..])?;
        written += self
            .parms_and_id
            .try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmtPublic {
            name_alg: TpmiAlgHash::try_unmarshal(buffer)?,
            object_attributes: TpmaObject::try_unmarshal(buffer)?,
            auth_policy: Tpm2bDigest::try_unmarshal(buffer)?,
            parms_and_id: PublicParmsAndId::try_unmarshal_variant(selector, buffer)?,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublic {
    size: u16,
    pub public_area: [u8; size_of::<TpmuPublicId>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bTemplate {
    size: u16,
    pub buffer: [u8; size_of::<TpmtPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateVendorSpecific {
    size: u16,
    pub buffer: [u8; TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES as usize],
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmuSensitiveComposite {
    Rsa(Tpm2bPrivateKeyRsa) = TPM2AlgID::RSA.0,
    Ecc(Tpm2bEccParameter) = TPM2AlgID::ECC.0,
    Bits(Tpm2bSensitiveData) = TPM2AlgID::KeyedHash.0,
    Sym(Tpm2bSymKey) = TPM2AlgID::SymCipher.0,
    /* For size purposes only */
    Any(Tpm2bPrivateVendorSpecific) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmtSensitive {
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TpmuSensitiveComposite,
}
// Custom overload of Marshalable, because the selector for sensitive is {un}marshaled first.
impl Marshalable for TpmtSensitive {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmResult<usize> {
        let mut written = 0;
        written += self
            .sensitive
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.auth_value.try_marshal(&mut buffer[written..])?;
        written += self.seed_value.try_marshal(&mut buffer[written..])?;
        written += self.sensitive.try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmtSensitive {
            auth_value: Tpm2bAuth::try_unmarshal(buffer)?,
            seed_value: Tpm2bDigest::try_unmarshal(buffer)?,
            sensitive: TpmuSensitiveComposite::try_unmarshal_variant(selector, buffer)?,
        })
    }
}

#[repr(C, u32)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub enum TpmsCapabilityData {
    Algorithms(TpmlAlgProperty) = TPM2Cap::Algs.0,
    Handles(TpmlHandle) = TPM2Cap::Handles.0,
    Command(TpmlCca) = TPM2Cap::Commands.0,
    PpCommands(TpmlCc) = TPM2Cap::PPCommands.0,
    AuditCommands(TpmlCc) = TPM2Cap::AuditCommands.0,
    AssignedPcr(TpmlPcrSelection) = TPM2Cap::PCRs.0,
    TpmProperties(TpmlTaggedTpmProperty) = TPM2Cap::TPMProperties.0,
    PcrProperties(TpmlTaggedPcrProperty) = TPM2Cap::PCRProperties.0,
    EccCurves(TpmlEccCurve) = TPM2Cap::ECCCurves.0,
    AuthPolicies(TpmlTaggedPolicy) = TPM2Cap::AuthPolicies.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmlAlgProperty {
    count: u32,
    #[length(count)]
    alg_properties: [TpmsAlgProperty; TPM2_MAX_CAP_ALGS],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmlHandle {
    count: u32,
    #[length(count)]
    handle: [TPM2Handle; TPM2_MAX_CAP_HANDLES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlCca {
    count: u32,
    #[length(count)]
    command_attributes: [TpmaCc; TPM2_MAX_CAP_CC],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmlCc {
    count: u32,
    #[length(count)]
    command_codes: [TPM2CC; TPM2_MAX_CAP_CC],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmlTaggedTpmProperty {
    pub count: u32,
    #[length(count)]
    tpm_property: [TpmsTaggedProperty; TPM2_MAX_TPM_PROPERTIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmlTaggedPcrProperty {
    count: u32,
    #[length(count)]
    pcr_property: [TpmsTaggedPcrSelect; TPM2_MAX_PCR_PROPERTIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmlEccCurve {
    count: u32,
    #[length(count)]
    ecc_curves: [TPM2ECCCurve; TPM2_MAX_ECC_CURVES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmlTaggedPolicy {
    count: u32,
    #[length(count)]
    policies: [TpmsTaggedPolicy; TPM2_MAX_TAGGED_POLICIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Marshal)]
pub struct TpmsAlgProperty {
    alg: u16,
    alg_properties: TpmaAlgorithm,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Marshal)]
pub struct TpmsTaggedProperty {
    pub property: u32,
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Marshal)]
pub struct TpmsTaggedPcrSelect {
    tag: u32,
    size_of_select: u8,
    #[length(size_of_select)]
    pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal, Default)]
pub struct TpmsTaggedPolicy {
    handle: u32,
    policy_hash: TpmtHa,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug, Marshal)]
pub struct TpmlDigest {
    count: u32,
    #[length(count)]
    digests: [Tpm2bDigest; 8],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitive {
    size: u16,
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
    size: u16,
    pub buffer: [u8; size_of::<_PRIVATE>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsIdObject {
    pub integrity_hmac: Tpm2bDigest,
    pub enc_identity: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIdObject {
    size: u16,
    pub credential: [u8; size_of::<TpmsIdObject>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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
    size: u16,
    pub nv_public: [u8; size_of::<TpmsNvPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextSensitive {
    size: u16,
    pub buffer: [u8; TPM2_MAX_CONTEXT_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsContextData {
    pub integrity: Tpm2bDigest,
    pub encrypted: Tpm2bContextSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextData {
    size: u16,
    pub buffer: [u8; size_of::<TpmsContextData>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmsCreationData {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
    pub locality: TpmaLocality,
    pub parent_name_alg: TPM2AlgID,
    pub parent_name: Tpm2bName,
    pub parent_qualified_name: Tpm2bName,
    pub outside_info: Tpm2bData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bCreationData {
    size: u16,
    pub creation_data: [u8; size_of::<TpmsCreationData>()],
}

// Helper for splitting up ranges of an unmarshal buffer.

pub trait Tpm2bSimple {
    const MAX_BUFFER_SIZE: usize;
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &[u8];
    fn from_bytes(buffer: &[u8]) -> TpmResult<Self>
    where
        Self: Sized;
}

macro_rules! impl_try_marshalable_tpm2b_simple {
    ($T:ty, $F:ident) => {
        impl Tpm2bSimple for $T {
            const MAX_BUFFER_SIZE: usize = size_of::<$T>() - size_of::<u16>();

            fn get_size(&self) -> u16 {
                self.size
            }

            fn get_buffer(&self) -> &[u8] {
                &self.$F[0..self.get_size() as usize]
            }

            fn from_bytes(buffer: &[u8]) -> TpmResult<Self> {
                // Overflow check
                if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
                    return Err(TpmError::TSS2_MU_RC_BAD_SIZE);
                }

                let mut dest: Self = Self {
                    size: buffer.len() as u16,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };
                dest.$F[..buffer.len()].copy_from_slice(buffer);
                Ok(dest)
            }
        }

        impl Default for $T {
            fn default() -> Self {
                Self {
                    size: 0,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                }
            }
        }

        impl Marshalable for $T {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
                let got_size = u16::try_unmarshal(buffer)?;
                // Ensure the buffer is large enough to fullfill the size indicated
                let sized_buffer = buffer.get(got_size as usize);
                if !sized_buffer.is_some() {
                    return Err(TpmError::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                let mut dest: Self = Self {
                    size: got_size,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };

                // Make sure the size indicated isn't too large for the types buffer
                if sized_buffer.unwrap().len() > dest.$F.len() {
                    return Err(TpmError::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }
                dest.$F[..got_size.into()].copy_from_slice(&sized_buffer.unwrap());

                Ok(dest)
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> TpmResult<usize> {
                let used = self.size.try_marshal(buffer)?;
                let (_, rest) = buffer.split_at_mut(used);
                let buffer_marsh = self.get_size() as usize;
                if buffer_marsh > (core::cmp::max(Self::MAX_BUFFER_SIZE, rest.len())) {
                    return Err(TpmError::TSS2_MU_RC_INSUFFICIENT_BUFFER);
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

            let mut s = (smaller_size_buf.len() - SIZE_OF_U16) as u16;
            assert!(s.try_marshal(&mut smaller_size_buf).is_ok());

            s = (same_size_buf.len() - SIZE_OF_U16) as u16;
            assert!(s.try_marshal(&mut same_size_buf).is_ok());

            s = (bigger_size_buf.len() - SIZE_OF_U16) as u16;
            assert!(s.try_marshal(&mut bigger_size_buf).is_ok());

            // too small should fail
            let mut result: TpmResult<$T> =
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
            offset: 10,
            nv_contents,
        };
        let mut marshal_buffer = [0u8; 48];
        let bytes = info.try_marshal(&mut marshal_buffer).unwrap();

        // Build the expected output manually.
        let mut expected = Vec::with_capacity(bytes);
        expected.extend_from_slice(&index_name.get_size().to_be_bytes());
        expected.extend_from_slice(&name_buffer);
        expected.extend_from_slice(&info.offset.to_be_bytes());
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
            hash_alg: TpmiAlgHash(TPM2AlgID::SHA256),
        };
        let scheme = TpmtKeyedHashScheme::Hmac(hmac);
        let mut buffer = [0u8; size_of::<TpmtKeyedHashScheme>()];
        assert!(scheme.try_marshal(&mut buffer).is_ok());
    }

    #[test]
    fn test_marshal_tpmt_public() {
        let xor_sym_def_obj =
            TpmtSymDefObject::ExclusiveOr(TpmiAlgHash(TPM2AlgID::SHA256), TpmsEmpty {});
        let mut buffer = [0u8; size_of::<TpmtSymDefObject>()];
        let mut marsh = xor_sym_def_obj.try_marshal(&mut buffer);
        // Because XOR does not populate TpmuSymMode, we have bytes left over.
        assert!(marsh.unwrap() < buffer.len());
        let rsa_scheme = TpmtRsaScheme::Ecdsa(TpmsSigSchemeEcdsa {
            hash_alg: TpmiAlgHash(TPM2AlgID::SHA256),
        });

        let rsa_parms = TpmsRsaParms {
            symmetric: xor_sym_def_obj,
            scheme: rsa_scheme,
            key_bits: TpmiRsaKeyBits(74),
            exponent: 2,
        };

        let pubkey_buf = [9u8; 24];
        let pubkey = Tpm2bPublicKeyRsa::from_bytes(&pubkey_buf).unwrap();

        let example = TpmtPublic {
            name_alg: TpmiAlgHash(TPM2AlgID::SHA256),
            object_attributes: TpmaObject(6543),
            auth_policy: Tpm2bDigest::from_bytes(&[2, 2, 4, 4]).unwrap(),
            parms_and_id: PublicParmsAndId::Rsa(rsa_parms, pubkey),
        };

        // Test a round-trip marshaling and unmarshaling, confirm that we get the same output.
        let mut buffer = [0u8; 256];
        marsh = example.try_marshal(&mut buffer);
        assert!(marsh.is_ok());
        let expected: [u8; 54] = [
            0, 1, 0, 11, 0, 0, 25, 143, 0, 4, 2, 2, 4, 4, 0, 10, 0, 11, 0, 24, 0, 11, 0, 74, 0, 0,
            0, 2, 0, 24, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        ];
        //assert_eq!(expected.len(), marsh.unwrap());
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
        assert!(TPM2AlgID::SHA256.try_marshal(&mut buffer).is_ok());
        unmarsh = TpmtPublic::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert_eq!(unmarsh.err(), Some(TpmError::TPM2_RC_SELECTOR));
    }
}
