#![allow(dead_code, clippy::large_enum_variant)]
#![cfg_attr(not(test), no_std)]

use crate::{constants::*, errors::*, marshal::*};
use core::mem::{align_of, size_of};
use marshal_derive::Marshal;
use zerocopy::byteorder::big_endian::*;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmaLocality(u8);

// Todo use U16<BE> instead to make it less subtle
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct Tpm2AlgId(U16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct Tpm2KeyBits(U16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct Tpm2St(U16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct Tpm2Generated(U32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct Tpm2Handle(U32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmaNv(U32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgHash(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgKdf(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgPublic(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgSymMode(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgSymObject(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgKeyedhashScheme(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgRsaScheme(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgEccScheme(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAlgAsymScheme(U16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiRhNvIndex(U32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct Tpm2EccCurve(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiEccCurve(U16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiYesNo(u8);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiStAttest(U16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiAesKeyBits(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiSm4KeyBits(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiCamelliaKeyBits(U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiRsaKeyBits(U16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmaObject(U32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmCap(U32);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmaAlgorithm(U32);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmaCc(U32);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmHandle(U32);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmCc(pub U32);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmPt(U32);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmPtPcr(U32);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmEccCurve(U16);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmSt(pub U16);
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, AsBytes, FromBytes, FromZeroes)]
pub struct TpmiStCommandTag(pub U16);

const TPM2_MAX_CAP_DATA: usize =
    TPM2_MAX_CAP_BUFFER as usize - size_of::<TpmCap>() - size_of::<u32>();
const TPM2_MAX_CAP_ALGS: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsAlgProperty>();
const TPM2_MAX_CAP_HANDLES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmHandle>();
const TPM2_MAX_CAP_CC: usize = TPM2_MAX_CAP_DATA / size_of::<TpmCc>();
const TPM2_MAX_TPM_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedProperty>();
const TPM2_MAX_PCR_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPcrSelect>();
const TPM2_MAX_ECC_CURVES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmEccCurve>();
const TPM2_MAX_TAGGED_POLICIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPolicy>();

pub mod commands;
pub mod constants;
pub mod crypto;
pub mod structures;
pub mod errors;
pub mod storage;
pub mod marshal;
pub mod server;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct TpmsEmpty;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtHa {
    Sha1([u8; constants::TPM2_SHA_DIGEST_SIZE as usize]) = TPM2_ALG_SHA1,
    Sha256([u8; constants::TPM2_SHA256_DIGEST_SIZE as usize]) = TPM2_ALG_SHA256,
    Sha384([u8; constants::TPM2_SHA384_DIGEST_SIZE as usize]) = TPM2_ALG_SHA384,
    Sha512([u8; constants::TPM2_SHA512_DIGEST_SIZE as usize]) = TPM2_ALG_SHA512,
    Sm3_256([u8; constants::TPM2_SM3_256_DIGEST_SIZE as usize]) = TPM2_ALG_SM3_256,
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
    Handle(Tpm2Handle),
}
impl TpmuName {
    pub const fn union_size() -> usize {
        size_of::<TpmuName>() - align_of::<TpmuName>() - size_of::<u16>()
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDigest {
    size: U16,
    pub buffer: [u8; TpmtHa::union_size()],
}

type Tpm2bNonce = Tpm2bDigest;
type Tpm2bOperand = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bData {
    size: U16,
    pub buffer: [u8; TpmtHa::union_size()],
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
    pub name: [u8; TpmuName::union_size()],
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
    pub count: U32,
    #[length(count)]
    pub pcr_selections: [TpmsPcrSelection; constants::TPM2_NUM_PCR_BANKS as usize],
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
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCommandAuditInfo {
    pub audit_counter: U64,
    pub digest_alg: Tpm2AlgId,
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
    pub time: U64,
    pub clock_info: TpmsClockInfo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: U64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsNvCertifyInfo {
    pub index_name: Tpm2bName,
    pub offset: U16,
    pub nv_contents: Tpm2bMaxNvBuffer,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmuAttest {
    Certify(TpmsCertifyInfo) = TPM2_ST_ATTEST_CERTIFY,
    Creation(TpmsCreationInfo) = TPM2_ST_ATTEST_CREATION,
    Quote(TpmsQuoteInfo) = TPM2_ST_ATTEST_QUOTE,
    CommandAudit(TpmsCommandAuditInfo) = TPM2_ST_ATTEST_COMMAND_AUDIT,
    SessionAudit(TpmsSessionAuditInfo) = TPM2_ST_ATTEST_SESSION_AUDIT,
    Time(TpmsTimeAttestInfo) = TPM2_ST_ATTEST_TIME,
    Nv(TpmsNvCertifyInfo) = TPM2_ST_ATTEST_NV,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsAttest {
    pub magic: Tpm2Generated,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: U64,
    pub attested: TpmuAttest,
}
// Custom overload of Marshalable, because the selector for attested is {un}marshaled separate from the field.
impl Marshalable for TpmsAttest {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmResult<usize> {
        let mut written = 0;
        written += self.magic.try_marshal(&mut buffer[written..])?;
        written += U16::new(self.attested.discriminant()).try_marshal(&mut buffer[written..])?;
        written += self.qualified_signer.try_marshal(&mut buffer[written..])?;
        written += self.extra_data.try_marshal(&mut buffer[written..])?;
        written += self.clock_info.try_marshal(&mut buffer[written..])?;
        written += self.firmware_version.try_marshal(&mut buffer[written..])?;
        written += self.attested.try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
        let magic = Tpm2Generated::try_unmarshal(buffer)?;
        let selector = U16::try_unmarshal(buffer)?;
        Ok(TpmsAttest {
            magic,
            qualified_signer: Tpm2bName::try_unmarshal(buffer)?,
            extra_data: Tpm2bData::try_unmarshal(buffer)?,
            clock_info: TpmsClockInfo::try_unmarshal(buffer)?,
            firmware_version: U64::try_unmarshal(buffer)?,
            attested: TpmuAttest::try_unmarshal_variant(selector.get(), buffer)?,
        })
    }
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
    size: U16,
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
    size: U16,
    pub secret: [u8; TpmuEncryptedSecret::union_size()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: TpmiAlgKdf,
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtKeyedHashScheme {
    Hmac(TpmsSchemeHmac) = TPM2_ALG_HMAC,
    ExclusiveOr(TpmsSchemeXor) = TPM2_ALG_XOR,
    Null(TpmsEmpty) = TPM2_ALG_NONE,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsKeyedHashParms {
    pub scheme: TpmtKeyedHashScheme,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtSymDefObject {
    Aes(TpmiAesKeyBits, TpmiAlgSymMode) = TPM2_ALG_AES,
    Sm4(TpmiSm4KeyBits, TpmiAlgSymMode) = TPM2_ALG_SM4,
    Camellia(TpmiCamelliaKeyBits, TpmiAlgSymMode) = TPM2_ALG_CAMELLIA,
    ExclusiveOr(TpmiAlgHash, TpmsEmpty) = TPM2_ALG_XOR,
    Null(TpmsEmpty, TpmsEmpty) = TPM2_ALG_NONE,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtRsaScheme {
    Rsapss(TpmsSigSchemeRsapss) = TPM2_ALG_RSAPSS,
    Rsassa(TpmsSigSchemeRsassa) = TPM2_ALG_RSASSA,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2_ALG_ECDSA,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2_ALG_ECDAA,
    Sm2(TpmsSigSchemeSm2) = TPM2_ALG_SM2,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2_ALG_ECSCHNORR,
    Rsaes(TpmsEncSchemeRsaes) = TPM2_ALG_RSAES,
    Oaep(TpmsEncSchemeOaep) = TPM2_ALG_OAEP,
    Null(TpmsEmpty) = TPM2_ALG_NONE,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: U32,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtEccScheme {
    Rsapss(TpmsSigSchemeRsapss) = TPM2_ALG_RSAPSS,
    Rsassa(TpmsSigSchemeRsassa) = TPM2_ALG_RSASSA,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2_ALG_ECDSA,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2_ALG_ECDAA,
    Sm2(TpmsSigSchemeSm2) = TPM2_ALG_SM2,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2_ALG_ECSCHNORR,
    Ecdh(TpmsKeySchemeEcdh) = TPM2_ALG_ECDH,
    Ecmqv(TpmsKeySchemeEcmqv) = TPM2_ALG_ECMQV,
    Null(TpmsEmpty) = TPM2_ALG_NONE,
}

pub type TpmsSchemeMgf1 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_56a = TpmsSchemeHash;
pub type TpmsSchemeKdf2 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_108 = TpmsSchemeHash;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtKdfScheme {
    Mgf1(TpmsSchemeMgf1) = TPM2_ALG_MGF1,
    Kdf1Sp800_56a(TpmsSchemeKdf1Sp800_56a) = TPM2_ALG_KDF1_SP800_56A,
    Kdf2(TpmsSchemeKdf2) = TPM2_ALG_KDF2,
    Kdf1Sp800_108(TpmsSchemeKdf1Sp800_108) = TPM2_ALG_KDF1_SP800_108,
    Null(TpmsEmpty) = TPM2_ALG_NONE,
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
    Ecdh(TpmsKeySchemeEcdh) = TPM2_ALG_ECDH,
    Ecmqv(TpmsKeySchemeEcmqv) = TPM2_ALG_ECMQV,
    Sm2(TpmsSigSchemeSm2) = TPM2_ALG_SM2,
    Rsapss(TpmsSigSchemeRsapss) = TPM2_ALG_RSAPSS,
    Rsassa(TpmsSigSchemeRsassa) = TPM2_ALG_RSASSA,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2_ALG_ECDSA,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2_ALG_ECDAA,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2_ALG_ECSCHNORR,
    Rsaes(TpmsEncSchemeRsaes) = TPM2_ALG_RSAES,
    Oaep(TpmsEncSchemeOaep) = TPM2_ALG_OAEP,
    Null(TpmsEmpty) = TPM2_ALG_NONE,
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
    KeyedHash(TpmsKeyedHashParms, Tpm2bDigest) = TPM2_ALG_KEYEDHASH,
    Sym(TpmsSymCipherParms, Tpm2bDigest) = TPM2_ALG_SYMCIPHER,
    Rsa(TpmsRsaParms, Tpm2bPublicKeyRsa) = TPM2_ALG_RSA,
    Ecc(TpmsEccParms, TpmsEccPoint) = TPM2_ALG_ECC,
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
        written +=
            U16::new(self.parms_and_id.discriminant()).try_marshal(&mut buffer[written..])?;
        written += self.name_alg.try_marshal(&mut buffer[written..])?;
        written += self.object_attributes.try_marshal(&mut buffer[written..])?;
        written += self.auth_policy.try_marshal(&mut buffer[written..])?;
        written += self
            .parms_and_id
            .try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
        let selector = U16::try_unmarshal(buffer)?;
        Ok(TpmtPublic {
            name_alg: TpmiAlgHash::try_unmarshal(buffer)?,
            object_attributes: TpmaObject::try_unmarshal(buffer)?,
            auth_policy: Tpm2bDigest::try_unmarshal(buffer)?,
            parms_and_id: PublicParmsAndId::try_unmarshal_variant(selector.get(), buffer)?,
        })
    }
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

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmuSensitiveComposite {
    Rsa(Tpm2bPrivateKeyRsa) = TPM2_ALG_RSA,
    Ecc(Tpm2bEccParameter) = TPM2_ALG_ECC,
    Bits(Tpm2bSensitiveData) = TPM2_ALG_KEYEDHASH,
    Sym(Tpm2bSymKey) = TPM2_ALG_SYMCIPHER,
    /* For size purposes only */
    Any(Tpm2bPrivateVendorSpecific) = TPM2_ALG_NONE,
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
        written += U16::new(self.sensitive.discriminant()).try_marshal(&mut buffer[written..])?;
        written += self.auth_value.try_marshal(&mut buffer[written..])?;
        written += self.seed_value.try_marshal(&mut buffer[written..])?;
        written += self.sensitive.try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
        let selector = U16::try_unmarshal(buffer)?;
        Ok(TpmtSensitive {
            auth_value: Tpm2bAuth::try_unmarshal(buffer)?,
            seed_value: Tpm2bDigest::try_unmarshal(buffer)?,
            sensitive: TpmuSensitiveComposite::try_unmarshal_variant(selector.get(), buffer)?,
        })
    }
}

#[repr(C, u32)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmsCapabilityData {
    Algorithms(TpmlAlgProperty) = TPM2_CAP_ALGS,
    Handles(TpmlHandle) = TPM2_CAP_HANDLES,
    Command(TpmlCca) = TPM2_CAP_COMMANDS,
    PpCommands(TpmlCc) = TPM2_CAP_PP_COMMANDS,
    AuditCommands(TpmlCc) = TPM2_CAP_AUDIT_COMMANDS,
    AssignedPcr(TpmlPcrSelection) = TPM2_CAP_PCRS,
    TpmProperties(TpmlTaggedTpmProperty) = TPM2_CAP_TPM_PROPERTIES,
    PcrProperties(TpmlTaggedPcrProperty) = TPM2_CAP_PCR_PROPERTIES,
    EccCurves(TpmlEccCurve) = TPM2_CAP_ECC_CURVES,
    AuthPolicies(TpmlTaggedPolicy) = TPM2_CAP_AUTH_POLICIES,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlAlgProperty {
    count: U32,
    #[length(count)]
    alg_properties: [TpmsAlgProperty; TPM2_MAX_CAP_ALGS],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlHandle {
    count: U32,
    #[length(count)]
    handle: [TpmHandle; TPM2_MAX_CAP_HANDLES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlCca {
    count: U32,
    #[length(count)]
    command_attributes: [TpmaCc; TPM2_MAX_CAP_CC],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlCc {
    count: U32,
    #[length(count)]
    command_codes: [TpmCc; TPM2_MAX_CAP_CC],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlTaggedTpmProperty {
    count: U32,
    #[length(count)]
    tpm_property: [TpmsTaggedProperty; TPM2_MAX_TPM_PROPERTIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlTaggedPcrProperty {
    count: U32,
    #[length(count)]
    pcr_property: [TpmsTaggedPcrSelect; TPM2_MAX_PCR_PROPERTIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlEccCurve {
    count: U32,
    #[length(count)]
    ecc_curves: [TpmEccCurve; TPM2_MAX_ECC_CURVES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlTaggedPolicy {
    count: U32,
    #[length(count)]
    policies: [TpmsTaggedPolicy; TPM2_MAX_TAGGED_POLICIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmsAlgProperty {
    alg: Tpm2AlgId,
    alg_properties: TpmaAlgorithm,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmsTaggedProperty {
    property: TpmPt,
    value: U32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmsTaggedPcrSelect {
    tag: TpmPtPcr,
    size_of_select: u8,
    #[length(size_of_select)]
    pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal, Default)]
pub struct TpmsTaggedPolicy {
    handle: TpmHandle,
    policy_hash: TpmtHa,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug, Marshal)]
pub struct TpmlDigest {
    count: U32,
    #[length(count)]
    digests: [Tpm2bDigest; 8],
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
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsNvPublic {
    pub nv_index: TpmiRhNvIndex,
    pub name_alg: TpmiAlgHash,
    pub attributes: TpmaNv,
    pub auth_policy: Tpm2bDigest,
    pub data_size: U16,
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
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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
    fn from_bytes(buffer: &[u8]) -> TpmResult<Self>
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

            fn from_bytes(buffer: &[u8]) -> TpmResult<Self> {
                // Overflow check
                if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
                    return Err(TpmError::TSS2_MU_RC_BAD_SIZE);
                }

                let mut dest: Self = Self {
                    size: U16::new(buffer.len() as u16),
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };
                dest.$F[..buffer.len()].copy_from_slice(buffer);
                Ok(dest)
            }
        }

        impl Default for $T {
            fn default() -> Self {
                Self {
                    size: U16::ZERO,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                }
            }
        }

        impl Marshalable for $T {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
                let got_size = U16::try_unmarshal(buffer)?;
                // Ensure the buffer is large enough to fullfill the size indicated
                let sized_buffer = buffer.get(got_size.get() as usize);
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

            let mut s = U16::from((smaller_size_buf.len() - SIZE_OF_U16) as u16);
            assert!(s.try_marshal(&mut smaller_size_buf).is_ok());

            s = U16::from((same_size_buf.len() - SIZE_OF_U16) as u16);
            assert!(s.try_marshal(&mut same_size_buf).is_ok());

            s = U16::from((bigger_size_buf.len() - SIZE_OF_U16) as u16);
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
            hash_alg: TpmiAlgHash(U16::new(0xB)),
        };
        let scheme = TpmtKeyedHashScheme::Hmac(hmac);
        let mut buffer = [0u8; size_of::<TpmtKeyedHashScheme>()];
        assert!(scheme.try_marshal(&mut buffer).is_ok());
    }

    #[test]
    fn test_marshal_tpmt_public() {
        let xor_sym_def_obj =
            TpmtSymDefObject::ExclusiveOr(TpmiAlgHash(U16::new(TPM2_ALG_SHA256)), TpmsEmpty {});
        let mut buffer = [0u8; size_of::<TpmtSymDefObject>()];
        let mut marsh = xor_sym_def_obj.try_marshal(&mut buffer);
        // Because XOR does not populate TpmuSymMode, we have bytes left over.
        assert!(marsh.unwrap() < buffer.len());
        let rsa_scheme = TpmtRsaScheme::Ecdsa(TpmsSigSchemeEcdsa {
            hash_alg: TpmiAlgHash(U16::from(TPM2_ALG_SHA256)),
        });

        let rsa_parms = TpmsRsaParms {
            symmetric: xor_sym_def_obj,
            scheme: rsa_scheme,
            key_bits: TpmiRsaKeyBits(U16::new(74)),
            exponent: U32::new(2),
        };

        let pubkey_buf = [9u8; 24];
        let pubkey = Tpm2bPublicKeyRsa::from_bytes(&pubkey_buf).unwrap();

        let example = TpmtPublic {
            name_alg: TpmiAlgHash(U16::new(TPM2_ALG_SHA256)),
            object_attributes: TpmaObject(U32::new(6543)),
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
        assert!(U16::new(TPM2_ALG_SHA256).try_marshal(&mut buffer).is_ok());
        unmarsh = TpmtPublic::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert_eq!(unmarsh.err(), Some(TpmError::TPM2_RC_SELECTOR));
    }
}
