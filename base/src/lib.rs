#![allow(dead_code)]
use std::mem;

pub type TpmaLocality = u8;

pub type Tpm2AlgId = u16;
pub type Tpm2KeyBits = u16;
pub type Tpm2St = u16;

pub type Tpm2Generated = u32;
pub type Tpm2Handle = u32;
pub type Tpm2Rc = u32;
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

pub type Tpm2EccCurve = u16;
pub type TpmiEccCurve = Tpm2EccCurve;

pub type TpmiYesNo = u8;
pub type TpmiStAttest = Tpm2St;

pub type TpmiAesKeyBits = Tpm2KeyBits;
pub type TpmiSm4KeyBits = Tpm2KeyBits;
pub type TpmiCamelliaKeyBits = Tpm2KeyBits;
pub type TpmiRsaKeyBits = Tpm2KeyBits;

pub type TpmaObject = u32;

pub type Tss2Rc = Tpm2Rc;

mod constants;
mod error_codes;

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
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmuHa>()],
}

type Tpm2bNonce = Tpm2bDigest;
type Tpm2bOperand = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bData {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmuHa>()],
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
    pub buffer: [u8; constants::TPM2_MAX_DIGEST_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxNvBuffer {
    size: u16,
    pub buffer: [u8; constants::TPM2_MAX_NV_BUFFER_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIv {
    size: u16,
    pub buffer: [u8; constants::TPM2_MAX_SYM_BLOCK_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bName {
    size: u16,
    pub name: [u8; mem::size_of::<TpmuName>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxCapBuffer {
    size: u16,
    pub buffer: [u8; constants::TPM2_MAX_CAP_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: TpmiYesNo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsPcrSelection {
    pub hash: TpmiAlgHash,
    pub sizeof_select: u8,
    pub pcr_select: [u8; constants::TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmlPcrSelection {
    pub count: u32,
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
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsTimeInfo {
    pub time: u64,
    pub clock_info: TpmsClockInfo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsNvCertifyInfo {
    pub index_name: Tpm2bName,
    pub offset: u16,
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
    size: u16,
    pub attestation_data: [u8; mem::size_of::<TpmsAttest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSymKey {
    size: u16,
    pub buffer: [u8; constants::TPM2_MAX_SYM_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bLabel {
    size: u16,
    pub buffer: [u8; constants::TPM2_LABEL_MAX_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsDerive {
    pub label: Tpm2bLabel,
    pub context: Tpm2bLabel,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDerive {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmsDerive>()],
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
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmuSensitiveCreate>()],
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
    size: u16,
    pub sensitive: [u8; mem::size_of::<TpmsSensitiveCreate>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublicKeyRsa {
    size: u16,
    pub buffer: [u8; constants::TPM2_MAX_RSA_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateKeyRsa {
    size: u16,
    pub buffer: [u8; (constants::TPM2_MAX_RSA_KEY_BYTES / 2) as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccParameter {
    size: u16,
    pub buffer: [u8; constants::TPM2_MAX_ECC_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsEccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccPoint {
    size: u16,
    pub point: [u8; mem::size_of::<TpmsEccPoint>()],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuEncryptedSecret {
    pub ecc: [u8; mem::size_of::<TpmsEccPoint>()],
    pub rsa: [u8; constants::TPM2_MAX_RSA_KEY_BYTES as usize],
    pub symmetric: [u8; mem::size_of::<Tpm2bDigest>()],
    pub keyed_hash: [u8; mem::size_of::<Tpm2bDigest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEncryptedSecret {
    size: u16,
    pub secret: [u8; mem::size_of::<TpmuEncryptedSecret>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtKeyedHashScheme {
    pub scheme: TpmiAlgKeyedhashScheme,
    pub details: TpmuSchemeKeyedHash,
}

#[repr(C)]
#[derive(Clone, Copy)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtSymDefObject {
    pub algorithm: TpmiAlgSymObject,
    pub key_bits: TpmuSymKeyBits,
    pub mode: TpmuSymMode,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsSymCipherParms {
    pub sym: TpmtSymDefObject,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtRsaScheme {
    pub scheme: TpmiAlgRsaScheme,
    pub details: TpmuAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtEccScheme {
    pub scheme: TpmiAlgEccScheme,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtKdfScheme {
    pub scheme: TpmiAlgKdf,
    pub details: TpmuKdfScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmiEccCurve,
    pub kdf: TpmtKdfScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtAsymScheme {
    pub scheme: TpmiAlgAsymScheme,
    pub details: TpmuAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuPublicId {
    pub keyed_hash: Tpm2bDigest,
    pub sym: Tpm2bDigest,
    pub rsa: Tpm2bPublicKeyRsa,
    pub ecc: TpmsEccPoint,
    pub derive: TpmsDerive,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtPublic {
    pub tipe: TpmiAlgPublic,
    pub name_alg: TpmiAlgHash,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parameters: TpmuPublicParms,
    pub unique: TpmuPublicId,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublic {
    size: u16,
    pub public_area: [u8; mem::size_of::<TpmuPublicId>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bTemplate {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmtPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateVendorSpecific {
    size: u16,
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
    size: u16,
    pub sensitive_area: [u8; mem::size_of::<TpmtSensitive>()],
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
    pub buffer: [u8; mem::size_of::<_PRIVATE>()],
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
    size: u16,
    pub credential: [u8; mem::size_of::<TpmsIdObject>()],
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
    size: u16,
    pub nv_public: [u8; mem::size_of::<TpmsNvPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextSensitive {
    size: u16,
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
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmsContextData>()],
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
    size: u16,
    pub creation_data: [u8; mem::size_of::<TpmsCreationData>()],
}

pub trait Marshalable {
    fn untry_marshal(buffer: &[u8]) -> Result<(Self, usize), Tpm2Rc>
    where
        Self: Sized;

    fn try_marshal(&self) -> Vec<u8>;
}

pub trait Tpm2bSimple {
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &[u8];
    fn from_bytes(buffer: &[u8]) -> Result<Self, Tpm2Rc>
    where
        Self: Sized;
}

macro_rules! impl_try_marshalable_scalar {
    ($T:ty) => {
        impl Marshalable for $T {
            fn untry_marshal(buffer: &[u8]) -> Result<(Self, usize), Tss2Rc>
            where
                Self: Sized,
            {
                if buffer.len() < std::mem::size_of::<$T>() {
                    return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                let (int_bytes, _) = buffer.split_at(std::mem::size_of::<$T>());

                let r = <$T>::from_be_bytes(int_bytes.try_into().unwrap());
                Ok((r, int_bytes.len().into()))
            }

            fn try_marshal(&self) -> Vec<u8> {
                let mut vec = Vec::new();

                let be_bytes = self.to_be_bytes();
                vec.extend_from_slice(&be_bytes);

                vec
            }
        }
    };
}

impl_try_marshalable_scalar! { u8 }
impl_try_marshalable_scalar! { u16 }
impl_try_marshalable_scalar! { u32 }
impl_try_marshalable_scalar! { u64 }
impl_try_marshalable_scalar! { i8 }
impl_try_marshalable_scalar! { i16 }
impl_try_marshalable_scalar! { i32 }
impl_try_marshalable_scalar! { i64 }

macro_rules! impl_try_marshalable_tpm2b_simple {
    ($T:ty, $F:ident) => {
        impl Tpm2bSimple for $T {
            fn get_size(&self) -> u16 {
                self.size
            }

            fn get_buffer(&self) -> &[u8] {
                &self.$F[0..self.get_size() as usize]
            }

            fn from_bytes(buffer: &[u8]) -> Result<Self, Tpm2Rc> {
                // Overflow check
                if buffer.len() > u16::MAX as usize {
                    return Err(error_codes::TSS2_MU_RC_BAD_SIZE);
                }

                let mut dest: Self = Self {
                    size: buffer.len() as u16,
                    $F: [0; std::mem::size_of::<$T>() - std::mem::size_of::<u16>()],
                };

                for (dst, src) in dest.$F.iter_mut().zip(buffer) {
                    *dst = *src
                }

                Ok(dest)
            }
        }

        impl Marshalable for $T {
            fn untry_marshal(buffer: &[u8]) -> Result<(Self, usize), Tpm2Rc> {
                // split_at panics, so we make sure to avoid that condition
                if buffer.len() < std::mem::size_of::<u16>() {
                    return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                // Split it at the sizeof(u16), ie the first two bytes
                let (int_bytes, rest) = buffer.split_at(std::mem::size_of::<u16>());
                let temp = int_bytes.try_into();
                if temp.is_err() {
                    return Err(error_codes::TSS2_BASE_RC_GENERAL_FAILURE);
                }
                let be_size_bytes: [u8; 2] = temp.unwrap();
                let got_size: u16 = u16::from_be_bytes(be_size_bytes);

                // Ensure the buffer is large enough to fullfill the size indicated
                if rest.len() != got_size.into() {
                    return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                let mut dest: Self = Self {
                    size: got_size,
                    // TODO best way?
                    $F: [0; std::mem::size_of::<$T>() - std::mem::size_of::<u16>()],
                };

                // Make sure the size indicated isn't too large for the types buffer
                if rest.len() > dest.$F.len() {
                    return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                let (field_data_buf, _) = rest.split_at(got_size.into());

                // panicked at 'source slice length (5) does not match destination slice length (68)',
                //dest.name.clone_from_slice(buffer_data);
                for (dst, src) in dest.$F.iter_mut().zip(field_data_buf) {
                    *dst = *src
                }

                Ok((dest, std::mem::size_of::<u16>() + usize::from(got_size)))
            }

            fn try_marshal(&self) -> Vec<u8> {
                let mut vec = Vec::new();

                let be_bytes = self.size.to_be_bytes();
                vec.extend_from_slice(&be_bytes);
                vec.extend_from_slice(&self.$F);

                vec
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

#[cfg(test)]
mod tests {
    use crate::{
        Marshalable, Tpm2Rc, Tpm2bAttest, Tpm2bContextData, Tpm2bContextSensitive, Tpm2bData,
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bEvent, Tpm2bIdObject, Tpm2bIv,
        Tpm2bMaxBuffer, Tpm2bMaxNvBuffer, Tpm2bName, Tpm2bPrivate, Tpm2bPrivateKeyRsa,
        Tpm2bPrivateVendorSpecific, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSimple,
        Tpm2bSymKey, Tpm2bTemplate,
    };

    // Unfortunately, I didn't see a way to generate a function name easily, see
    // https://github.com/rust-lang/rust/issues/29599 for more details. So we just
    // generate the test body here.
    macro_rules! impl_test_tpm2b_simple {
        ($T:ty) => {
            const SIZE_OF_U16: usize = std::mem::size_of::<u16>();
            const SIZE_OF_TYPE: usize = std::mem::size_of::<$T>();
            const SIZE_OF_BUFFER: usize = SIZE_OF_TYPE - SIZE_OF_U16;

            /*
             * Generate arrays that are:
             *   - too small
             *   - smaller than buffer limit
             *   - same size as buffer limit
             *   - exceeding buffer limit
             */
            let too_small_size_buf: [u8; 1] = [0x00; 1];
            let mut smaller_size_buf: [u8; SIZE_OF_TYPE - 8] = [0xFF; SIZE_OF_TYPE - 8];
            let mut same_size_buf: [u8; SIZE_OF_TYPE] = [0xFF; SIZE_OF_TYPE];
            let mut bigger_size_buf: [u8; SIZE_OF_TYPE + 8] = [0xFF; SIZE_OF_TYPE + 8];

            let mut s: u16 = (smaller_size_buf.len() - SIZE_OF_U16) as u16;
            let mut b: Vec<u8> = s.try_marshal();

            let mut index: usize = 0;
            while index < b.len() {
                smaller_size_buf[index] = b[index];
                index += 1;
            }

            s = (same_size_buf.len() - SIZE_OF_U16) as u16;
            b = s.try_marshal();

            index = 0;
            while index < b.len() {
                same_size_buf[index] = b[index];
                index += 1;
            }

            s = (bigger_size_buf.len() - SIZE_OF_U16) as u16;
            b = s.try_marshal();

            index = 0;
            while index < b.len() {
                bigger_size_buf[index] = b[index];
                index += 1;
            }

            // too small should fail
            let mut result: Result<($T, usize), Tpm2Rc> = <$T>::untry_marshal(&too_small_size_buf);
            assert!(result.is_err());

            // bigger size should fail
            result = <$T>::untry_marshal(&bigger_size_buf);
            assert!(result.is_err());

            // small, should be good
            result = <$T>::untry_marshal(&smaller_size_buf);
            assert!(result.is_ok());
            let (mut digest, mut offset) = result.unwrap();
            assert_eq!(offset, smaller_size_buf.len());
            assert_eq!(
                usize::from(digest.get_size()),
                smaller_size_buf.len() - SIZE_OF_U16
            );
            assert_eq!(digest.get_buffer(), &smaller_size_buf[SIZE_OF_U16..]);

            // same size should be good
            result = <$T>::untry_marshal(&same_size_buf);
            assert!(result.is_ok());
            (digest, offset) = result.unwrap();
            assert_eq!(offset, same_size_buf.len());
            assert_eq!(
                usize::from(digest.get_size()),
                same_size_buf.len() - std::mem::size_of::<u16>()
            );
            assert_eq!(
                digest.get_buffer(),
                &same_size_buf[std::mem::size_of::<u16>()..]
            );
        };
    }

    macro_rules! impl_test_scalar {
        ($T:ty, $I:expr, $V:expr) => {
            const SIZE_OF_TYPE: usize = std::mem::size_of::<$T>();

            let too_small_buffer: [u8; SIZE_OF_TYPE - 1] = [$I; SIZE_OF_TYPE - 1];
            let same_size_buffer: [u8; SIZE_OF_TYPE] = [$I; SIZE_OF_TYPE];
            let larger_buffer: [u8; SIZE_OF_TYPE + 4] = [$I; SIZE_OF_TYPE + 4];

            let mut res: Result<($T, usize), Tpm2Rc> = <$T>::untry_marshal(&too_small_buffer);
            assert!(res.is_err());

            res = <$T>::untry_marshal(&same_size_buffer);
            assert!(res.is_ok());
            let (mut value, mut offset) = res.unwrap();
            assert_eq!(value, $V);
            assert_eq!(offset, SIZE_OF_TYPE);

            res = <$T>::untry_marshal(&larger_buffer);
            assert!(res.is_ok());
            (value, offset) = res.unwrap();
            assert_eq!(value, $V);
            assert_eq!(offset, SIZE_OF_TYPE);
        };
    }

    #[test]
    fn test_untry_marshal_u8() {
        impl_test_scalar! {u8, 0xFF, 0xFF}
    }

    #[test]
    fn test_untry_marshal_i8() {
        impl_test_scalar! {i8, 0x7F, 0x7F}
    }

    #[test]
    fn test_untry_marshal_u16() {
        impl_test_scalar! {u16, 0xFF, 0xFFFF}
    }

    #[test]
    fn test_untry_marshal_i16() {
        impl_test_scalar! {i16, 0x7F, 0x7F7F}
    }

    #[test]
    fn test_untry_marshal_u32() {
        impl_test_scalar! {u32, 0xFF, 0xFFFFFFFF}
    }

    #[test]
    fn test_untry_marshal_i32() {
        impl_test_scalar! {i32, 0x7F, 0x7F7F7F7F}
    }

    #[test]
    fn test_untry_marshal_u64() {
        impl_test_scalar! {u64, 0xFF, 0xFFFFFFFFFFFFFFFF}
    }

    #[test]
    fn test_untry_marshal_i64() {
        impl_test_scalar! {i64, 0x7F, 0x7F7F7F7F7F7F7F7F}
    }

    #[test]
    fn test_untry_marshal_tpm2b_name() {
        impl_test_tpm2b_simple! {Tpm2bName};
    }

    #[test]
    fn test_untry_marshal_tpm2b_attest() {
        impl_test_tpm2b_simple! {Tpm2bAttest};
    }

    #[test]
    fn test_untry_marshal_tpm2b_context_data() {
        impl_test_tpm2b_simple! {Tpm2bContextData};
    }

    #[test]
    fn test_untry_marshal_tpm2b_context_sensitive() {
        impl_test_tpm2b_simple! {Tpm2bContextSensitive};
    }

    #[test]
    fn test_untry_marshal_tpm2b_data() {
        impl_test_tpm2b_simple! {Tpm2bData};
    }

    #[test]
    fn test_untry_marshal_tpm2b_digest() {
        impl_test_tpm2b_simple! {Tpm2bDigest};
    }

    #[test]
    fn test_untry_marshal_tpm2b_ecc_parameter() {
        impl_test_tpm2b_simple! {Tpm2bEccParameter};
    }

    #[test]
    fn test_untry_marshal_tpm2b_encrypted_secret() {
        impl_test_tpm2b_simple! {Tpm2bEncryptedSecret};
    }

    #[test]
    fn test_untry_marshal_tpm2b_event() {
        impl_test_tpm2b_simple! {Tpm2bEvent};
    }

    #[test]
    fn test_untry_marshal_tpm2b_id_object() {
        impl_test_tpm2b_simple! {Tpm2bIdObject};
    }

    #[test]
    fn test_untry_marshal_tpm2b_iv() {
        impl_test_tpm2b_simple! {Tpm2bIv};
    }

    #[test]
    fn test_untry_marshal_tpm2b_max_buffer() {
        impl_test_tpm2b_simple! {Tpm2bMaxBuffer};
    }

    #[test]
    fn test_untry_marshal_tpm2b_max_nv_buffer() {
        impl_test_tpm2b_simple! {Tpm2bMaxNvBuffer};
    }

    #[test]
    fn test_untry_marshal_tpm2b_private() {
        impl_test_tpm2b_simple! {Tpm2bPrivate};
    }

    #[test]
    fn test_untry_marshal_tpm2b_private_key_rsa() {
        impl_test_tpm2b_simple! {Tpm2bPrivateKeyRsa};
    }

    #[test]
    fn test_untry_marshal_tpm2b_private_vendor_specific() {
        impl_test_tpm2b_simple! {Tpm2bPrivateVendorSpecific};
    }

    #[test]
    fn test_untry_marshal_tpm2b_public_key_rsa() {
        impl_test_tpm2b_simple! {Tpm2bPublicKeyRsa};
    }

    #[test]
    fn test_untry_marshal_tpm2b_sensitive_data() {
        impl_test_tpm2b_simple! {Tpm2bSensitiveData};
    }

    #[test]
    fn test_untry_marshal_tpm2b_sym_key() {
        impl_test_tpm2b_simple! {Tpm2bSymKey};
    }

    #[test]
    fn test_untry_marshal_tpm2b_template() {
        impl_test_tpm2b_simple! {Tpm2bTemplate};
    }
}
