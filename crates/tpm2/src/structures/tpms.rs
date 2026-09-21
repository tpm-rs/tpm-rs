use crate::{
    errors::UnmarshalError,
    marshal::{marshal_helper, max},
    *,
};

/// `TPMS_CLOCK_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.14 (Table 135).
///
/// Holds time information including the clock counter, reset count, restart count, and safe flag.
#[doc(alias = "TPMS_CLOCK_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}

impl Marshal for TpmsClockInfo {
    const MAX_SIZE: usize = u64::MAX_SIZE + u32::MAX_SIZE + u32::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.clock, dst, 0);
        let count = marshal_helper(&self.reset_count, dst, count);
        let count = marshal_helper(&self.restart_count, dst, count);
        marshal_helper(&self.safe, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsClockInfo {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            clock: Unmarshal::unmarshal(src)?,
            reset_count: Unmarshal::unmarshal(src)?,
            restart_count: Unmarshal::unmarshal(src)?,
            safe: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_PCR_SELECT` Structure
///
/// Represents a bitmap selection of PCRs.
#[doc(alias = "TPMS_PCR_SELECT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsPcrSelect {
    sizeof_select: u8,
    pcr_select: [u8; Self::MAX],
}

impl TpmsPcrSelect {
    /// The number of PCRs required by the platform-specific specification.
    #[doc(alias = "PLATFORM_PCR")]
    pub const PLATFORM_PCRS: usize = 24;
    /// The maximum number of PCRs implemented on the TPM.
    #[doc(alias = "IMPLEMENTATION_PCR")]
    #[doc(alias = "TPM2_MAX_PCRS")]
    pub const MAX_PCRS: usize = 32;
    /// The minimum number of bytes usable to select PCRs.
    #[doc(alias = "TPM2_PCR_SELECT_MIN")]
    #[doc(alias = "PCR_SELECT_MIN")]
    pub const MIN: usize = Self::PLATFORM_PCRS.div_ceil(8);
    /// The maximum number of bytes usable to select PCRs.
    #[doc(alias = "TPM2_PCR_SELECT_MAX")]
    #[doc(alias = "PCR_SELECT_MAX")]
    pub const MAX: usize = Self::MAX_PCRS.div_ceil(8);

    /// Create a new [`TpmsPcrSelect`] from the given bit array.
    ///
    /// Returns [`None`] unless:
    /// [`TpmsPcrSelect::MIN`] `<= selection.len() <=` [`TpmsPcrSelect::MAX`].
    pub const fn new(selection: &[u8]) -> Option<Self> {
        if selection.len() < Self::MIN {
            return None;
        }
        let mut pcr_select = [0u8; Self::MAX];
        let Some((dst, _)) = pcr_select.split_at_mut_checked(selection.len()) else {
            return None;
        };
        dst.copy_from_slice(selection);
        Some(Self {
            sizeof_select: selection.len() as u8,
            pcr_select,
        })
    }

    /// Returns the slice of selected PCR bits.
    pub const fn pcrs(&self) -> &[u8] {
        debug_assert!(self.sizeof_select as usize >= Self::MIN);
        debug_assert!(self.sizeof_select as usize <= Self::MAX);
        if let Some((head, _)) = self
            .pcr_select
            .split_at_checked(self.sizeof_select as usize)
        {
            head
        } else {
            &self.pcr_select
        }
    }
}

impl Default for TpmsPcrSelect {
    fn default() -> Self {
        Self {
            sizeof_select: Self::MIN as u8,
            pcr_select: [0u8; Self::MAX],
        }
    }
}

impl Marshal for TpmsPcrSelect {
    const MAX_SIZE: usize = u8::MAX_SIZE + Self::MAX;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        let (head, rest) = dst.split_first_chunk_mut::<1>().unwrap();
        let src = self.pcrs();
        let len = src.len();
        let count = self.sizeof_select.marshal(head);
        rest[..len].copy_from_slice(src);
        count + len
    }
}

impl<'a> Unmarshal<'a> for TpmsPcrSelect {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let sizeof_select = u8::unmarshal(src)?;
        let len = sizeof_select as usize;
        if !(Self::MIN..=Self::MAX).contains(&len) || src.len() < len {
            return Err(UnmarshalError);
        }
        let (slice, rest) = src.split_at(len);
        *src = rest;
        let mut pcr_select = [0u8; Self::MAX];
        pcr_select[..len].copy_from_slice(slice);
        Ok(Self {
            sizeof_select,
            pcr_select,
        })
    }
}

/// [TPM2.0 1.83] 10.7.2 TPMS_PCR_SELECTION Structure.
/// Represents a selection of PCRs for a single hash algorithm.
/// `TPMS_PCR_SELECTION` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.4 (Table 103).
///
/// Specifies a PCR selection for a single hash bank (`hashAlg`, `pcrSelect` bitmap).
#[doc(alias = "TPMS_PCR_SELECTION")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsPcrSelection {
    pub hash: TpmiAlgHash,
    pub selection: TpmsPcrSelect,
}

impl Marshal for TpmsPcrSelection {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + TpmsPcrSelect::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.hash, dst, 0);
        marshal_helper(&self.selection, dst, count)
    }
}

impl Unmarshal<'_> for TpmsPcrSelection {
    fn unmarshal(src: &mut &[u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            hash: Unmarshal::unmarshal(src)?,
            selection: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_QUOTE_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.18 (Table 139).
///
/// Contains quote attestation data including the PCR selection bitmap and PCR composite digest.
#[doc(alias = "TPMS_QUOTE_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsQuoteInfo<'a> {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest<'a>,
}
impl Marshal for TpmsQuoteInfo<'_> {
    const MAX_SIZE: usize = TpmlPcrSelection::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmsQuoteInfo::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsQuoteInfo::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.pcr_select, dst, 0);
        marshal_helper(&self.pcr_digest, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsQuoteInfo<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_select: Unmarshal::unmarshal(src)?,
            pcr_digest: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_CREATION_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.21 (Table 140).
///
/// Contains creation attestation data including the created object's Name and creation digest.
#[doc(alias = "TPMS_CREATION_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsCreationInfo<'a> {
    pub object_name: Tpm2bName<'a>,
    pub creation_hash: Tpm2bDigest<'a>,
}
impl Marshal for TpmsCreationInfo<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmsCreationInfo::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsCreationInfo::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.object_name, dst, 0);
        marshal_helper(&self.creation_hash, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsCreationInfo<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_name: Unmarshal::unmarshal(src)?,
            creation_hash: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_CERTIFY_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.17 (Table 138).
///
/// Contains certification attestation data including the object Name and qualified Name of a certified key.
#[doc(alias = "TPMS_CERTIFY_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsCertifyInfo<'a> {
    pub name: Tpm2bName<'a>,
    pub qualified_name: Tpm2bName<'a>,
}
impl Marshal for TpmsCertifyInfo<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; TpmsCertifyInfo::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsCertifyInfo::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.name, dst, 0);
        marshal_helper(&self.qualified_name, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsCertifyInfo<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            name: Unmarshal::unmarshal(src)?,
            qualified_name: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_COMMAND_AUDIT_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.19 (Table 140).
///
/// Contains command audit attestation data including audit counter, digest algorithm, audit digest, and command digest.
#[doc(alias = "TPMS_COMMAND_AUDIT_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsCommandAuditInfo<'a> {
    pub audit_counter: u64,
    pub digest_alg: u16,
    pub audit_digest: Tpm2bDigest<'a>,
    pub command_digest: Tpm2bDigest<'a>,
}
impl Marshal for TpmsCommandAuditInfo<'_> {
    const MAX_SIZE: usize =
        u64::MAX_SIZE + u16::MAX_SIZE + Tpm2bDigest::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmsCommandAuditInfo::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsCommandAuditInfo::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.audit_counter, dst, 0);
        let count = marshal_helper(&self.digest_alg, dst, count);
        let count = marshal_helper(&self.audit_digest, dst, count);
        marshal_helper(&self.command_digest, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsCommandAuditInfo<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            audit_counter: Unmarshal::unmarshal(src)?,
            digest_alg: Unmarshal::unmarshal(src)?,
            audit_digest: Unmarshal::unmarshal(src)?,
            command_digest: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_SESSION_AUDIT_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.20 (Table 141).
///
/// Contains session audit attestation data including exclusive session flag and session digest.
#[doc(alias = "TPMS_SESSION_AUDIT_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsSessionAuditInfo<'a> {
    pub exclusive_session: bool,
    pub session_digest: Tpm2bDigest<'a>,
}
impl Marshal for TpmsSessionAuditInfo<'_> {
    const MAX_SIZE: usize = bool::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmsSessionAuditInfo::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsSessionAuditInfo::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.exclusive_session, dst, 0);
        marshal_helper(&self.session_digest, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsSessionAuditInfo<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            exclusive_session: Unmarshal::unmarshal(src)?,
            session_digest: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_TIME_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.15 (Table 136).
///
/// Contains timestamp information including current time and clock info.
#[doc(alias = "TPMS_TIME_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsTimeInfo {
    pub time: u64,
    pub clock_info: TpmsClockInfo,
}
impl Marshal for TpmsTimeInfo {
    const MAX_SIZE: usize = u64::MAX_SIZE + TpmsClockInfo::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.time, dst, 0);
        marshal_helper(&self.clock_info, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsTimeInfo {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            time: Unmarshal::unmarshal(src)?,
            clock_info: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_TIME_ATTEST_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.16 (Table 137).
///
/// Contains time attestation data including timestamp info and TPM firmware version.
#[doc(alias = "TPMS_TIME_ATTEST_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}
impl Marshal for TpmsTimeAttestInfo {
    const MAX_SIZE: usize = TpmsTimeInfo::MAX_SIZE + u64::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.time, dst, 0);
        marshal_helper(&self.firmware_version, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsTimeAttestInfo {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            time: Unmarshal::unmarshal(src)?,
            firmware_version: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_NV_CERTIFY_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.22 (Table 141).
///
/// Contains NV Index certification attestation data including NV Index Name, offset, and data contents.
#[doc(alias = "TPMS_NV_CERTIFY_INFO")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsNvCertifyInfo<'a> {
    pub index_name: Tpm2bName<'a>,
    pub offset: u16,
    pub nv_contents: Tpm2bMaxNvBuffer<'a>,
}
impl Marshal for TpmsNvCertifyInfo<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE + u16::MAX_SIZE + Tpm2bMaxNvBuffer::MAX_SIZE;
    type MaxBuffer = [u8; TpmsNvCertifyInfo::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsNvCertifyInfo::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.index_name, dst, 0);
        let count = marshal_helper(&self.offset, dst, count);
        marshal_helper(&self.nv_contents, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsNvCertifyInfo<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            index_name: Unmarshal::unmarshal(src)?,
            offset: Unmarshal::unmarshal(src)?,
            nv_contents: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_ATTEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.24 (Table 143).
///
/// Standard attestation structure signed during TPM attestation commands (`TPM2_Certify`, `TPM2_Quote`, `TPM2_GetTime`, etc.).
#[doc(alias = "TPMS_ATTEST")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsAttest<'a> {
    pub magic: TpmGenerated,
    pub qualified_signer: Tpm2bName<'a>,
    pub extra_data: Tpm2bData<'a>,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: TpmuAttest<'a>,
}

impl TpmsAttest<'_> {
    #[doc(alias = "TPMI_ST_ATTEST")]
    pub fn attested_type(&self) -> TpmSt {
        self.attested.attested_type()
    }
}

impl Marshal for TpmsAttest<'_> {
    const MAX_SIZE: usize = TpmGenerated::MAX_SIZE
        + TpmSt::MAX_SIZE
        + Tpm2bName::MAX_SIZE
        + Tpm2bData::MAX_SIZE
        + TpmsClockInfo::MAX_SIZE
        + u64::MAX_SIZE
        + TpmuAttest::MAX_SIZE;
    type MaxBuffer = [u8; TpmsAttest::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsAttest::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.magic, dst, 0);
        let count = marshal_helper(&self.attested_type(), dst, count);
        let count = marshal_helper(&self.qualified_signer, dst, count);
        let count = marshal_helper(&self.extra_data, dst, count);
        let count = marshal_helper(&self.clock_info, dst, count);
        let count = marshal_helper(&self.firmware_version, dst, count);
        marshal_helper(&self.attested, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsAttest<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let magic = Unmarshal::unmarshal(src)?;
        let type_tag = Unmarshal::unmarshal(src)?;
        let qualified_signer = Unmarshal::unmarshal(src)?;
        let extra_data = Unmarshal::unmarshal(src)?;
        let clock_info = Unmarshal::unmarshal(src)?;
        let firmware_version = Unmarshal::unmarshal(src)?;
        let attested = TpmuAttest::unmarshal_variant(type_tag, src)?;
        Ok(Self {
            magic,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version,
            attested,
        })
    }
}

/// `TPMS_DERIVE` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.9 (Table 156).
///
/// Parameters for key derivation input (`label`, `context`).
#[doc(alias = "TPMS_DERIVE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsDerive<'a> {
    pub label: Tpm2bLabel<'a>,
    pub context: Tpm2bLabel<'a>,
}
impl Marshal for TpmsDerive<'_> {
    const MAX_SIZE: usize = Tpm2bLabel::MAX_SIZE + Tpm2bLabel::MAX_SIZE;
    type MaxBuffer = [u8; TpmsDerive::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsDerive::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.label, dst, 0);
        marshal_helper(&self.context, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsDerive<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            label: Unmarshal::unmarshal(src)?,
            context: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_SENSITIVE_CREATE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.2 (Table 162).
///
/// Sensitive creation data structure containing the user authorization value and sensitive data buffer.
#[doc(alias = "TPMS_SENSITIVE_CREATE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsSensitiveCreate<'a> {
    pub user_auth: Tpm2bAuth<'a>,
    pub data: Tpm2bSensitiveData<'a>,
}
impl Marshal for TpmsSensitiveCreate<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + Tpm2bSensitiveData::MAX_SIZE;
    type MaxBuffer = [u8; TpmsSensitiveCreate::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsSensitiveCreate::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.user_auth, dst, 0);
        marshal_helper(&self.data, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsSensitiveCreate<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            user_auth: Unmarshal::unmarshal(src)?,
            data: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_ECC_POINT` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.2 (Table 189).
///
/// Holds the affine coordinates (X, Y) of an Elliptic Curve cryptography point.
#[doc(alias = "TPMS_ECC_POINT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsEccPoint<'a> {
    pub x: Tpm2bEccParameter<'a>,
    pub y: Tpm2bEccParameter<'a>,
}
impl Marshal for TpmsEccPoint<'_> {
    const MAX_SIZE: usize = Tpm2bEccParameter::MAX_SIZE + Tpm2bEccParameter::MAX_SIZE;
    type MaxBuffer = [u8; TpmsEccPoint::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsEccPoint::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.x, dst, 0);
        marshal_helper(&self.y, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsEccPoint<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            x: Unmarshal::unmarshal(src)?,
            y: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_SCHEME_XOR` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.10 (Table 163).
///
/// Parameter structure for XOR obfuscation scheme specifying hash algorithm and KDF.
#[doc(alias = "TPMS_SCHEME_XOR")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: Option<TpmiAlgKdf>,
}
impl Marshal for TpmsSchemeXor {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + <Option<TpmiAlgKdf>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.hash_alg, dst, 0);
        marshal_helper(&self.kdf, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsSchemeXor {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            hash_alg: Unmarshal::unmarshal(src)?,
            kdf: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_SIGNATURE_RSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.3.1 (Table 198).
///
/// Signature structure for RSA signatures, containing hash algorithm and signature buffer.
#[doc(alias = "TPMS_SIGNATURE_RSA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsSignatureRsa<'a> {
    pub hash: TpmiAlgHash,
    pub sig: Tpm2bPublicKeyRsa<'a>,
}
impl Marshal for TpmsSignatureRsa<'_> {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + Tpm2bPublicKeyRsa::MAX_SIZE;
    type MaxBuffer = [u8; TpmsSignatureRsa::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsSignatureRsa::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.hash, dst, 0);
        marshal_helper(&self.sig, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsSignatureRsa<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            hash: Unmarshal::unmarshal(src)?,
            sig: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_SIGNATURE_ECC` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.3.3 (Table 199).
///
/// Signature structure for ECC signatures, containing hash algorithm and (r, s) signature coordinates.
#[doc(alias = "TPMS_SIGNATURE_ECC")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsSignatureEcc<'a> {
    pub hash: TpmiAlgHash,
    pub signature_r: Tpm2bEccParameter<'a>,
    pub signature_s: Tpm2bEccParameter<'a>,
}
impl Marshal for TpmsSignatureEcc<'_> {
    const MAX_SIZE: usize =
        TpmiAlgHash::MAX_SIZE + Tpm2bEccParameter::MAX_SIZE + Tpm2bEccParameter::MAX_SIZE;
    type MaxBuffer = [u8; TpmsSignatureEcc::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsSignatureEcc::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.hash, dst, 0);
        let count = marshal_helper(&self.signature_r, dst, count);
        marshal_helper(&self.signature_s, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsSignatureEcc<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            hash: Unmarshal::unmarshal(src)?,
            signature_r: Unmarshal::unmarshal(src)?,
            signature_s: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_SCHEME_ECDAA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.3 (Table 192).
///
/// Parameter structure for ECDAA scheme specifying hash algorithm and commit count.
#[doc(alias = "TPMS_SCHEME_ECDAA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsSchemeEcdaa {
    pub hash_alg: TpmiAlgHash,
    pub count: u16,
}
impl Marshal for TpmsSchemeEcdaa {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.hash_alg, dst, 0);
        marshal_helper(&self.count, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsSchemeEcdaa {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let hash_alg = Unmarshal::unmarshal(src)?;
        let count = Unmarshal::unmarshal(src)?;
        Ok(Self { hash_alg, count })
    }
}

/// `TPMS_RSA_PARMS` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.3.4 (Table 206).
///
/// Parameter structure for RSA objects, specifying symmetric cipher, scheme, key bits, and public exponent.
#[doc(alias = "TPMS_RSA_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsRsaParms {
    pub symmetric: Option<TpmtSymDefObject>,
    pub scheme: Option<TpmtRsaScheme>,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: u32,
}
impl Marshal for TpmsRsaParms {
    const MAX_SIZE: usize = <Option<TpmtSymDefObject>>::MAX_SIZE
        + <Option<TpmtRsaScheme>>::MAX_SIZE
        + TpmiRsaKeyBits::MAX_SIZE
        + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.symmetric, dst, 0);
        let count = marshal_helper(&self.scheme, dst, count);
        let count = marshal_helper(&self.key_bits, dst, count);
        marshal_helper(&self.exponent, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsRsaParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let symmetric = Unmarshal::unmarshal(src)?;
        let scheme = <Option<TpmtRsaScheme>>::unmarshal(src)?;
        let key_bits = Unmarshal::unmarshal(src)?;
        let exponent = Unmarshal::unmarshal(src)?;
        Ok(Self {
            symmetric,
            scheme,
            key_bits,
            exponent,
        })
    }
}

/// `TPMS_ECC_PARMS` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.3.5 (Table 208).
///
/// Parameter structure for ECC objects, specifying symmetric cipher, scheme, curve ID, and KDF.
#[doc(alias = "TPMS_ECC_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsEccParms {
    pub symmetric: Option<TpmtSymDefObject>,
    pub scheme: Option<TpmtEccScheme>,
    pub curve_id: TpmEccCurve,
    pub kdf: Option<TpmtKdfScheme>,
}
impl Marshal for TpmsEccParms {
    const MAX_SIZE: usize = <Option<TpmtSymDefObject>>::MAX_SIZE
        + <Option<TpmtEccScheme>>::MAX_SIZE
        + TpmEccCurve::MAX_SIZE
        + <Option<TpmtKdfScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.symmetric, dst, 0);
        let count = marshal_helper(&self.scheme, dst, count);
        let count = marshal_helper(&self.curve_id, dst, count);
        marshal_helper(&self.kdf, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsEccParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let symmetric = Unmarshal::unmarshal(src)?;
        let scheme = <Option<TpmtEccScheme>>::unmarshal(src)?;
        let curve_id = Unmarshal::unmarshal(src)?;
        let kdf = <Option<TpmtKdfScheme>>::unmarshal(src)?;
        Ok(Self {
            symmetric,
            scheme,
            curve_id,
            kdf,
        })
    }
}

/// `TPMS_ALGORITHM_DETAIL_ECC` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.6 (Table 194).
///
/// Details structure for ECC curve parameters returned by `TPM2_ECC_Parameters`.
#[doc(alias = "TPMS_ALGORITHM_DETAIL_ECC")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsAlgorithmDetailEcc<'a> {
    pub curve_id: TpmEccCurve,
    pub key_size: u16,
    pub kdf: Option<TpmtKdfScheme>,
    pub sign: Option<TpmtEccScheme>,
    pub curve_p: Tpm2bEccParameter<'a>,
    pub curve_a: Tpm2bEccParameter<'a>,
    pub curve_b: Tpm2bEccParameter<'a>,
    pub g_x: Tpm2bEccParameter<'a>,
    pub g_y: Tpm2bEccParameter<'a>,
    pub n: Tpm2bEccParameter<'a>,
    pub h: Tpm2bEccParameter<'a>,
}
impl Marshal for TpmsAlgorithmDetailEcc<'_> {
    const MAX_SIZE: usize = TpmEccCurve::MAX_SIZE
        + u16::MAX_SIZE
        + <Option<TpmtKdfScheme>>::MAX_SIZE
        + <Option<TpmtEccScheme>>::MAX_SIZE
        + Tpm2bEccParameter::MAX_SIZE
        + Tpm2bEccParameter::MAX_SIZE
        + Tpm2bEccParameter::MAX_SIZE
        + Tpm2bEccParameter::MAX_SIZE
        + Tpm2bEccParameter::MAX_SIZE
        + Tpm2bEccParameter::MAX_SIZE
        + Tpm2bEccParameter::MAX_SIZE;
    type MaxBuffer = [u8; TpmsAlgorithmDetailEcc::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsAlgorithmDetailEcc::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.curve_id, dst, 0);
        let count = marshal_helper(&self.key_size, dst, count);
        let count = marshal_helper(&self.kdf, dst, count);
        let count = marshal_helper(&self.sign, dst, count);
        let count = marshal_helper(&self.curve_p, dst, count);
        let count = marshal_helper(&self.curve_a, dst, count);
        let count = marshal_helper(&self.curve_b, dst, count);
        let count = marshal_helper(&self.g_x, dst, count);
        let count = marshal_helper(&self.g_y, dst, count);
        let count = marshal_helper(&self.n, dst, count);
        marshal_helper(&self.h, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsAlgorithmDetailEcc<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let curve_id = Unmarshal::unmarshal(src)?;
        let key_size = Unmarshal::unmarshal(src)?;
        let kdf = <Option<TpmtKdfScheme>>::unmarshal(src)?;
        let sign = <Option<TpmtEccScheme>>::unmarshal(src)?;
        let curve_p = Unmarshal::unmarshal(src)?;
        let curve_a = Unmarshal::unmarshal(src)?;
        let curve_b = Unmarshal::unmarshal(src)?;
        let g_x = Unmarshal::unmarshal(src)?;
        let g_y = Unmarshal::unmarshal(src)?;
        let n = Unmarshal::unmarshal(src)?;
        let h = Unmarshal::unmarshal(src)?;
        Ok(Self {
            curve_id,
            key_size,
            kdf,
            sign,
            curve_p,
            curve_a,
            curve_b,
            g_x,
            g_y,
            n,
            h,
        })
    }
}

/// `TPMS_CAPABILITY_DATA` union structure defined in TPM 2.0 Part 2: Structures, Section 10.6.2 (Table 128).
///
/// Data area returned in response to `TPM2_GetCapability`.
#[doc(alias = "TPMS_CAPABILITY_DATA")]
#[doc(alias = "TPMU_CAPABILITIES")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmsCapabilityData<'a> {
    Algorithms(TpmlAlgProperty),
    Handles(TpmlHandle),
    Command(TpmlCca),
    PPCommands(TpmlCc),
    AuditCommands(TpmlCc),
    AssignedPcr(TpmlPcrSelection),
    TpmProperties(TpmlTaggedTpmProperty),
    PcrProperties(TpmlTaggedPcrProperty),
    EccCurves(TpmlEccCurve),
    AuthPolicies(TpmlTaggedPolicy<'a>),
}

impl<'a> TpmsCapabilityData<'a> {
    pub const fn capability(self) -> TpmCap {
        match self {
            Self::Algorithms(_) => TpmCap::Algs,
            Self::Handles(_) => TpmCap::Handles,
            Self::Command(_) => TpmCap::Commands,
            Self::PPCommands(_) => TpmCap::PPCommands,
            Self::AuditCommands(_) => TpmCap::AuditCommands,
            Self::AssignedPcr(_) => TpmCap::PCRs,
            Self::TpmProperties(_) => TpmCap::TPMProperties,
            Self::PcrProperties(_) => TpmCap::PCRProperties,
            Self::EccCurves(_) => TpmCap::ECCCurves,
            Self::AuthPolicies(_) => TpmCap::AuthPolicies,
        }
    }
}

impl Marshal for TpmsCapabilityData<'_> {
    const MAX_SIZE: usize = TpmCap::MAX_SIZE
        + max(&[
            TpmlAlgProperty::MAX_SIZE,
            TpmlHandle::MAX_SIZE,
            TpmlCca::MAX_SIZE,
            TpmlCc::MAX_SIZE,
            TpmlPcrSelection::MAX_SIZE,
            TpmlTaggedTpmProperty::MAX_SIZE,
            TpmlTaggedPcrProperty::MAX_SIZE,
            TpmlEccCurve::MAX_SIZE,
            TpmlTaggedPolicy::MAX_SIZE,
        ]);
    type MaxBuffer = [u8; TpmsCapabilityData::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsCapabilityData::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.capability(), dst, 0);
        match self {
            Self::Algorithms(x) => marshal_helper(x, dst, count),
            Self::Handles(x) => marshal_helper(x, dst, count),
            Self::Command(x) => marshal_helper(x, dst, count),
            Self::PPCommands(x) => marshal_helper(x, dst, count),
            Self::AuditCommands(x) => marshal_helper(x, dst, count),
            Self::AssignedPcr(x) => marshal_helper(x, dst, count),
            Self::TpmProperties(x) => marshal_helper(x, dst, count),
            Self::PcrProperties(x) => marshal_helper(x, dst, count),
            Self::EccCurves(x) => marshal_helper(x, dst, count),
            Self::AuthPolicies(x) => marshal_helper(x, dst, count),
        }
    }
}

impl<'a> Unmarshal<'a> for TpmsCapabilityData<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmCap::unmarshal(src)? {
            TpmCap::Algs => Self::Algorithms(Unmarshal::unmarshal(src)?),
            TpmCap::Handles => Self::Handles(Unmarshal::unmarshal(src)?),
            TpmCap::Commands => Self::Command(Unmarshal::unmarshal(src)?),
            TpmCap::PPCommands => Self::PPCommands(Unmarshal::unmarshal(src)?),
            TpmCap::AuditCommands => Self::AuditCommands(Unmarshal::unmarshal(src)?),
            TpmCap::PCRs => Self::AssignedPcr(Unmarshal::unmarshal(src)?),
            TpmCap::TPMProperties => Self::TpmProperties(Unmarshal::unmarshal(src)?),
            TpmCap::PCRProperties => Self::PcrProperties(Unmarshal::unmarshal(src)?),
            TpmCap::ECCCurves => Self::EccCurves(Unmarshal::unmarshal(src)?),
            TpmCap::AuthPolicies => Self::AuthPolicies(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        })
    }
}

/// `TPMS_ALG_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.9 (Table 108).
///
/// Structure reporting algorithm properties (`alg`, `algProperties`).
#[doc(alias = "TPMS_ALG_PROPERTY")]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct TpmsAlgProperty {
    pub alg: Alg,
    pub alg_properties: TpmaAlgorithm,
}
impl Marshal for TpmsAlgProperty {
    const MAX_SIZE: usize = Alg::MAX_SIZE + TpmaAlgorithm::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.alg, dst, 0);
        marshal_helper(&self.alg_properties, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsAlgProperty {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            alg: Unmarshal::unmarshal(src)?,
            alg_properties: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_TAGGED_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.10 (Table 109).
///
/// Structure reporting tagged UINT32 TPM properties (`property`, `value`).
#[doc(alias = "TPMS_TAGGED_PROPERTY")]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct TpmsTaggedProperty {
    pub property: TpmPt,
    pub value: u32,
}
impl Marshal for TpmsTaggedProperty {
    const MAX_SIZE: usize = TpmPt::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.property, dst, 0);
        marshal_helper(&self.value, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsTaggedProperty {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            property: Unmarshal::unmarshal(src)?,
            value: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_TAGGED_PCR_SELECT` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.11 (Table 110).
///
/// Structure reporting tagged PCR properties (`tag`, `sizeofSelect`, `pcrSelect`).
#[doc(alias = "TPMS_TAGGED_PCR_SELECT")]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct TpmsTaggedPcrSelect {
    pub tag: TpmPtPcr,
    pub selection: TpmsPcrSelect,
}

impl Marshal for TpmsTaggedPcrSelect {
    const MAX_SIZE: usize = TpmPtPcr::MAX_SIZE + TpmsPcrSelect::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag, dst, 0);
        marshal_helper(&self.selection, dst, count)
    }
}
impl Unmarshal<'_> for TpmsTaggedPcrSelect {
    fn unmarshal(src: &mut &[u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            tag: Unmarshal::unmarshal(src)?,
            selection: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_TAGGED_POLICY` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.12 (Table 111).
///
/// Structure reporting policy associated with permanent handles (`handle`, `policyHash`).
#[doc(alias = "TPMS_TAGGED_POLICY")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsTaggedPolicy<'a> {
    pub handle: Handle,
    pub policy_hash: TpmtHa<'a>,
}

impl Marshal for TpmsTaggedPolicy<'_> {
    const MAX_SIZE: usize = Handle::MAX_SIZE + TpmtHa::MAX_SIZE;
    type MaxBuffer = [u8; TpmsTaggedPolicy::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsTaggedPolicy::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.handle, dst, 0);
        marshal_helper(&self.policy_hash, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsTaggedPolicy<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle: Unmarshal::unmarshal(src)?,
            policy_hash: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_AUTH_COMMAND` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.25 (Table 144).
///
/// Format for each authorization in the session area of a command.
#[doc(alias = "TPMS_AUTH_COMMAND")]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct TpmsAuthCommand<'a> {
    pub session_handle: Handle,
    pub nonce: Tpm2bNonce<'a>,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bAuth<'a>,
}
impl Marshal for TpmsAuthCommand<'_> {
    const MAX_SIZE: usize =
        Handle::MAX_SIZE + Tpm2bNonce::MAX_SIZE + TpmaSession::MAX_SIZE + Tpm2bAuth::MAX_SIZE;
    type MaxBuffer = [u8; TpmsAuthCommand::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsAuthCommand::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.session_handle, dst, 0);
        let count = marshal_helper(&self.nonce, dst, count);
        let count = marshal_helper(&self.session_attributes, dst, count);
        marshal_helper(&self.hmac, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsAuthCommand<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            session_handle: Unmarshal::unmarshal(src)?,
            nonce: Unmarshal::unmarshal(src)?,
            session_attributes: Unmarshal::unmarshal(src)?,
            hmac: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_AUTH_RESPONSE` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.26 (Table 146).
///
/// Format for each authorization in the session area of a response.
#[doc(alias = "TPMS_AUTH_RESPONSE")]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct TpmsAuthResponse<'a> {
    pub nonce: Tpm2bNonce<'a>,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bData<'a>,
}
impl Marshal for TpmsAuthResponse<'_> {
    const MAX_SIZE: usize = Tpm2bNonce::MAX_SIZE + TpmaSession::MAX_SIZE + Tpm2bData::MAX_SIZE;
    type MaxBuffer = [u8; TpmsAuthResponse::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsAuthResponse::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.nonce, dst, 0);
        let count = marshal_helper(&self.session_attributes, dst, count);
        marshal_helper(&self.hmac, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsAuthResponse<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nonce: Unmarshal::unmarshal(src)?,
            session_attributes: Unmarshal::unmarshal(src)?,
            hmac: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_NV_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 13.2 (Table 227).
///
/// Defines the public area parameters for an NV Index (index handle, name hash algorithm, attributes, policy, and data size).
#[doc(alias = "TPMS_NV_PUBLIC")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsNvPublic<'a> {
    pub nv_index: Handle,
    pub name_alg: TpmiAlgHash,
    pub attributes: TpmaNv,
    pub auth_policy: Tpm2bDigest<'a>,
    pub data_size: u16,
}
impl Marshal for TpmsNvPublic<'_> {
    const MAX_SIZE: usize = Handle::MAX_SIZE
        + TpmiAlgHash::MAX_SIZE
        + TpmaNv::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + u16::MAX_SIZE;
    type MaxBuffer = [u8; TpmsNvPublic::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsNvPublic::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.nv_index, dst, 0);
        let count = marshal_helper(&self.name_alg, dst, count);
        let count = marshal_helper(&self.attributes, dst, count);
        let count = marshal_helper(&self.auth_policy, dst, count);
        marshal_helper(&self.data_size, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsNvPublic<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nv_index: Unmarshal::unmarshal(src)?,
            name_alg: Unmarshal::unmarshal(src)?,
            attributes: Unmarshal::unmarshal(src)?,
            auth_policy: Unmarshal::unmarshal(src)?,
            data_size: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_CONTEXT` structure defined in TPM 2.0 Part 2: Structures, Section 14.3 (Table 233).
///
/// Parameter structure for `TPM2_ContextSave` and `TPM2_ContextLoad` containing sequence number, handle, hierarchy, and context data.
#[doc(alias = "TPMS_CONTEXT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsContext<'a> {
    pub sequence: u64,
    pub saved_handle: Handle,
    pub hierarchy: Handle,
    pub context_blob: Tpm2bContextData<'a>,
}
impl Marshal for TpmsContext<'_> {
    const MAX_SIZE: usize =
        u64::MAX_SIZE + Handle::MAX_SIZE + Handle::MAX_SIZE + Tpm2bContextData::MAX_SIZE;
    type MaxBuffer = [u8; TpmsContext::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsContext::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.sequence, dst, 0);
        let count = marshal_helper(&self.saved_handle, dst, count);
        let count = marshal_helper(&self.hierarchy, dst, count);
        marshal_helper(&self.context_blob, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsContext<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence: Unmarshal::unmarshal(src)?,
            saved_handle: Unmarshal::unmarshal(src)?,
            hierarchy: Unmarshal::unmarshal(src)?,
            context_blob: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_CREATION_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.3 (Table 102).
///
/// Creation data recorded when an object is created, including parent name and creation PCR digest.
#[doc(alias = "TPMS_CREATION_DATA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsCreationData<'a> {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest<'a>,
    pub locality: TpmaLocality,
    pub parent_name_alg: Option<TpmiAlgHash>,
    pub parent_name: Tpm2bName<'a>,
    pub parent_qualified_name: Tpm2bName<'a>,
    pub outside_info: Tpm2bData<'a>,
}

impl Marshal for TpmsCreationData<'_> {
    const MAX_SIZE: usize = TpmlPcrSelection::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + TpmaLocality::MAX_SIZE
        + <Option<TpmiAlgHash>>::MAX_SIZE
        + Tpm2bName::MAX_SIZE
        + Tpm2bName::MAX_SIZE
        + Tpm2bData::MAX_SIZE;
    type MaxBuffer = [u8; TpmsCreationData::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsCreationData::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.pcr_select, dst, 0);
        let count = marshal_helper(&self.pcr_digest, dst, count);
        let count = marshal_helper(&self.locality, dst, count);
        let count = marshal_helper(&self.parent_name_alg, dst, count);
        let count = marshal_helper(&self.parent_name, dst, count);
        let count = marshal_helper(&self.parent_qualified_name, dst, count);
        marshal_helper(&self.outside_info, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsCreationData<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_select: Unmarshal::unmarshal(src)?,
            pcr_digest: Unmarshal::unmarshal(src)?,
            locality: Unmarshal::unmarshal(src)?,
            parent_name_alg: Unmarshal::unmarshal(src)?,
            parent_name: Unmarshal::unmarshal(src)?,
            parent_qualified_name: Unmarshal::unmarshal(src)?,
            outside_info: Unmarshal::unmarshal(src)?,
        })
    }
}
