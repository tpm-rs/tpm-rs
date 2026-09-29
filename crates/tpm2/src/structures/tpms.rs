use crate::{
    errors::{TpmRc, UnmarshalError},
    marshal::{marshal_helper, max},
    *,
};

/// `TPMS_CLOCK_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.14 (Table 135).
///
/// Holds time information including the clock counter, reset count, restart count, and safe flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}

impl Marshal for TpmsClockInfo {
    const MAX_SIZE: usize = 8 + 4 + 4 + 1;
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

/// `TPMS_PCR_SELECT` structure defined in TPM 2.0 Part 2: Structures, Section 10.3 (Table 100).
///
/// Specifies a PCR selection bitmap (`sizeofSelect`, `pcrSelect`).
#[doc(alias = "TPMS_PCR_SELECT")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmsPcrSelect {
    /// Size of the `pcr_select` array in bytes (`PCR_SELECT_MIN..=PCR_SELECT_MAX`).
    pub sizeof_select: u8,
    /// Bitmask of selected PCRs.
    pub pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

impl TpmsPcrSelect {
    /// The number of PCRs required by the platform-specific specification.
    #[doc(alias = "PLATFORM_PCR")]
    pub const PLATFORM_PCRS: usize = 24;
    /// The maximum number of PCRs implemented on the TPM.
    #[doc(alias = "IMPLEMENTATION_PCR")]
    #[doc(alias = "TPM2_MAX_PCRS")]
    pub const MAX_PCRS: usize = TPM2_MAX_PCRS as usize;
    /// The minimum number of bytes usable to select PCRs.
    #[doc(alias = "TPM2_PCR_SELECT_MIN")]
    #[doc(alias = "PCR_SELECT_MIN")]
    pub const MIN: usize = TPM2_PCR_SELECT_MIN;
    /// The maximum number of bytes usable to select PCRs.
    #[doc(alias = "TPM2_PCR_SELECT_MAX")]
    #[doc(alias = "PCR_SELECT_MAX")]
    pub const MAX: usize = TPM2_PCR_SELECT_MAX as usize;

    /// Creates a new [`TpmsPcrSelect`], verifying that `selected_pcrs.len()` is within
    /// `TPM2_PCR_SELECT_MIN..=TPM2_PCR_SELECT_MAX`.
    pub fn new(selected_pcrs: &[u8]) -> Result<Self, TpmRc> {
        if selected_pcrs.len() < TPM2_PCR_SELECT_MIN
            || selected_pcrs.len() > TPM2_PCR_SELECT_MAX as usize
        {
            return Err(TpmRc::VALUE.to_rc());
        }
        let mut pcr_select = [0u8; TPM2_PCR_SELECT_MAX as usize];
        pcr_select[..selected_pcrs.len()].copy_from_slice(selected_pcrs);
        Ok(Self {
            sizeof_select: selected_pcrs.len() as u8,
            pcr_select,
        })
    }

    /// Returns the `sizeof_select` value.
    pub const fn sizeof_select(&self) -> u8 {
        self.sizeof_select
    }

    /// Returns the slice of selected PCR bits (`&pcr_select[..sizeof_select]`).
    pub fn pcr_select(&self) -> &[u8] {
        let len = (self.sizeof_select as usize).min(TPM2_PCR_SELECT_MAX as usize);
        &self.pcr_select[..len]
    }

    /// Returns the slice of selected PCR bits.
    pub fn pcrs(&self) -> &[u8] {
        self.pcr_select()
    }
}

impl Default for TpmsPcrSelect {
    fn default() -> Self {
        Self {
            sizeof_select: TPM2_PCR_SELECT_MIN as u8,
            pcr_select: [0u8; TPM2_PCR_SELECT_MAX as usize],
        }
    }
}

impl Marshal for TpmsPcrSelect {
    const MAX_SIZE: usize = 1 + (TPM2_PCR_SELECT_MAX as usize);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let len = (self.sizeof_select as usize).min(self.pcr_select.len());
        let count = marshal_helper(&(len as u8), dst, 0);
        dst[count..count + len].copy_from_slice(&self.pcr_select[..len]);
        count + len
    }
}

impl<'a> Unmarshal<'a> for TpmsPcrSelect {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let sizeof_select = Unmarshal::unmarshal(src)?;
        let len = sizeof_select as usize;
        if len < TPM2_PCR_SELECT_MIN || len > TPM2_PCR_SELECT_MAX as usize {
            return Err(UnmarshalError::VALUE);
        }
        if src.len() < len {
            return Err(UnmarshalError::INSUFFICIENT);
        }
        let (slice, rest) = src.split_at(len);
        *src = rest;
        let mut pcr_select = [0u8; TPM2_PCR_SELECT_MAX as usize];
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsPcrSelection {
    /// The hash algorithm associated with this selection.
    pub(crate) hash: TpmiAlgHash,
    /// Size of the `pcr_select` array in bytes.
    pub(crate) sizeof_select: u8,
    /// Bitmask of selected PCRs.
    pub(crate) pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

impl TpmsPcrSelection {
    /// Creates a new TpmsPcrSelection, verifying bounds.
    pub fn new(hash: TpmiAlgHash, selected_pcrs: &[u8]) -> Result<Self, TpmRc> {
        if selected_pcrs.len() < TPM2_PCR_SELECT_MIN
            || selected_pcrs.len() > TPM2_PCR_SELECT_MAX as usize
        {
            return Err(TpmRc::VALUE.to_rc());
        }
        let mut pcr_select = [0u8; TPM2_PCR_SELECT_MAX as usize];
        pcr_select[..selected_pcrs.len()].copy_from_slice(selected_pcrs);
        Ok(Self {
            hash,
            sizeof_select: selected_pcrs.len() as u8,
            pcr_select,
        })
    }

    /// Returns the hash algorithm.
    pub fn hash(&self) -> TpmiAlgHash {
        self.hash
    }

    /// Returns the sizeof_select value.
    pub fn sizeof_select(&self) -> u8 {
        self.sizeof_select
    }

    /// Returns the slice of selected PCR bits.
    pub fn pcr_select(&self) -> &[u8] {
        let len = (self.sizeof_select as usize).min(self.pcr_select.len());
        &self.pcr_select[..len]
    }
}

impl Default for TpmsPcrSelection {
    fn default() -> Self {
        Self {
            hash: TpmiAlgHash::DEFAULT_HASH,
            sizeof_select: TPM2_PCR_SELECT_MIN as u8,
            pcr_select: [0u8; TPM2_PCR_SELECT_MAX as usize],
        }
    }
}

impl Marshal for TpmsPcrSelection {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + 1 + (TPM2_PCR_SELECT_MAX as usize);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.hash, dst, 0);
        let len = (self.sizeof_select as usize).min(self.pcr_select.len());
        let count = marshal_helper(&(len as u8), dst, count);
        dst[count..count + len].copy_from_slice(&self.pcr_select[..len]);
        count + len
    }
}

impl<'a> Unmarshal<'a> for TpmsPcrSelection {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let hash = Unmarshal::unmarshal(src)?;
        let sizeof_select = Unmarshal::unmarshal(src)?;
        let len = sizeof_select as usize;
        if len < TPM2_PCR_SELECT_MIN || len > TPM2_PCR_SELECT_MAX as usize {
            return Err(UnmarshalError::VALUE);
        }
        if src.len() < len {
            return Err(UnmarshalError::INSUFFICIENT);
        }
        let (slice, rest) = src.split_at(len);
        *src = rest;
        let mut pcr_select = [0u8; TPM2_PCR_SELECT_MAX as usize];
        pcr_select[..len].copy_from_slice(slice);
        Ok(Self {
            hash,
            sizeof_select,
            pcr_select,
        })
    }
}

/// `TPMS_QUOTE_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.18 (Table 139).
///
/// Contains quote attestation data including the PCR selection bitmap and PCR composite digest.
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsCommandAuditInfo<'a> {
    pub audit_counter: u64,
    pub digest_alg: Alg,
    pub audit_digest: Tpm2bDigest<'a>,
    pub command_digest: Tpm2bDigest<'a>,
}
impl Marshal for TpmsCommandAuditInfo<'_> {
    const MAX_SIZE: usize =
        u64::MAX_SIZE + Alg::MAX_SIZE + Tpm2bDigest::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
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
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsTimeInfo {
    pub time: u64,
    pub clock_info: TpmsClockInfo,
}
impl Marshal for TpmsTimeInfo {
    const MAX_SIZE: usize = 8 + TpmsClockInfo::MAX_SIZE;
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
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}
impl Marshal for TpmsTimeAttestInfo {
    const MAX_SIZE: usize = TpmsTimeInfo::MAX_SIZE + 8;
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

/// `TPMS_NV_DIGEST_CERTIFY_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.12.9 (Table 153).
///
/// Contains NV Index certification digest data including NV Index Name and NV digest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsNvDigestCertifyInfo<'a> {
    pub index_name: Tpm2bName<'a>,
    pub nv_digest: Tpm2bDigest<'a>,
}
impl Marshal for TpmsNvDigestCertifyInfo<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmsNvDigestCertifyInfo::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsNvDigestCertifyInfo::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.index_name, dst, 0);
        marshal_helper(&self.nv_digest, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsNvDigestCertifyInfo<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            index_name: Unmarshal::unmarshal(src)?,
            nv_digest: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_ATTEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.24 (Table 143).
///
/// Standard attestation structure signed during TPM attestation commands (`TPM2_Certify`, `TPM2_Quote`, `TPM2_GetTime`, etc.).
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
        let type_tag: TpmSt = Unmarshal::unmarshal(src)?;
        if !matches!(
            type_tag,
            TpmSt::ATTEST_CERTIFY
                | TpmSt::ATTEST_CREATION
                | TpmSt::ATTEST_QUOTE
                | TpmSt::ATTEST_COMMAND_AUDIT
                | TpmSt::ATTEST_SESSION_AUDIT
                | TpmSt::ATTEST_TIME
                | TpmSt::ATTEST_NV
                | TpmSt::ATTEST_NV_DIGEST
        ) {
            return Err(UnmarshalError::VALUE);
        }
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

impl Default for TpmsAttest<'_> {
    fn default() -> Self {
        Self {
            magic: TpmGenerated,
            qualified_signer: Default::default(),
            extra_data: Default::default(),
            clock_info: Default::default(),
            firmware_version: 0,
            attested: TpmuAttest::Time(Default::default()),
        }
    }
}

/// `TPMS_DERIVE` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.9 (Table 156).
///
/// Parameters for key derivation input (`label`, `context`).
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

/// `TPMS_MLDSA_PARMS` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.3.4.
///
/// Parameter structure for pure ML-DSA signing keys (`TPM_ALG_MLDSA`), specifying the
/// ML-DSA parameter set and whether external `mu` digest input is permitted.
#[doc(alias = "TPMS_MLDSA_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsMldsaParms {
    pub parameter_set: TpmiMldsaParms,
    pub allow_external_mu: bool,
}

impl Marshal for TpmsMldsaParms {
    const MAX_SIZE: usize = TpmiMldsaParms::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.parameter_set, dst, 0);
        marshal_helper(&self.allow_external_mu, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsMldsaParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let parameter_set = Unmarshal::unmarshal(src)?;
        let allow_external_mu = Unmarshal::unmarshal(src)?;
        Ok(Self {
            parameter_set,
            allow_external_mu,
        })
    }
}

/// `TPMS_HASH_MLDSA_PARMS` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.3.4.
///
/// Parameter structure for Pre-Hash ML-DSA signing keys (`TPM_ALG_HASH_MLDSA`), specifying the
/// ML-DSA parameter set and the pre-hash digest algorithm.
#[doc(alias = "TPMS_HASH_MLDSA_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsHashMldsaParms {
    pub parameter_set: TpmiMldsaParms,
    pub hash_alg: TpmiAlgHash,
}

impl Marshal for TpmsHashMldsaParms {
    const MAX_SIZE: usize = TpmiMldsaParms::MAX_SIZE + TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.parameter_set, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsHashMldsaParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let parameter_set = Unmarshal::unmarshal(src)?;
        let hash_alg = Unmarshal::unmarshal(src)?;
        Ok(Self {
            parameter_set,
            hash_alg,
        })
    }
}

/// `TPMS_MLKEM_PARMS` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.3.4.
///
/// Parameter structure for ML-KEM keys (`TPM_ALG_MLKEM`), specifying the optional symmetric
/// cipher for restricted decryption keys and the ML-KEM parameter set.
#[doc(alias = "TPMS_MLKEM_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsMlkemParms {
    pub symmetric: Option<TpmtSymDefObject>,
    pub parameter_set: TpmiMlkemParms,
}

impl Marshal for TpmsMlkemParms {
    const MAX_SIZE: usize = <Option<TpmtSymDefObject>>::MAX_SIZE + TpmiMlkemParms::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.symmetric, dst, 0);
        marshal_helper(&self.parameter_set, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsMlkemParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let symmetric = Unmarshal::unmarshal(src)?;
        let parameter_set = Unmarshal::unmarshal(src)?;
        Ok(Self {
            symmetric,
            parameter_set,
        })
    }
}

/// `TPMS_SIGNATURE_HASH_MLDSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.6.6.
///
/// Signature structure for Pre-Hash ML-DSA (`TPM_ALG_HASH_MLDSA`) signatures, containing
/// the pre-hash algorithm (`TPMI_ALG_HASH`) and the ML-DSA signature (`TPM2B_SIGNATURE_MLDSA`).
#[doc(alias = "TPMS_SIGNATURE_HASH_MLDSA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsSignatureHashMldsa<'a> {
    pub hash: TpmiAlgHash,
    pub sig: Tpm2bSignatureMldsa<'a>,
}

impl Marshal for TpmsSignatureHashMldsa<'_> {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + Tpm2bSignatureMldsa::MAX_SIZE;
    type MaxBuffer = [u8; TpmsSignatureHashMldsa::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.hash, dst, 0);
        marshal_helper(&self.sig, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsSignatureHashMldsa<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            hash: Unmarshal::unmarshal(src)?,
            sig: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_ALGORITHM_DETAIL_ECC` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.6 (Table 194).
///
/// Details structure for ECC curve parameters returned by `TPM2_ECC_Parameters`.
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

/// `TPMS_ACT_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.6.1 (Table 127).
///
/// Contains data for an Authenticated Countdown Timer (ACT) returned by `TPM2_GetCapability(TPM_CAP_ACT)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsActData {
    pub handle: Handle,
    pub timeout: u32,
    pub attributes: TpmaAct,
}
impl Marshal for TpmsActData {
    const MAX_SIZE: usize = Handle::MAX_SIZE + u32::MAX_SIZE + TpmaAct::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.handle, dst, 0);
        let count = marshal_helper(&self.timeout, dst, count);
        marshal_helper(&self.attributes, dst, count)
    }
}
impl<'a> Unmarshal<'a> for TpmsActData {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle: Unmarshal::unmarshal(src)?,
            timeout: Unmarshal::unmarshal(src)?,
            attributes: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_SPDM_SESSION_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.6.1a (Table 127a).
///
/// Contains SPDM session information returned by `TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsSpdmSessionInfo<'a> {
    pub req_key_name: Tpm2bName<'a>,
    pub tpm_key_name: Tpm2bName<'a>,
}
impl Marshal for TpmsSpdmSessionInfo<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; TpmsSpdmSessionInfo::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsSpdmSessionInfo::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.req_key_name, dst, 0);
        marshal_helper(&self.tpm_key_name, dst, count)
    }
}
impl<'a> Unmarshal<'a> for TpmsSpdmSessionInfo<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            req_key_name: Unmarshal::unmarshal(src)?,
            tpm_key_name: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_CAPABILITY_DATA` union structure defined in TPM 2.0 Part 2: Structures, Section 10.6.2 (Table 128).
///
/// Data area returned in response to `TPM2_GetCapability`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum TpmsCapabilityData<'a> {
    Algorithms(TpmlAlgProperty) = TpmCap::Algs.tag(),
    Handles(TpmlHandle) = TpmCap::Handles.tag(),
    Command(TpmlCca) = TpmCap::Commands.tag(),
    PPCommands(TpmlCc) = TpmCap::PPCommands.tag(),
    AuditCommands(TpmlCc) = TpmCap::AuditCommands.tag(),
    AssignedPcr(TpmlPcrSelection) = TpmCap::PCRs.tag(),
    TpmProperties(TpmlTaggedTpmProperty) = TpmCap::TPMProperties.tag(),
    PcrProperties(TpmlTaggedPcrProperty) = TpmCap::PCRProperties.tag(),
    EccCurves(TpmlEccCurve) = TpmCap::ECCCurves.tag(),
    AuthPolicies(TpmlTaggedPolicy<'a>) = TpmCap::AuthPolicies.tag(),
    ActData(TpmlActData) = TpmCap::ACT.tag(),
    PubKeys(TpmlPubKey<'a>) = TpmCap::PubKeys.tag(),
    SpdmSessionInfo(TpmlSpdmSessionInfo<'a>) = TpmCap::SpdmSessionInfo.tag(),
    VendorProperty(TpmlVendorProperty<'a>) = TpmCap::VendorProperty.tag(),
}

impl<'a> Marshal for TpmsCapabilityData<'a> {
    const MAX_SIZE: usize = 4 + max(&[
        TpmlAlgProperty::MAX_SIZE,
        TpmlHandle::MAX_SIZE,
        TpmlCca::MAX_SIZE,
        TpmlCc::MAX_SIZE,
        TpmlPcrSelection::MAX_SIZE,
        TpmlTaggedTpmProperty::MAX_SIZE,
        TpmlTaggedPcrProperty::MAX_SIZE,
        TpmlEccCurve::MAX_SIZE,
        TpmlTaggedPolicy::MAX_SIZE,
        TpmlActData::MAX_SIZE,
        TpmlPubKey::MAX_SIZE,
        TpmlSpdmSessionInfo::MAX_SIZE,
        TpmlVendorProperty::MAX_SIZE,
    ]);
    type MaxBuffer = [u8; TpmsCapabilityData::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Self::Algorithms(x) => {
                let count = marshal_helper(&(TpmCap::Algs.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Handles(x) => {
                let count = marshal_helper(&(TpmCap::Handles.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Command(x) => {
                let count = marshal_helper(&(TpmCap::Commands.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::PPCommands(x) => {
                let count = marshal_helper(&(TpmCap::PPCommands.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::AuditCommands(x) => {
                let count = marshal_helper(&(TpmCap::AuditCommands.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::AssignedPcr(x) => {
                let count = marshal_helper(&(TpmCap::PCRs.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::TpmProperties(x) => {
                let count = marshal_helper(&(TpmCap::TPMProperties.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::PcrProperties(x) => {
                let count = marshal_helper(&(TpmCap::PCRProperties.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::EccCurves(x) => {
                let count = marshal_helper(&(TpmCap::ECCCurves.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::AuthPolicies(x) => {
                let count = marshal_helper(&(TpmCap::AuthPolicies.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::ActData(x) => {
                let count = marshal_helper(&(TpmCap::ACT.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::PubKeys(x) => {
                let count = marshal_helper(&(TpmCap::PubKeys.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::SpdmSessionInfo(x) => {
                let count = marshal_helper(&(TpmCap::SpdmSessionInfo.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::VendorProperty(x) => {
                let count = marshal_helper(&(TpmCap::VendorProperty.tag()), dst, 0);
                marshal_helper(x, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmsCapabilityData<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = TpmCap::unmarshal(src)?;
        match selector {
            TpmCap::Algs => Ok(Self::Algorithms(TpmlAlgProperty::unmarshal(src)?)),
            TpmCap::Handles => Ok(Self::Handles(TpmlHandle::unmarshal(src)?)),
            TpmCap::Commands => Ok(Self::Command(TpmlCca::unmarshal(src)?)),
            TpmCap::PPCommands => Ok(Self::PPCommands(TpmlCc::unmarshal(src)?)),
            TpmCap::AuditCommands => Ok(Self::AuditCommands(TpmlCc::unmarshal(src)?)),
            TpmCap::PCRs => Ok(Self::AssignedPcr(TpmlPcrSelection::unmarshal(src)?)),
            TpmCap::TPMProperties => {
                Ok(Self::TpmProperties(TpmlTaggedTpmProperty::unmarshal(src)?))
            }
            TpmCap::PCRProperties => {
                Ok(Self::PcrProperties(TpmlTaggedPcrProperty::unmarshal(src)?))
            }
            TpmCap::ECCCurves => Ok(Self::EccCurves(TpmlEccCurve::unmarshal(src)?)),
            TpmCap::AuthPolicies => Ok(Self::AuthPolicies(TpmlTaggedPolicy::unmarshal(src)?)),
            TpmCap::ACT => Ok(Self::ActData(TpmlActData::unmarshal(src)?)),
            TpmCap::PubKeys => Ok(Self::PubKeys(TpmlPubKey::unmarshal(src)?)),
            TpmCap::SpdmSessionInfo => {
                Ok(Self::SpdmSessionInfo(TpmlSpdmSessionInfo::unmarshal(src)?))
            }
            TpmCap::VendorProperty => Ok(Self::VendorProperty(TpmlVendorProperty::unmarshal(src)?)),
        }
    }
}

/// `TPMS_SET_CAPABILITY_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.6.3 (Table 129).
///
/// Specifies the capability and capability data to be set in `TPM2_SetCapability`.
#[doc(alias = "TPMS_SET_CAPABILITY_DATA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsSetCapabilityData<'a> {
    pub set_capability: TpmCap,
    pub data: TpmuSetCapabilities<'a>,
}

impl Marshal for TpmsSetCapabilityData<'_> {
    const MAX_SIZE: usize = TpmCap::MAX_SIZE + TpmuSetCapabilities::MAX_SIZE;
    type MaxBuffer = [u8; TpmsSetCapabilityData::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.set_capability, dst, 0);
        marshal_helper(&self.data, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsSetCapabilityData<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let set_capability = TpmCap::unmarshal(src)?;
        let data = TpmuSetCapabilities::unmarshal_variant(set_capability, src)?;
        Ok(Self {
            set_capability,
            data,
        })
    }
}

/// `TPMS_ALG_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.9 (Table 108).
///
/// Structure reporting algorithm properties (`alg`, `algProperties`).
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

/// `TPMS_TAGGED_PCR_SELECT` structure defined in TPM 2.0 Part 2: Structures, Section 10.7.5 (Table 110).
///
/// Structure reporting tagged PCR properties (`tag`, `sizeofSelect`, `pcrSelect`).
#[doc(alias = "TPMS_TAGGED_PCR_SELECT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsTaggedPcrSelect {
    /// The PCR property identifier.
    pub tag: TpmPtPcr,
    /// Size of the `pcr_select` array in bytes (`PCR_SELECT_MIN..=PCR_SELECT_MAX`).
    pub size_of_select: u8,
    /// Bitmask of PCRs with the identified property.
    pub pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

impl TpmsTaggedPcrSelect {
    /// Creates a new [`TpmsTaggedPcrSelect`], verifying that `selected_pcrs.len()` is within
    /// `TPM2_PCR_SELECT_MIN..=TPM2_PCR_SELECT_MAX`.
    pub fn new(tag: TpmPtPcr, selected_pcrs: &[u8]) -> Result<Self, TpmRc> {
        if selected_pcrs.len() < TPM2_PCR_SELECT_MIN
            || selected_pcrs.len() > TPM2_PCR_SELECT_MAX as usize
        {
            return Err(TpmRc::VALUE.to_rc());
        }
        let mut pcr_select = [0u8; TPM2_PCR_SELECT_MAX as usize];
        pcr_select[..selected_pcrs.len()].copy_from_slice(selected_pcrs);
        Ok(Self {
            tag,
            size_of_select: selected_pcrs.len() as u8,
            pcr_select,
        })
    }

    /// Returns the PCR property tag.
    pub const fn tag(&self) -> TpmPtPcr {
        self.tag
    }

    /// Returns the `size_of_select` value.
    pub const fn size_of_select(&self) -> u8 {
        self.size_of_select
    }

    /// Returns the `sizeof_select` value.
    pub const fn sizeof_select(&self) -> u8 {
        self.size_of_select
    }

    /// Returns the slice of selected PCR bits (`&pcr_select[..size_of_select]`),
    /// clamped to `pcr_select.len()`.
    pub fn pcr_select(&self) -> &[u8] {
        let len = (self.size_of_select as usize).min(self.pcr_select.len());
        &self.pcr_select[..len]
    }
}

impl Default for TpmsTaggedPcrSelect {
    fn default() -> Self {
        Self {
            tag: TpmPtPcr::default(),
            size_of_select: TPM2_PCR_SELECT_MIN as u8,
            pcr_select: [0u8; TPM2_PCR_SELECT_MAX as usize],
        }
    }
}

impl Marshal for TpmsTaggedPcrSelect {
    const MAX_SIZE: usize = TpmPtPcr::MAX_SIZE + 1 + (TPM2_PCR_SELECT_MAX as usize);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag, dst, 0);
        let sel_len = (self.size_of_select as usize).min(self.pcr_select.len());
        let count = marshal_helper(&(sel_len as u8), dst, count);
        dst[count..count + sel_len].copy_from_slice(&self.pcr_select[..sel_len]);
        count + sel_len
    }
}

impl<'a> Unmarshal<'a> for TpmsTaggedPcrSelect {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let tag = Unmarshal::unmarshal(src)?;
        let size_of_select = Unmarshal::unmarshal(src)?;
        let sel_len = size_of_select as usize;
        if sel_len < TPM2_PCR_SELECT_MIN || sel_len > (TPM2_PCR_SELECT_MAX as usize) {
            return Err(UnmarshalError::VALUE);
        }
        if src.len() < sel_len {
            return Err(UnmarshalError::INSUFFICIENT);
        }
        let (slice, rest) = src.split_at(sel_len);
        *src = rest;
        let mut pcr_select = [0u8; TPM2_PCR_SELECT_MAX as usize];
        pcr_select[..sel_len].copy_from_slice(slice);
        Ok(Self {
            tag,
            size_of_select,
            pcr_select,
        })
    }
}

/// `TPMS_TAGGED_POLICY` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.12 (Table 111).
///
/// Structure reporting policy associated with permanent handles (`handle`, `policyHash`).
///
/// When a permanent handle does not have an authorization policy set, `policy_hash`
/// is `None` (representing `TPM_ALG_NULL` with an empty digest).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsTaggedPolicy<'a> {
    pub handle: Handle,
    pub policy_hash: Option<TpmtHa<'a>>,
}

impl<'a> Marshal for TpmsTaggedPolicy<'a> {
    const MAX_SIZE: usize = Handle::MAX_SIZE + <Option<TpmtHa>>::MAX_SIZE;
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
        let session_handle = TpmiShAuthSession::<true>::unmarshal(src)?.0;
        Ok(Self {
            session_handle,
            nonce: Unmarshal::unmarshal(src)?,
            session_attributes: Unmarshal::unmarshal(src)?,
            hmac: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_AUTH_RESPONSE` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.26 (Table 146).
/// Format for each authorization in the session area of a response.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct TpmsAuthResponse<'a> {
    pub nonce: Tpm2bNonce<'a>,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bAuth<'a>,
}
impl Marshal for TpmsAuthResponse<'_> {
    const MAX_SIZE: usize = Tpm2bNonce::MAX_SIZE + TpmaSession::MAX_SIZE + Tpm2bAuth::MAX_SIZE;
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

/// `TPMS_ID_OBJECT` structure defined in TPM 2.0 Part 2: Structures, Section 12.3 (Table 220).
///
/// Structure containing credential integrity HMAC and encrypted credential for `TPM2_ActivateCredential`.
/// Per TPM 2.0 Spec Part 1 Section 24.4 and Part 2 Table 220, `enc_identity` is the raw CFB-encrypted
/// ciphertext of a marshaled `TPM2B_DIGEST` (including its encrypted 2-byte length prefix).
#[doc(alias = "TPMS_ID_OBJECT")]
#[derive(Clone, Copy, Debug)]
pub struct TpmsIdObject<'a> {
    pub integrity_hmac: Tpm2bDigest<'a>,
    pub enc_identity_len: usize,
    pub enc_identity: [u8; Tpm2bDigest::MAX_SIZE],
}

impl<'a> TpmsIdObject<'a> {
    /// Creates a new `TpmsIdObject` from an integrity HMAC and raw encrypted identity bytes.
    pub fn new(
        integrity_hmac: Tpm2bDigest<'a>,
        enc_identity_bytes: &[u8],
    ) -> Result<Self, UnmarshalError> {
        if (integrity_hmac.get_size() as usize) > Tpm2bDigest::MAX_BUFFER_SIZE
            || enc_identity_bytes.len() > Tpm2bDigest::MAX_SIZE
        {
            return Err(UnmarshalError::SIZE);
        }
        let mut enc_identity = [0u8; Tpm2bDigest::MAX_SIZE];
        enc_identity[..enc_identity_bytes.len()].copy_from_slice(enc_identity_bytes);
        Ok(Self {
            integrity_hmac,
            enc_identity_len: enc_identity_bytes.len(),
            enc_identity,
        })
    }

    /// Returns the slice of valid encrypted identity bytes.
    pub fn enc_identity(&self) -> &[u8] {
        &self.enc_identity[..self.enc_identity_len.min(Tpm2bDigest::MAX_SIZE)]
    }
}

impl Default for TpmsIdObject<'_> {
    fn default() -> Self {
        Self {
            integrity_hmac: Tpm2bDigest::default(),
            enc_identity_len: 0,
            enc_identity: [0u8; Tpm2bDigest::MAX_SIZE],
        }
    }
}

impl PartialEq for TpmsIdObject<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.integrity_hmac == other.integrity_hmac
            && self.enc_identity_len == other.enc_identity_len
            && self.enc_identity() == other.enc_identity()
    }
}

impl Eq for TpmsIdObject<'_> {}

impl Marshal for TpmsIdObject<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmsIdObject::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsIdObject::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.integrity_hmac, dst, 0);
        let enc_slice = self.enc_identity();
        dst[count..count + enc_slice.len()].copy_from_slice(enc_slice);
        count + enc_slice.len()
    }
}

impl<'a> Unmarshal<'a> for TpmsIdObject<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let integrity_hmac = Unmarshal::unmarshal(src)?;
        if src.len() > Tpm2bDigest::MAX_SIZE {
            return Err(UnmarshalError::SIZE);
        }
        let enc_identity_len = src.len();
        let mut enc_identity = [0u8; Tpm2bDigest::MAX_SIZE];
        enc_identity[..enc_identity_len].copy_from_slice(src);
        *src = &[];
        Ok(Self {
            integrity_hmac,
            enc_identity_len,
            enc_identity,
        })
    }
}

/// `TPMS_NV_PIN_COUNTER_PARAMETERS` structure defined in TPM 2.0 Part 2: Structures, Section 13.3 (Table 224).
///
/// Defines the data written to and read from a `TPM_NT_PIN_PASS` or `TPM_NT_PIN_FAIL`
/// non-volatile index. `pin_count` is the most significant octets and `pin_limit` is
/// the least significant octets.
#[doc(alias = "TPMS_NV_PIN_COUNTER_PARAMETERS")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TpmsNvPinCounterParameters {
    pub pin_count: u32,
    pub pin_limit: u32,
}

impl Marshal for TpmsNvPinCounterParameters {
    const MAX_SIZE: usize = u32::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.pin_count, dst, 0);
        marshal_helper(&self.pin_limit, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsNvPinCounterParameters {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pin_count: Unmarshal::unmarshal(src)?,
            pin_limit: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_NV_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 13.2 (Table 227).
///
/// Defines the public area parameters for an NV Index (index handle, name hash algorithm, attributes, policy, and data size).
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
        let nv_index = TpmiRhNvLegacyIndex::unmarshal(src)?.0;
        let name_alg = Unmarshal::unmarshal(src)?;
        let attributes = Unmarshal::unmarshal(src)?;
        let auth_policy = Unmarshal::unmarshal(src)?;
        let data_size = Unmarshal::unmarshal(src)?;
        if data_size > TPM2_MAX_NV_INDEX_SIZE {
            return Err(UnmarshalError::SIZE);
        }
        Ok(Self {
            nv_index,
            name_alg,
            attributes,
            auth_policy,
            data_size,
        })
    }
}

impl Default for TpmsNvPublic<'_> {
    fn default() -> Self {
        Self {
            nv_index: Handle(0),
            name_alg: TpmiAlgHash::DEFAULT_HASH,
            attributes: TpmaNv::empty(),
            auth_policy: Default::default(),
            data_size: 0,
        }
    }
}

/// `TPMS_NV_PUBLIC_EXP_ATTR` structure defined in TPM 2.0 Part 2: Structures, Section 13.5 (Table 229).
///
/// Defines the public area parameters for an NV Index with expanded 64-bit attributes (`TPMA_NV_EXP`).
#[doc(alias = "TPMS_NV_PUBLIC_EXP_ATTR")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmsNvPublicExpAttr<'a> {
    pub nv_index: Handle,
    pub name_alg: TpmiAlgHash,
    pub attributes: TpmaNvExp,
    pub auth_policy: Tpm2bDigest<'a>,
    pub data_size: u16,
}

impl Marshal for TpmsNvPublicExpAttr<'_> {
    const MAX_SIZE: usize = Handle::MAX_SIZE
        + TpmiAlgHash::MAX_SIZE
        + TpmaNvExp::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + u16::MAX_SIZE;
    type MaxBuffer = [u8; TpmsNvPublicExpAttr::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsNvPublicExpAttr::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.nv_index, dst, 0);
        let count = marshal_helper(&self.name_alg, dst, count);
        let count = marshal_helper(&self.attributes, dst, count);
        let count = marshal_helper(&self.auth_policy, dst, count);
        marshal_helper(&self.data_size, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsNvPublicExpAttr<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let nv_index = TpmiRhNvExpIndex::unmarshal(src)?.0;
        let name_alg = Unmarshal::unmarshal(src)?;
        let attributes = Unmarshal::unmarshal(src)?;
        let auth_policy = Unmarshal::unmarshal(src)?;
        let data_size = Unmarshal::unmarshal(src)?;
        if data_size > TPM2_MAX_NV_INDEX_SIZE {
            return Err(UnmarshalError::SIZE);
        }
        Ok(Self {
            nv_index,
            name_alg,
            attributes,
            auth_policy,
            data_size,
        })
    }
}

impl Default for TpmsNvPublicExpAttr<'_> {
    fn default() -> Self {
        Self {
            nv_index: Handle(0),
            name_alg: TpmiAlgHash::DEFAULT_HASH,
            attributes: TpmaNvExp::empty(),
            auth_policy: Default::default(),
            data_size: 0,
        }
    }
}

/// `TPMS_CONTEXT_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 14.3 (Table 234).
///
/// Holds integrity values and encrypted data for a saved context in `TPM2_ContextSave` and `TPM2_ContextLoad`.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct TpmsContextData<'a> {
    pub integrity: Tpm2bDigest<'a>,
    pub encrypted: Tpm2bContextSensitive<'a>,
}
impl Marshal for TpmsContextData<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + Tpm2bContextSensitive::MAX_SIZE;
    type MaxBuffer = [u8; TpmsContextData::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmsContextData::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.integrity, dst, 0);
        marshal_helper(&self.encrypted, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsContextData<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            integrity: Unmarshal::unmarshal(src)?,
            encrypted: Unmarshal::unmarshal(src)?,
        })
    }
}

/// `TPMS_CONTEXT` structure defined in TPM 2.0 Part 2: Structures, Section 14.3 (Table 233).
///
/// Parameter structure for `TPM2_ContextSave` and `TPM2_ContextLoad` containing sequence number, handle, hierarchy, and context data.
#[doc(alias = "TPMS_CONTEXT")]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
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
        let sequence = Unmarshal::unmarshal(src)?;
        let saved_handle = TpmiDhSaved::unmarshal(src)?.0;
        let hierarchy = TpmiRhHierarchy::unmarshal(src)?.0;
        let context_blob = Unmarshal::unmarshal(src)?;
        Ok(Self {
            sequence,
            saved_handle,
            hierarchy,
            context_blob,
        })
    }
}

/// `TPMS_CREATION_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 15.1 (Table 238).
///
/// Creation data recorded when an object is created, including parent name and creation PCR digest.
#[doc(alias = "TPMS_CREATION_DATA")]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct TpmsCreationData<'a> {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest<'a>,
    pub locality: TpmaLocality,
    pub parent_name_alg: Alg,
    pub parent_name: Tpm2bName<'a>,
    pub parent_qualified_name: Tpm2bName<'a>,
    pub outside_info: Tpm2bData<'a>,
}

impl Marshal for TpmsCreationData<'_> {
    const MAX_SIZE: usize = TpmlPcrSelection::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + TpmaLocality::MAX_SIZE
        + Alg::MAX_SIZE
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

/// `TPMS_AC_OUTPUT` structure defined in TPM 2.0 Part 2: Structures, Section 14.9 (Table 242).
///
/// Used to return information about an Attached Component (AC). When `tag` is [`TpmAt::ERROR`],
/// `data` holds an AC error value such as [`TpmAe::NONE`].
#[doc(alias = "TPMS_AC_OUTPUT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmsAcOutput {
    pub tag: TpmAt,
    pub data: u32,
}

impl Marshal for TpmsAcOutput {
    const MAX_SIZE: usize = TpmAt::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag, dst, 0);
        marshal_helper(&self.data, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmsAcOutput {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            tag: Unmarshal::unmarshal(src)?,
            data: Unmarshal::unmarshal(src)?,
        })
    }
}
