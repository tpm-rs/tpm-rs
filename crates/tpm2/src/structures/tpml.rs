use core::fmt;

use crate::{
    errors::{TpmRc, UnmarshalError},
    marshal::marshal_helper,
    *,
};

pub const TPM2_MAX_CAP_DATA: usize = limits::MAX_CAP_BUFFER - TpmCap::MAX_SIZE - u32::MAX_SIZE;
pub const TPM2_MAX_CAP_ALGS: usize = TPM2_MAX_CAP_DATA / TpmsAlgProperty::MAX_SIZE;
pub const TPM2_MAX_CAP_HANDLES: usize = TPM2_MAX_CAP_DATA / Handle::MAX_SIZE;
pub const TPM2_MAX_CAP_CC: usize = TPM2_MAX_CAP_DATA / TpmCc::MAX_SIZE;
pub const TPM2_MAX_TPM_PROPERTIES: usize = TPM2_MAX_CAP_DATA / TpmsTaggedProperty::MAX_SIZE;
pub const TPM2_MAX_PCR_PROPERTIES: usize = TPM2_MAX_CAP_DATA / TpmsTaggedPcrSelect::MAX_SIZE;
pub const TPM2_MAX_ECC_CURVES: usize = TPM2_MAX_CAP_DATA / TpmEccCurve::MAX_SIZE;
pub const TPM2_MAX_TAGGED_POLICIES: usize = TPM2_MAX_CAP_DATA / TpmsTaggedPolicy::MAX_SIZE;
pub const TPM2_MAX_ACT_DATA: usize = TPM2_MAX_CAP_DATA / TpmsActData::MAX_SIZE;
pub const TPM2_MAX_PUB_KEYS: usize =
    crate::marshal::max(&[TPM2_MAX_CAP_DATA / Tpm2bPublic::MAX_SIZE, 1]);
pub const TPM2_MAX_SPDM_SESSION_INFO: usize = TPM2_MAX_CAP_DATA / TpmsSpdmSessionInfo::MAX_SIZE;
pub const TPM2_MAX_VENDOR_PROPERTY: usize = if TPM2_MAX_CAP_DATA / Tpm2bVendorProperty::MAX_SIZE > 0
{
    TPM2_MAX_CAP_DATA / Tpm2bVendorProperty::MAX_SIZE
} else {
    1
};
pub const TPM2_MAX_AC_CAPABILITIES: usize = TPM2_MAX_CAP_DATA / TpmsAcOutput::MAX_SIZE;
pub const TPML_DIGEST_MAX_DIGESTS: usize = 8;
pub const TPM2_MAX_ALG_LIST_SIZE: usize = 64;

/// An element type that can be stored in a [`Tpml`] list, providing a `const` default value for uninitialized array slots
/// and the [`UnmarshalError`] returned when the list `count` exceeds capacity.
pub trait TpmlElement: Copy {
    const DEFAULT: Self;
    const COUNT_OVERFLOW_ERROR: UnmarshalError = UnmarshalError::SIZE;
}

/// A length-prefixed (`u32`) list of up to `CAP` elements of type `T` (representing `TPML_*` structures in TPM 2.0 Part 2, Section 10.5).
#[derive(Clone, Copy)]
pub struct Tpml<T, const CAP: usize> {
    count: u32,
    array: [T; CAP],
}

impl<T: PartialEq, const CAP: usize> PartialEq for Tpml<T, CAP> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl<T: Eq, const CAP: usize> Eq for Tpml<T, CAP> {}
impl<T: fmt::Debug, const CAP: usize> fmt::Debug for Tpml<T, CAP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Tpml").field(&self.as_slice()).finish()
    }
}
impl<T: TpmlElement, const CAP: usize> Default for Tpml<T, CAP> {
    fn default() -> Self {
        Self::new(&[]).unwrap()
    }
}
impl<T, const CAP: usize> AsRef<[T]> for Tpml<T, CAP> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, const CAP: usize> Tpml<T, CAP> {
    /// Helper constant to access the capacity of a `Tpml` type. For example,
    /// [`TpmlPcrSelection::CAP`] is equal to [`TpmiAlgHash::HASH_COUNT`].
    pub const CAP: usize = CAP;

    pub const fn as_slice(&self) -> &[T] {
        debug_assert!(self.count as usize <= CAP);
        if let Some((head, _)) = self.array.split_at_checked(self.count as usize) {
            head
        } else {
            &self.array
        }
    }

    pub const fn count(&self) -> usize {
        self.count as usize
    }

    pub fn add(&mut self, elem: &T) -> Result<(), TpmRc>
    where
        T: Copy,
    {
        let idx = self.count as usize;
        if idx >= CAP {
            return Err(TpmRc::SIZE.to_rc());
        }
        self.array[idx] = *elem;
        self.count += 1;
        Ok(())
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        self.as_slice().get(index)
    }
}

impl<T: TpmlElement, const CAP: usize> Tpml<T, CAP> {
    pub const fn new(slice: &[T]) -> Option<Self> {
        let mut array = [T::DEFAULT; CAP];
        let Some((dst, _)) = array.split_at_mut_checked(slice.len()) else {
            return None;
        };
        dst.copy_from_slice(slice);

        const { assert!(CAP <= 0xFFFF_FFFF) };
        Some(Self {
            count: slice.len() as u32,
            array,
        })
    }

    pub const fn from_slice(slice: &[T]) -> Option<Self> {
        Self::new(slice)
    }
}

impl<T, const CAP: usize> core::ops::Index<usize> for Tpml<T, CAP> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<T: Marshal<MaxBuffer = [u8; N]>, const N: usize, const CAP: usize> Tpml<T, CAP> {
    const fn max_size() -> usize {
        u32::MAX_SIZE + CAP * N
    }

    fn marshal_helper<const M: usize>(&self, dst: &mut [u8; M]) -> usize {
        const { assert!(M == Self::max_size()) };
        let mut offset = marshal_helper(&self.count, dst, 0);
        for elem in self.as_slice() {
            offset = marshal_helper(elem, dst, offset);
        }
        offset
    }
}

macro_rules! impl_marshal {
    ($ty:ty) => {
        impl Marshal for $ty {
            const MAX_SIZE: usize = Self::max_size();
            type MaxBuffer = [u8; <$ty>::MAX_SIZE];

            fn marshal(&self, dst: &mut [u8; <$ty>::MAX_SIZE]) -> usize {
                Self::marshal_helper(self, dst)
            }
        }
    };
}

impl<'a, T: TpmlElement + Unmarshal<'a>, const CAP: usize> Tpml<T, CAP> {
    /// Unmarshals a [`Tpml`] ensuring the element count is at least `min_count` and at most `CAP`.
    pub fn unmarshal_with_min_count(
        src: &mut &'a [u8],
        min_count: u32,
    ) -> Result<Self, UnmarshalError> {
        let count = u32::unmarshal(src)?;
        const { assert!(CAP <= 0xFFFF_FFFF) };
        if count < min_count {
            return Err(UnmarshalError::SIZE);
        }
        if count > (CAP as u32) {
            return Err(T::COUNT_OVERFLOW_ERROR);
        }
        let mut array = [T::DEFAULT; CAP];
        for elem in &mut array[..(count as usize)] {
            *elem = T::unmarshal(src)?;
        }
        Ok(Self { count, array })
    }

    /// Unmarshals a [`Tpml`] in-place ensuring the element count is at least `min_count` and at most `CAP`.
    ///
    /// On success, returns the remaining, unused bytes from `src`. On failure,
    /// `*self` remains unmodified.
    pub fn unmarshal_ref_with_min_count(
        &mut self,
        mut src: &'a [u8],
        min_count: u32,
    ) -> Result<&'a [u8], UnmarshalError> {
        *self = Self::unmarshal_with_min_count(&mut src, min_count)?;
        Ok(src)
    }
}

impl<'a, T: TpmlElement + Unmarshal<'a>, const CAP: usize> Unmarshal<'a> for Tpml<T, CAP> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Self::unmarshal_with_min_count(src, 0)
    }

    fn unmarshal_ref(&mut self, src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
        self.unmarshal_ref_with_min_count(src, 0)
    }
}

/// `TPML_PCR_SELECTION` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.8 (Table 127).
///
/// Holds a count and an array of PCR selection structures (`TPMS_PCR_SELECTION`), representing PCR selections across multiple hash banks.
/// Used in commands such as `TPM2_PCR_Read`, `TPM2_PolicyPCR`, and `TPM2_Quote`.
#[doc(alias = "TPML_PCR_SELECTION")]
pub type TpmlPcrSelection = Tpml<TpmsPcrSelection, { TpmiAlgHash::HASH_COUNT }>;
impl_marshal!(TpmlPcrSelection);
impl TpmlElement for TpmsPcrSelection {
    const DEFAULT: Self = Self {
        hash: TpmiAlgHash::DEFAULT_HASH,
        sizeof_select: TPM2_PCR_SELECT_MIN as u8,
        pcr_select: [0u8; TPM2_PCR_SELECT_MAX as usize],
    };
}
impl<const CAP: usize> Tpml<TpmsPcrSelection, CAP> {
    pub fn pcr_selections(&self) -> core::slice::Iter<'_, TpmsPcrSelection> {
        self.as_slice().iter()
    }
}

/// `TPML_ALG_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.9 (Table 128).
///
/// Holds a count and an array of algorithm properties (`TPMS_ALG_PROPERTY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_ALGS)`.
#[doc(alias = "TPML_ALG_PROPERTY")]
pub type TpmlAlgProperty = Tpml<TpmsAlgProperty, { TPM2_MAX_CAP_DATA / TpmsAlgProperty::MAX_SIZE }>;
impl_marshal!(TpmlAlgProperty);
impl TpmlElement for TpmsAlgProperty {
    const DEFAULT: Self = Self {
        alg: Alg::NULL,
        alg_properties: TpmaAlgorithm(0),
    };
}
impl<const CAP: usize> Tpml<TpmsAlgProperty, CAP> {
    pub const fn alg_properties(&self) -> &[TpmsAlgProperty] {
        self.as_slice()
    }
}

/// `TPML_ALG` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.4 (Table 123).
///
/// Holds a count and an array of algorithm identifiers (`TPM_ALG_ID`).
/// Used in capability reporting and parameter validation.
#[doc(alias = "TPML_ALG")]
pub type TpmlAlg = Tpml<Alg, 64>;
impl_marshal!(TpmlAlg);
impl TpmlElement for Alg {
    const DEFAULT: Self = Self::NULL;
}
impl<const CAP: usize> Tpml<Alg, CAP> {
    pub const fn algorithms(&self) -> &[Alg] {
        self.as_slice()
    }
}

/// `TPML_HANDLE` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.5 (Table 124).
///
/// Holds a count and an array of TPM handle values (`TPM_HANDLE`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_HANDLES)`.
#[doc(alias = "TPML_HANDLE")]
pub type TpmlHandle = Tpml<Handle, { TPM2_MAX_CAP_DATA / Handle::MAX_SIZE }>;
impl_marshal!(TpmlHandle);
impl TpmlElement for Handle {
    const DEFAULT: Self = Self(0);
}
impl<const CAP: usize> Tpml<Handle, CAP> {
    pub const fn handle(&self) -> &[Handle] {
        self.as_slice()
    }
}

/// `TPML_CCA` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.3 (Table 122).
///
/// Holds a count and an array of command attributes (`TPMA_CC`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_COMMANDS)`.
#[doc(alias = "TPML_CCA")]
pub type TpmlCca = Tpml<TpmaCc, { TPM2_MAX_CAP_DATA / TpmaCc::MAX_SIZE }>;
impl_marshal!(TpmlCca);
impl TpmlElement for TpmaCc {
    const DEFAULT: Self = Self(0);
}
impl<const CAP: usize> Tpml<TpmaCc, CAP> {
    pub const fn command_attributes(&self) -> &[TpmaCc] {
        self.as_slice()
    }
}

/// `TPML_CC` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.2 (Table 121).
///
/// Holds a count and an array of command codes (`TPM_CC`).
/// Used in capability reporting and command audit settings.
#[doc(alias = "TPML_CC")]
pub type TpmlCc = Tpml<TpmCc, { TPM2_MAX_CAP_DATA / TpmCc::MAX_SIZE }>;
impl_marshal!(TpmlCc);
impl TpmlElement for TpmCc {
    const DEFAULT: Self = Self::new(0);
}
impl<const CAP: usize> Tpml<TpmCc, CAP> {
    pub const fn command_codes(&self) -> &[TpmCc] {
        self.as_slice()
    }
}

/// `TPML_TAGGED_TPM_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.10 (Table 129).
///
/// Holds a count and an array of tagged TPM property structures (`TPMS_TAGGED_PROPERTY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)`.
#[doc(alias = "TPML_TAGGED_TPM_PROPERTY")]
pub type TpmlTaggedTpmProperty =
    Tpml<TpmsTaggedProperty, { TPM2_MAX_CAP_DATA / TpmsTaggedProperty::MAX_SIZE }>;
impl_marshal!(TpmlTaggedTpmProperty);
impl TpmlElement for TpmsTaggedProperty {
    const DEFAULT: Self = Self {
        property: TpmPt(0),
        value: 0,
    };
}
impl<const CAP: usize> Tpml<TpmsTaggedProperty, CAP> {
    pub const fn tpm_property(&self) -> &[TpmsTaggedProperty] {
        self.as_slice()
    }
}

/// `TPML_TAGGED_PCR_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.11 (Table 130).
///
/// Holds a count and an array of tagged PCR property structures (`TPMS_TAGGED_PCR_SELECT`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_PCRS)`.
#[doc(alias = "TPML_TAGGED_PCR_PROPERTY")]
pub type TpmlTaggedPcrProperty =
    Tpml<TpmsTaggedPcrSelect, { TPM2_MAX_CAP_DATA / TpmsTaggedPcrSelect::MAX_SIZE }>;
impl_marshal!(TpmlTaggedPcrProperty);
impl TpmlElement for TpmsTaggedPcrSelect {
    const DEFAULT: Self = Self {
        tag: TpmPtPcr(0),
        size_of_select: TPM2_PCR_SELECT_MIN as u8,
        pcr_select: [0u8; TPM2_PCR_SELECT_MAX as usize],
    };
}
impl<const CAP: usize> Tpml<TpmsTaggedPcrSelect, CAP> {
    pub const fn pcr_property(&self) -> &[TpmsTaggedPcrSelect] {
        self.as_slice()
    }
}

/// `TPML_ECC_CURVE` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.12 (Table 131).
///
/// Holds a count and an array of ECC curve identifiers (`TPM_ECC_CURVE`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_ECC_CURVES)`.
#[doc(alias = "TPML_ECC_CURVE")]
pub type TpmlEccCurve = Tpml<TpmEccCurve, { TPM2_MAX_CAP_DATA / TpmEccCurve::MAX_SIZE }>;
impl_marshal!(TpmlEccCurve);
impl TpmlElement for TpmEccCurve {
    const DEFAULT: Self = Self::None;
}
impl<const CAP: usize> Tpml<TpmEccCurve, CAP> {
    pub const fn ecc_curves(&self) -> &[TpmEccCurve] {
        self.as_slice()
    }
}

/// `TPML_TAGGED_POLICY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.13 (Table 132).
///
/// Holds a count and an array of tagged policy structures (`TPMS_TAGGED_POLICY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_AUTH_POLICIES)`.
#[doc(alias = "TPML_TAGGED_POLICY")]
pub type TpmlTaggedPolicy<'a> =
    Tpml<TpmsTaggedPolicy<'a>, { TPM2_MAX_CAP_DATA / TpmsTaggedPolicy::MAX_SIZE }>;
impl_marshal!(TpmlTaggedPolicy<'_>);
impl<'a> TpmlElement for TpmsTaggedPolicy<'a> {
    const DEFAULT: Self = Self {
        handle: Handle(0),
        policy_hash: None,
    };
}
impl<'a, const CAP: usize> Tpml<TpmsTaggedPolicy<'a>, CAP> {
    pub fn policies(&self) -> core::slice::Iter<'_, TpmsTaggedPolicy<'a>> {
        self.as_slice().iter()
    }
}

/// `TPML_DIGEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.6 (Table 125).
///
/// Holds a count and an array of digest values (`TPM2B_DIGEST`).
/// Used in commands such as `TPM2_PolicyOR` to provide a list of expected policy hashes.
#[doc(alias = "TPML_DIGEST")]
pub type TpmlDigest<'a> = Tpml<Tpm2bDigest<'a>, 8>;
impl_marshal!(TpmlDigest<'_>);
impl<'a> TpmlElement for Tpm2bDigest<'a> {
    const DEFAULT: Self = Self::new(&[]).unwrap();
}
impl<'a, const CAP: usize> Tpml<Tpm2bDigest<'a>, CAP> {
    pub const fn digests(&self) -> &[Tpm2bDigest<'a>] {
        self.as_slice()
    }
}

/// `TPML_DIGEST_VALUES` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.7 (Table 126).
///
/// Holds a count and an array of tagged digest values (`TPMT_HA`).
/// Used in `TPM2_PCR_Extend` and `TPM2_EventSequenceComplete` to pass digests for multiple hash algorithms simultaneously.
#[doc(alias = "TPML_DIGEST_VALUES")]
pub type TpmlDigestValues<'a> = Tpml<TpmtHa<'a>, { TpmiAlgHash::HASH_COUNT }>;
impl_marshal!(TpmlDigestValues<'_>);
impl<'a> TpmlElement for TpmtHa<'a> {
    const DEFAULT: Self = Self::DEFAULT_HA;
}
impl<'a, const CAP: usize> Tpml<TpmtHa<'a>, CAP> {
    pub fn digests(&self) -> core::slice::Iter<'_, TpmtHa<'a>> {
        self.as_slice().iter()
    }
}

/// `TPML_ACT_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.14 (Table 133).
///
/// Holds a count and an array of ACT data structures (`TPMS_ACT_DATA`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_ACT)`.
#[doc(alias = "TPML_ACT_DATA")]
pub type TpmlActData = Tpml<TpmsActData, TPM2_MAX_ACT_DATA>;
impl_marshal!(TpmlActData);
impl TpmlElement for TpmsActData {
    const DEFAULT: Self = Self {
        handle: Handle(0),
        timeout: 0,
        attributes: TpmaAct(0),
    };
}
impl<const CAP: usize> Tpml<TpmsActData, CAP> {
    pub const fn act_data(&self) -> &[TpmsActData] {
        self.as_slice()
    }
}

/// `TPML_PUB_KEY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.15 (Table 134).
///
/// Holds a count and an array of public key structures (`TPM2B_PUBLIC`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_PUB_KEYS)`.
#[doc(alias = "TPML_PUB_KEY")]
pub type TpmlPubKey<'a> = Tpml<Tpm2bPublic<'a>, TPM2_MAX_PUB_KEYS>;
impl_marshal!(TpmlPubKey<'_>);
impl<'a> TpmlElement for Tpm2bPublic<'a> {
    const DEFAULT: Self = Tpm2b::new(TpmtPublic {
        name_alg: None,
        object_attributes: TpmaObject(0),
        auth_policy: Tpm2bDigest::DEFAULT,
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::DEFAULT),
    });
}
impl<'a, const CAP: usize> Tpml<Tpm2bPublic<'a>, CAP> {
    pub const fn pub_keys(&self) -> &[Tpm2bPublic<'a>] {
        self.as_slice()
    }
}

/// `TPML_SPDM_SESSION_INFO` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.16 (Table 135).
///
/// Holds a count and an array of SPDM session information structures (`TPMS_SPDM_SESSION_INFO`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO)`.
#[doc(alias = "TPML_SPDM_SESSION_INFO")]
pub type TpmlSpdmSessionInfo<'a> = Tpml<TpmsSpdmSessionInfo<'a>, TPM2_MAX_SPDM_SESSION_INFO>;
impl_marshal!(TpmlSpdmSessionInfo<'_>);
impl<'a> TpmlElement for TpmsSpdmSessionInfo<'a> {
    const DEFAULT: Self = Self {
        req_key_name: Tpm2bName::new(&[]).unwrap(),
        tpm_key_name: Tpm2bName::new(&[]).unwrap(),
    };
}
impl<'a, const CAP: usize> Tpml<TpmsSpdmSessionInfo<'a>, CAP> {
    pub const fn spdm_session_info(&self) -> &[TpmsSpdmSessionInfo<'a>] {
        self.as_slice()
    }
}

/// `TPML_VENDOR_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.17 (Table 136).
///
/// Holds a count and an array of vendor property buffers (`TPM2B_VENDOR_PROPERTY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_VENDOR_PROPERTY)`.
#[doc(alias = "TPML_VENDOR_PROPERTY")]
pub type TpmlVendorProperty<'a> = Tpml<Tpm2bVendorProperty<'a>, TPM2_MAX_VENDOR_PROPERTY>;
impl_marshal!(TpmlVendorProperty<'_>);
impl<'a> TpmlElement for Tpm2bVendorProperty<'a> {
    const DEFAULT: Self = Self::new(&[]).unwrap();
    const COUNT_OVERFLOW_ERROR: UnmarshalError = UnmarshalError::VALUE;
}
impl<'a, const CAP: usize> Tpml<Tpm2bVendorProperty<'a>, CAP> {
    pub const fn vendor_property(&self) -> &[Tpm2bVendorProperty<'a>] {
        self.as_slice()
    }
}

/// `TPML_AC_CAPABILITIES` structure defined in TPM 2.0 Part 2: Structures, Section 10.12.4 (Table 243).
///
/// Holds a count and an array of AC capabilities structures (`TPMS_AC_OUTPUT`).
/// Returned in response to `TPM2_AC_GetCapability`.
#[doc(alias = "TPML_AC_CAPABILITIES")]
pub type TpmlAcCapabilities = Tpml<TpmsAcOutput, TPM2_MAX_AC_CAPABILITIES>;
impl_marshal!(TpmlAcCapabilities);
impl TpmlElement for TpmsAcOutput {
    const DEFAULT: Self = Self {
        tag: TpmAt(0),
        data: 0,
    };
}
impl<const CAP: usize> Tpml<TpmsAcOutput, CAP> {
    pub const fn ac_capabilities(&self) -> &[TpmsAcOutput] {
        self.as_slice()
    }
}
