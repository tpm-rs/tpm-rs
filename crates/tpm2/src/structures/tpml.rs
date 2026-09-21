use core::fmt;

use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

const MAX_CAP_DATA: usize = limits::MAX_CAP_BUFFER - TpmCap::MAX_SIZE - u32::MAX_SIZE;

/// An element type that can be stored in a [`Tpml`] list, providing a `const` default value for uninitialized array slots.
pub trait TpmlElement: Copy {
    const DEFAULT: Self;
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

impl<'a, T: TpmlElement + Unmarshal<'a>, const CAP: usize> Unmarshal<'a> for Tpml<T, CAP> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = u32::unmarshal(src)?;
        const { assert!(CAP <= 0xFFFF_FFFF) };
        if count > (CAP as u32) {
            return Err(UnmarshalError);
        }

        let mut array = [T::DEFAULT; CAP];
        for elem in &mut array[..(count as usize)] {
            *elem = T::unmarshal(src)?;
        }
        Ok(Self { count, array })
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
        hash: TpmiAlgHash::Sha256,
        selection: TpmsPcrSelect::new(&[0; TpmsPcrSelect::MIN]).unwrap(),
    };
}

/// `TPML_ALG_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.9 (Table 128).
///
/// Holds a count and an array of algorithm properties (`TPMS_ALG_PROPERTY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_ALGS)`.
#[doc(alias = "TPML_ALG_PROPERTY")]
pub type TpmlAlgProperty = Tpml<TpmsAlgProperty, { MAX_CAP_DATA / TpmsAlgProperty::MAX_SIZE }>;
impl_marshal!(TpmlAlgProperty);
impl TpmlElement for TpmsAlgProperty {
    const DEFAULT: Self = Self {
        alg: Alg::NULL,
        alg_properties: TpmaAlgorithm(0),
    };
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

/// `TPML_HANDLE` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.5 (Table 124).
///
/// Holds a count and an array of TPM handle values (`TPM_HANDLE`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_HANDLES)`.
#[doc(alias = "TPML_HANDLE")]
pub type TpmlHandle = Tpml<Handle, { MAX_CAP_DATA / Handle::MAX_SIZE }>;
impl_marshal!(TpmlHandle);
impl TpmlElement for Handle {
    const DEFAULT: Self = Self(0);
}

/// `TPML_CCA` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.3 (Table 122).
///
/// Holds a count and an array of command attributes (`TPMA_CC`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_COMMANDS)`.
#[doc(alias = "TPML_CCA")]
pub type TpmlCca = Tpml<TpmaCc, { MAX_CAP_DATA / TpmaCc::MAX_SIZE }>;
impl_marshal!(TpmlCca);
impl TpmlElement for TpmaCc {
    const DEFAULT: Self = Self(0);
}

/// `TPML_CC` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.2 (Table 121).
///
/// Holds a count and an array of command codes (`TPM_CC`).
/// Used in capability reporting and command audit settings.
#[doc(alias = "TPML_CC")]
pub type TpmlCc = Tpml<TpmCc, { MAX_CAP_DATA / TpmCc::MAX_SIZE }>;
impl_marshal!(TpmlCc);
impl TpmlElement for TpmCc {
    const DEFAULT: Self = Self::new(0);
}

/// `TPML_TAGGED_TPM_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.10 (Table 129).
///
/// Holds a count and an array of tagged TPM property structures (`TPMS_TAGGED_PROPERTY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)`.
#[doc(alias = "TPML_TAGGED_TPM_PROPERTY")]
pub type TpmlTaggedTpmProperty =
    Tpml<TpmsTaggedProperty, { MAX_CAP_DATA / TpmsTaggedProperty::MAX_SIZE }>;
impl_marshal!(TpmlTaggedTpmProperty);
impl TpmlElement for TpmsTaggedProperty {
    const DEFAULT: Self = Self {
        property: TpmPt::FamilyIndicator,
        value: 0,
    };
}

/// `TPML_TAGGED_PCR_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.11 (Table 130).
///
/// Holds a count and an array of tagged PCR property structures (`TPMS_TAGGED_PCR_SELECT`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_PCRS)`.
#[doc(alias = "TPML_TAGGED_PCR_PROPERTY")]
pub type TpmlTaggedPcrProperty =
    Tpml<TpmsTaggedPcrSelect, { MAX_CAP_DATA / TpmsTaggedPcrSelect::MAX_SIZE }>;
impl_marshal!(TpmlTaggedPcrProperty);
impl TpmlElement for TpmsTaggedPcrSelect {
    const DEFAULT: Self = Self {
        tag: TpmPtPcr::Save,
        selection: TpmsPcrSelect::new(&[0; TpmsPcrSelect::MIN]).unwrap(),
    };
}

/// `TPML_ECC_CURVE` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.12 (Table 131).
///
/// Holds a count and an array of ECC curve identifiers (`TPM_ECC_CURVE`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_ECC_CURVES)`.
#[doc(alias = "TPML_ECC_CURVE")]
pub type TpmlEccCurve = Tpml<TpmEccCurve, { MAX_CAP_DATA / TpmEccCurve::MAX_SIZE }>;
impl_marshal!(TpmlEccCurve);
impl TpmlElement for TpmEccCurve {
    const DEFAULT: Self = Self::NistP192;
}

/// `TPML_TAGGED_POLICY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.13 (Table 132).
///
/// Holds a count and an array of tagged policy structures (`TPMS_TAGGED_POLICY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_POLICIES)`.
#[doc(alias = "TPML_TAGGED_POLICY")]
pub type TpmlTaggedPolicy<'a> =
    Tpml<TpmsTaggedPolicy<'a>, { MAX_CAP_DATA / TpmsTaggedPolicy::MAX_SIZE }>;
impl_marshal!(TpmlTaggedPolicy<'_>);
impl<'a> TpmlElement for TpmsTaggedPolicy<'a> {
    const DEFAULT: Self = Self {
        handle: Handle(0),
        policy_hash: TpmtHa::DEFAULT,
    };
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

/// `TPML_DIGEST_VALUES` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.7 (Table 126).
///
/// Holds a count and an array of tagged digest values (`TPMT_HA`).
/// Used in `TPM2_PCR_Extend` and `TPM2_EventSequenceComplete` to pass digests for multiple hash algorithms simultaneously.
#[doc(alias = "TPML_DIGEST_VALUES")]
pub type TpmlDigestValues<'a> = Tpml<TpmtHa<'a>, { TpmiAlgHash::HASH_COUNT }>;
impl_marshal!(TpmlDigestValues<'_>);
impl<'a> TpmlElement for TpmtHa<'a> {
    const DEFAULT: Self = Self::Sha256(&[0; TpmiAlgHash::Sha256.digest_size()]);
}
