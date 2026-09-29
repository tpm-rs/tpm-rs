use core::{fmt, marker::PhantomData};

use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// Backwards-compatible trait for byte-slice `Tpm2bSized` buffers.
pub trait Tpm2bSimple<'a>: Sized {
    const MAX_BUFFER_SIZE: usize;
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &'a [u8];
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, UnmarshalError>;
}

impl<'a, Tag: limits::Tag> Tpm2bSimple<'a> for Tpm2bSized<'a, Tag> {
    const MAX_BUFFER_SIZE: usize = Tag::CAP;
    fn get_size(&self) -> u16 {
        self.as_slice().len() as u16
    }
    fn get_buffer(&self) -> &'a [u8] {
        self.as_slice()
    }
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, UnmarshalError> {
        Self::new(bytes).ok_or(UnmarshalError::SIZE)
    }
}

/// Backwards-compatible trait for structured `Tpm2b<T>` buffers.
pub trait Tpm2bStruct<'a>: Sized {
    type StructType;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError>;
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError>;
}

impl<'a, T: Clone> Tpm2bStruct<'a> for Tpm2b<T> {
    type StructType = T;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        Ok(Self(val.clone()))
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        Ok(self.0.clone())
    }
}

pub trait Validate2bStruct {
    fn validate_to_struct(&self) -> Result<(), UnmarshalError> {
        Ok(())
    }
}

impl Validate2bStruct for TpmsAttest<'_> {}
impl Validate2bStruct for TpmsCreationData<'_> {}
impl Validate2bStruct for TpmsSensitiveCreate<'_> {}
impl Validate2bStruct for TpmtSensitive<'_> {}
impl Validate2bStruct for TpmsEccPoint<'_> {}
impl Validate2bStruct for TpmsNvPublic<'_> {}
impl Validate2bStruct for TpmsNvPublicExpAttr<'_> {}
impl Validate2bStruct for TpmtNvPublic2<'_> {
    fn validate_to_struct(&self) -> Result<(), UnmarshalError> {
        if self.handle_type != self.public_area.handle_type() {
            return Err(UnmarshalError::SELECTOR);
        }
        Ok(())
    }
}
impl Validate2bStruct for TpmsSetCapabilityData<'_> {}
impl Validate2bStruct for TpmtPublic<'_> {
    fn validate_to_struct(&self) -> Result<(), UnmarshalError> {
        if self.name_alg.is_none() {
            return Err(UnmarshalError::HASH);
        }
        Ok(())
    }
}

/// A length-prefixed (`u16`) buffer wrapping a structured TPM payload `T`.
///
/// For example a [`Tpm2bPublic`] wraps a [`TpmtPublic`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Tpm2b<T>(pub T);

impl<const N: usize, T: Marshal<MaxBuffer = [u8; N]>> Tpm2b<T> {
    /// Helper constant to access the capacity of a `Tpm2b` type. For example,
    /// [`Tpm2bPublic::CAP`] is equal to [`TpmtPublic::MAX_SIZE`].
    pub const CAP: usize = N;
    pub const MAX_BUFFER_SIZE: usize = N;

    pub const fn new(val: T) -> Self {
        Self(val)
    }

    pub fn from_struct(val: &T) -> Result<Self, UnmarshalError>
    where
        T: Clone,
    {
        Ok(Self(val.clone()))
    }

    pub fn to_struct(&self) -> Result<T, UnmarshalError>
    where
        T: Clone + Validate2bStruct,
    {
        self.0.validate_to_struct()?;
        Ok(self.0.clone())
    }

    pub fn get_size(&self) -> u16 {
        let mut dst = [0u8; N];
        self.0.marshal(&mut dst) as u16
    }

    const fn max_size() -> usize {
        u16::MAX_SIZE + N
    }

    fn marshal_helper<const M: usize>(&self, buf: &mut [u8; M]) -> usize {
        // This check ensures these unwrap()/slicing ops don't panic.
        const { assert!(M == Self::max_size()) };
        let (head, rest) = buf.split_first_chunk_mut::<2>().unwrap();
        let dst: &mut [u8; N] = (&mut rest[..N]).try_into().unwrap();

        // count <= N <= 0x7FFF < u16::MAX, so unwrap()/slicing ops don't panic.
        const { assert!(N <= 0x7FFF) };
        let len = self.0.marshal(dst);
        len + u16::try_from(len).unwrap().marshal(head)
    }
}

impl<'a, const N: usize, T: Marshal<MaxBuffer = [u8; N]> + Unmarshal<'a>> Tpm2b<T> {
    pub fn from_bytes(mut bytes: &'a [u8]) -> Result<Self, UnmarshalError> {
        if bytes.len() > Self::CAP {
            return Err(UnmarshalError::SIZE);
        }
        let t = T::unmarshal(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(UnmarshalError::SIZE);
        }
        Ok(Self(t))
    }
}

impl<'a, const N: usize, T: Marshal<MaxBuffer = [u8; N]> + Unmarshal<'a>> Unmarshal<'a>
    for Tpm2b<T>
{
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let len: usize = u16::unmarshal(src)?.into();
        if len == 0 {
            return Err(UnmarshalError::SIZE);
        }
        let start_len = src.len();
        let t = T::unmarshal(src)?;
        let consumed = start_len - src.len();
        if consumed != len || consumed > Self::CAP {
            return Err(UnmarshalError::SIZE);
        }
        Ok(Self(t))
    }
}

/// A length-prefixed (`u16`) byte slice buffer whose maximum capacity is
/// defined by a [`Tag`](limits::Tag).
///
/// For example, a [`Tpm2bDigest`] has a maximum length of
/// [`TpmiAlgHash::MAX_DIGEST_BYTES`], which is encoded via the
/// [`limits::Digest`] tag type.
pub struct Tpm2bSized<'a, Tag: limits::Tag> {
    buf: &'a [u8],
    tag: PhantomData<Tag>,
}

// We need these manual impls to avoid a trait bound on the `Tag`.
impl<Tag: limits::Tag> Clone for Tpm2bSized<'_, Tag> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<Tag: limits::Tag> Copy for Tpm2bSized<'_, Tag> {}
impl<Tag: limits::Tag> PartialEq for Tpm2bSized<'_, Tag> {
    fn eq(&self, other: &Self) -> bool {
        self.buf == other.buf
    }
}
impl<Tag: limits::Tag> Eq for Tpm2bSized<'_, Tag> {}
impl<Tag: limits::Tag> fmt::Debug for Tpm2bSized<'_, Tag> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Tpm2bSized").field(&self.buf).finish()
    }
}
impl<Tag: limits::Tag> Default for Tpm2bSized<'_, Tag> {
    fn default() -> Self {
        Self {
            buf: &[],
            tag: PhantomData,
        }
    }
}
impl<'a, Tag: limits::Tag> AsRef<[u8]> for Tpm2bSized<'a, Tag> {
    fn as_ref(&self) -> &'a [u8] {
        self.as_slice()
    }
}

impl<'a, Tag: limits::Tag> Tpm2bSized<'a, Tag> {
    /// Helper constant to access the capacity of a `Tpm2b` type. For example,
    /// [`Tpm2bDigest::CAP`] is equal to [`TpmiAlgHash::MAX_DIGEST_BYTES`].
    pub const CAP: usize = Tag::CAP;
    pub const MAX_BUFFER_SIZE: usize = Tag::CAP;

    pub const fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() > Self::CAP {
            return None;
        }
        Some(Self {
            buf,
            tag: PhantomData,
        })
    }

    pub fn from_bytes(buf: &'a [u8]) -> Result<Self, UnmarshalError> {
        Self::new(buf).ok_or(UnmarshalError::SIZE)
    }

    pub const fn as_slice(self) -> &'a [u8] {
        debug_assert!(self.buf.len() <= Self::CAP);
        if let Some((head, _)) = self.buf.split_at_checked(Self::CAP) {
            head
        } else {
            self.buf
        }
    }

    pub const fn get_buffer(&self) -> &'a [u8] {
        self.as_slice()
    }

    pub const fn get_size(&self) -> u16 {
        self.as_slice().len() as u16
    }

    const fn max_size() -> usize {
        u16::MAX_SIZE + Self::CAP
    }

    fn marshal_helper<const M: usize>(&self, buf: &mut [u8; M]) -> usize {
        // This check ensures these unwrap()/slicing ops don't panic.
        const { assert!(M == Self::max_size()) };
        let (head, rest) = buf.split_first_chunk_mut::<2>().unwrap();

        let src: &'a [u8] = self.as_slice();
        let len = src.len();

        // len <= CAP <= 0x7FFF < u16::MAX, so unwrap()/slicing ops don't panic.
        const { assert!(Self::CAP <= 0x7FFF) };
        let count = u16::try_from(len).unwrap().marshal(head);
        rest[..len].copy_from_slice(src);
        count + len
    }
}

impl<'a, Tag: limits::Tag> Unmarshal<'a> for Tpm2bSized<'a, Tag> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let len: usize = u16::unmarshal(src)?.into();
        if len > Self::CAP {
            return Err(UnmarshalError::SIZE);
        }
        let Some((buf, rest)) = src.split_at_checked(len) else {
            return Err(UnmarshalError::INSUFFICIENT);
        };
        *src = rest;
        Ok(Self {
            buf,
            tag: PhantomData,
        })
    }
}

/// Helper macro needed for [`Marshal`] implementations (as Rust doesn't yet
/// support enough const-generics functionality to make this impl generic).
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

// ---------------------------------------------------------------------------
// Tpm2bDigest
// ---------------------------------------------------------------------------
/// `TPM2B_DIGEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.2 (Table 87).
///
/// A sized buffer that holds digest values, HMAC keys, auth values, nonces, or seed values.
/// The size cannot exceed the largest digest produced by any hash algorithm implemented on the TPM.
#[doc(alias = "TPM2B_DIGEST")]
pub type Tpm2bDigest<'a> = Tpm2bSized<'a, limits::Digest>;
impl_marshal!(Tpm2bDigest<'_>);

/// `TPM2B_NONCE` type alias defined in TPM 2.0 Part 2: Structures, Section 10.4.6 (Table 79).
///
/// Type alias for `Tpm2bDigest` representing a nonce in authorization protocols.
#[doc(alias = "TPM2B_NONCE")]
pub type Tpm2bNonce<'a> = Tpm2bDigest<'a>;

/// `TPM2B_OPERAND` type alias defined in TPM 2.0 Part 2: Structures, Section 10.4.5 (Table 78).
///
/// Type alias for `Tpm2bDigest` representing an operand in cryptographic operations.
#[doc(alias = "TPM2B_OPERAND")]
pub type Tpm2bOperand<'a> = Tpm2bDigest<'a>;

/// `TPM2B_AUTH` type alias defined in TPM 2.0 Part 2: Structures, Section 10.4.7 (Table 80).
///
/// Type alias for `Tpm2bDigest` representing an authorization value.
#[doc(alias = "TPM2B_AUTH")]
pub type Tpm2bAuth<'a> = Tpm2bDigest<'a>;

// ---------------------------------------------------------------------------
// Tpm2bTimeout
// ---------------------------------------------------------------------------
/// `TPM2B_TIMEOUT` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.8 (Table 81).
///
/// An 8-byte buffer containing a TPM-specific value used to limit the lifetime of an authorization ticket.
#[doc(alias = "TPM2B_TIMEOUT")]
pub type Tpm2bTimeout<'a> = Tpm2bSized<'a, limits::Timeout>;
impl_marshal!(Tpm2bTimeout<'_>);

// ---------------------------------------------------------------------------
// Tpm2bData
// ---------------------------------------------------------------------------
/// `TPM2B_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.3 (Table 76).
///
/// A buffer holding data that may be associated with a digest or attestation (sized up to `sizeof(TPMT_HA)`).
#[doc(alias = "TPM2B_DATA")]
pub type Tpm2bData<'a> = Tpm2bSized<'a, limits::Data>;
impl_marshal!(Tpm2bData<'_>);

// ---------------------------------------------------------------------------
// Tpm2bEvent
// ---------------------------------------------------------------------------
/// `TPM2B_EVENT` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.9 (Table 82).
///
/// A sized buffer (up to 1024 bytes) holding event data passed to `TPM2_PCR_Event`.
#[doc(alias = "TPM2B_EVENT")]
pub type Tpm2bEvent<'a> = Tpm2bSized<'a, limits::Event>;
impl_marshal!(Tpm2bEvent<'_>);

// ---------------------------------------------------------------------------
// Tpm2bMaxBuffer
// ---------------------------------------------------------------------------
/// `TPM2B_MAX_BUFFER` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.10 (Table 83).
///
/// A sized buffer holding up to [`limits::MAX_2B_BUFFER_SIZE`] bytes, used for
/// bulk data transfer in hash, sequence, and encryption commands.
#[doc(alias = "TPM2B_MAX_BUFFER")]
pub type Tpm2bMaxBuffer<'a> = Tpm2bSized<'a, limits::MaxBuffer>;
impl_marshal!(Tpm2bMaxBuffer<'_>);

// ---------------------------------------------------------------------------
// Tpm2bMaxNvBuffer
// ---------------------------------------------------------------------------
/// `TPM2B_MAX_NV_BUFFER` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.11 (Table 84).
///
/// A sized buffer holding up to [`limits::MAX_NV_BUFFER_SIZE`] bytes, used for
/// NV index read and write operations.
#[doc(alias = "TPM2B_MAX_NV_BUFFER")]
pub type Tpm2bMaxNvBuffer<'a> = Tpm2bSized<'a, limits::MaxNvBuffer>;
impl_marshal!(Tpm2bMaxNvBuffer<'_>);

// ---------------------------------------------------------------------------
// Tpm2bIv
// ---------------------------------------------------------------------------
/// `TPM2B_IV` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.12 (Table 85).
///
/// A sized buffer holding a symmetric cipher initialization vector (up to `MAX_SYM_BLOCK_SIZE`, 16 bytes).
#[doc(alias = "TPM2B_IV")]
pub type Tpm2bIv<'a> = Tpm2bSized<'a, limits::Iv>;
impl_marshal!(Tpm2bIv<'_>);

// ---------------------------------------------------------------------------
// Tpm2bName
// ---------------------------------------------------------------------------
/// `TPM2B_NAME` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.3 (Table 86).
///
/// A buffer holding a TPM entity Name (`sizeof(TPMU_NAME)`).
/// For handles (like PCRs or sessions), this is a 4-byte handle value. For objects and NV indices,
/// this is a 2-byte hash algorithm ID followed by the hash digest of the public area.
#[doc(alias = "TPM2B_NAME")]
pub type Tpm2bName<'a> = Tpm2bSized<'a, limits::Name>;
impl_marshal!(Tpm2bName<'_>);

// ---------------------------------------------------------------------------
// Tpm2bAttest
// ---------------------------------------------------------------------------
/// `TPM2B_ATTEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.23 (Table 143).
///
/// A sized buffer wrapping a marshaled `TPMS_ATTEST` structure, signed by the TPM during attestation commands.
#[doc(alias = "TPM2B_ATTEST")]
pub type Tpm2bAttest<'a> = Tpm2b<TpmsAttest<'a>>;
impl_marshal!(Tpm2bAttest<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSetCapabilityData
// ---------------------------------------------------------------------------
/// `TPM2B_SET_CAPABILITY_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.6.4 (Table 130).
///
/// A sized buffer wrapping a `TPMS_SET_CAPABILITY_DATA` structure, used in `TPM2_SetCapability`.
#[doc(alias = "TPM2B_SET_CAPABILITY_DATA")]
pub type Tpm2bSetCapabilityData<'a> = Tpm2b<TpmsSetCapabilityData<'a>>;
impl_marshal!(Tpm2bSetCapabilityData<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSymKey
// ---------------------------------------------------------------------------
/// `TPM2B_SYM_KEY` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.5 (Table 152).
///
/// A sized buffer holding a symmetric key (up to `MAX_SYM_KEY_BYTES`, 32 bytes).
#[doc(alias = "TPM2B_SYM_KEY")]
pub type Tpm2bSymKey<'a> = Tpm2bSized<'a, limits::SymKey>;
impl_marshal!(Tpm2bSymKey<'_>);

// ---------------------------------------------------------------------------
// Tpm2bLabel
// ---------------------------------------------------------------------------
/// `TPM2B_LABEL` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.8 (Table 155).
///
/// A sized buffer holding a KDF label or context string (up to `LABEL_MAX_BUFFER`, 32 bytes).
#[doc(alias = "TPM2B_LABEL")]
pub type Tpm2bLabel<'a> = Tpm2bSized<'a, limits::Label>;
impl_marshal!(Tpm2bLabel<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSensitiveData
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.13 (Table 160).
///
/// A sized buffer holding sealed data or sensitive key material inside `TPMS_SENSITIVE_CREATE` or `TPMT_SENSITIVE`.
#[doc(alias = "TPM2B_SENSITIVE_DATA")]
pub type Tpm2bSensitiveData<'a> = Tpm2bSized<'a, limits::SensitiveData>;
impl_marshal!(Tpm2bSensitiveData<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSensitiveCreate
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE_CREATE` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.14 (Table 162).
///
/// A sized buffer wrapping `TPMS_SENSITIVE_CREATE`, containing the user authorization value and sensitive data
/// passed to `TPM2_Create` or `TPM2_CreatePrimary`.
#[doc(alias = "TPM2B_SENSITIVE_CREATE")]
pub type Tpm2bSensitiveCreate<'a> = Tpm2b<TpmsSensitiveCreate<'a>>;
impl_marshal!(Tpm2bSensitiveCreate<'_>);

// ---------------------------------------------------------------------------
// Tpm2bPublicKeyRsa
// ---------------------------------------------------------------------------
/// `TPM2B_PUBLIC_KEY_RSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.4.5 (Table 184).
///
/// A sized buffer holding the modulus of an RSA public key, up to
/// [`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`] bytes.
#[doc(alias = "TPM2B_PUBLIC_KEY_RSA")]
pub type Tpm2bPublicKeyRsa<'a> = Tpm2bSized<'a, limits::PublicKeyRsa>;
impl_marshal!(Tpm2bPublicKeyRsa<'_>);

// ---------------------------------------------------------------------------
// Tpm2bPrivateKeyRsa
// ---------------------------------------------------------------------------
/// `TPM2B_PRIVATE_KEY_RSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.4.6 (Table 185).
///
/// A sized buffer holding an RSA private prime factor (P or Q) or CRT components, up to
/// [`TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES`] bytes.
#[doc(alias = "TPM2B_PRIVATE_KEY_RSA")]
pub type Tpm2bPrivateKeyRsa<'a> = Tpm2bSized<'a, limits::PrivateKeyRsa>;
impl_marshal!(Tpm2bPrivateKeyRsa<'_>);

// ---------------------------------------------------------------------------
// Tpm2bEccParameter
// ---------------------------------------------------------------------------
/// `TPM2B_ECC_PARAMETER` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.5.1 (Table 188).
///
/// A sized buffer holding an ECC curve coordinate (X or Y) or private scalar (up to `MAX_ECC_KEY_BYTES`, 128 bytes).
#[doc(alias = "TPM2B_ECC_PARAMETER")]
pub type Tpm2bEccParameter<'a> = Tpm2bSized<'a, limits::EccParameter>;
impl_marshal!(Tpm2bEccParameter<'_>);

// ---------------------------------------------------------------------------
// Tpm2bEccPoint
// ---------------------------------------------------------------------------
/// `TPM2B_ECC_POINT` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.5.3 (Table 190).
///
/// A sized buffer wrapping `TPMS_ECC_POINT` (X and Y coordinates), used in ECC commands such as `TPM2_ECDH_ZGen` and `TPM2_Commit`.
#[doc(alias = "TPM2B_ECC_POINT")]
pub type Tpm2bEccPoint<'a> = Tpm2b<TpmsEccPoint<'a>>;
impl_marshal!(Tpm2bEccPoint<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSignatureEddsa
// ---------------------------------------------------------------------------
/// `TPM2B_SIGNATURE_EDDSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.3.2 (Table 198).
///
/// A sized buffer holding an EdDSA signature (up to `2 * MAX_ECC_KEY_BYTES`, 256 bytes).
#[doc(alias = "TPM2B_SIGNATURE_EDDSA")]
pub type Tpm2bSignatureEddsa<'a> = Tpm2bSized<'a, limits::SignatureEddsa>;
impl_marshal!(Tpm2bSignatureEddsa<'_>);

// ---------------------------------------------------------------------------
// Tpm2bEncryptedSecret
// ---------------------------------------------------------------------------
/// `TPM2B_ENCRYPTED_SECRET` structure defined in TPM 2.0 Part 2: Structures, Section 11.4 (Table 202).
///
/// A sized buffer holding an encrypted seed value (`sizeof(TPMU_ENCRYPTED_SECRET)`) used in
/// `TPM2_Import`, `TPM2_ActivateCredential`, and `TPM2_StartAuthSession`.
#[doc(alias = "TPM2B_ENCRYPTED_SECRET")]
pub type Tpm2bEncryptedSecret<'a> = Tpm2bSized<'a, limits::EncryptedSecret>;
impl_marshal!(Tpm2bEncryptedSecret<'_>);

// ---------------------------------------------------------------------------
// Tpm2bPublic
// ---------------------------------------------------------------------------
/// `TPM2B_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.4 (Table 212).
///
/// A sized buffer wrapping `TPMT_PUBLIC`, defining the public area of a TPM object (type, name algorithm,
/// attributes, policy, parameters, and unique identifier).
#[doc(alias = "TPM2B_PUBLIC")]
pub type Tpm2bPublic<'a> = Tpm2b<TpmtPublic<'a>>;
impl_marshal!(Tpm2bPublic<'_>);

impl<'a> Tpm2bPublic<'a> {
    /// Extracts the [`TpmtPublic`] structure, permitting `name_alg == TPM_ALG_NULL` (`None`).
    pub fn to_struct_nullable(&self) -> Result<TpmtPublic<'a>, UnmarshalError> {
        Ok(self.0)
    }

    /// Unmarshals a `TPM2B_PUBLIC` structure, optionally allowing `name_alg == TPM_ALG_NULL` (`None`).
    pub fn unmarshal_with_flag(
        src: &mut &'a [u8],
        allow_null_name_alg: bool,
    ) -> Result<Self, UnmarshalError> {
        let len: usize = u16::unmarshal(src)?.into();
        if len == 0 {
            return Err(UnmarshalError::SIZE);
        }
        let start_len = src.len();
        let t = TpmtPublic::unmarshal_with_flag(src, allow_null_name_alg)?;
        let consumed = start_len - src.len();
        if consumed != len || consumed > Self::CAP {
            return Err(UnmarshalError::SIZE);
        }
        Ok(Self(t))
    }

    /// Unmarshals a `TPM2B_PUBLIC+` structure, permitting `name_alg == TPM_ALG_NULL` (`None`).
    pub fn unmarshal_nullable(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Self::unmarshal_with_flag(src, true)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bTemplate
// ---------------------------------------------------------------------------
/// `TPM2B_TEMPLATE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.4 (Table 213).
///
/// A sized buffer holding a marshaled `TPMT_PUBLIC` object template used in `TPM2_CreateLoaded`.
#[doc(alias = "TPM2B_TEMPLATE")]
pub type Tpm2bTemplate<'a> = Tpm2bSized<'a, limits::Template>;
impl_marshal!(Tpm2bTemplate<'_>);

impl<'a> Tpm2bTemplate<'a> {
    /// Marshals a `TpmtPublic` into caller buffer `buf` and returns a `Tpm2bTemplate<'a>`.
    pub fn from_struct_in(
        val: &TpmtPublic<'_>,
        buf: &'a mut [u8; TpmtPublic::MAX_SIZE],
    ) -> Result<Self, UnmarshalError> {
        let len = val.marshal(buf);
        Self::from_bytes(&buf[..len])
    }

    /// Marshals a derivation template (`TpmtPublic` parameters + `TpmsDerive`) into `buf` and returns a `Tpm2bTemplate<'a>`.
    pub fn from_derive_template_in(
        pub_area: &TpmtPublic<'_>,
        derive: &TpmsDerive<'_>,
        buf: &'a mut [u8; TpmtPublic::MAX_SIZE],
    ) -> Result<Self, UnmarshalError> {
        let mut count = marshal_helper(&pub_area.parms_and_id.algorithm(), buf, 0);
        count = marshal_helper(&pub_area.name_alg, buf, count);
        count = marshal_helper(&pub_area.object_attributes, buf, count);
        count = marshal_helper(&pub_area.auth_policy, buf, count);
        count = match &pub_area.parms_and_id {
            PublicParmsAndId::KeyedHash(parms, _) => marshal_helper(parms, buf, count),
            PublicParmsAndId::Sym(parms, _) => marshal_helper(parms, buf, count),
            PublicParmsAndId::Rsa(parms, _) => marshal_helper(parms, buf, count),
            PublicParmsAndId::Ecc(parms, _) => marshal_helper(parms, buf, count),
            PublicParmsAndId::Mldsa(parms, _) => marshal_helper(parms, buf, count),
            PublicParmsAndId::HashMldsa(parms, _) => marshal_helper(parms, buf, count),
            PublicParmsAndId::Mlkem(parms, _) => marshal_helper(parms, buf, count),
        };
        count = marshal_helper(derive, buf, count);
        Self::from_bytes(&buf[..count])
    }

    /// Unmarshals the template buffer into a `TpmtPublic` and optional `TpmsDerive` (`UnmarshalToPublic`
    /// in the TPM 2.0 reference implementation, Part 2 Section 12.2.6 (Table 213)).
    pub fn unmarshal_to_public(
        &self,
        derivation: bool,
    ) -> Result<(TpmtPublic<'a>, Option<TpmsDerive<'a>>), UnmarshalError> {
        let mut src = self.as_slice();
        let res = TpmtPublic::unmarshal_for_template(&mut src, derivation)?;
        if !src.is_empty() {
            return Err(UnmarshalError::SIZE);
        }
        Ok(res)
    }

    /// Unmarshals the template buffer into a standard `TpmtPublic`.
    pub fn to_struct(&self) -> Result<TpmtPublic<'a>, UnmarshalError> {
        let mut src = self.as_slice();
        let res = TpmtPublic::unmarshal(&mut src)?;
        if !src.is_empty() {
            return Err(UnmarshalError::SIZE);
        }
        Ok(res)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
impl Tpm2bTemplate<'static> {
    pub fn from_struct(val: &TpmtPublic<'_>) -> Result<Self, UnmarshalError> {
        let buf = std::boxed::Box::leak(std::boxed::Box::new([0u8; TpmtPublic::MAX_SIZE]));
        Self::from_struct_in(val, buf)
    }

    pub fn from_derive_template(
        pub_area: &TpmtPublic<'_>,
        derive: &TpmsDerive<'_>,
    ) -> Result<Self, UnmarshalError> {
        let buf = std::boxed::Box::leak(std::boxed::Box::new([0u8; TpmtPublic::MAX_SIZE]));
        Self::from_derive_template_in(pub_area, derive, buf)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bSensitive
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 217).
///
/// A sized buffer wrapping `TPMT_SENSITIVE`, containing the plaintext sensitive area of an object
/// (used in `TPM2_LoadExternal` and `TPM2_Import`).
#[doc(alias = "TPM2B_SENSITIVE")]
pub type Tpm2bSensitive<'a> = Tpm2b<TpmtSensitive<'a>>;
impl_marshal!(Tpm2bSensitive<'_>);

// Implement Marshal/Unmarshal for Option<Tpm2bSensitive<'a>> to support
// public-only keys in TPM2_LoadExternal (which use an empty buffer).
impl Marshal for Option<Tpm2bSensitive<'_>> {
    const MAX_SIZE: usize = Tpm2bSensitive::MAX_SIZE;
    type MaxBuffer = [u8; Tpm2bSensitive::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(val) => val.marshal(dst),
            None => 0u16.marshal(dst.first_chunk_mut::<2>().unwrap()),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<Tpm2bSensitive<'a>> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let start_slice = *src;
        let size = u16::unmarshal(src)?;
        if size == 0 {
            return Ok(None);
        }
        *src = start_slice;
        Tpm2bSensitive::unmarshal(src).map(Some)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bPrivate
// ---------------------------------------------------------------------------
/// `TPM2B_PRIVATE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 218).
///
/// A sized buffer holding the encrypted sensitive area (`TPMT_SENSITIVE`) of a TPM object, encrypted under
/// its parent object's key.
#[doc(alias = "TPM2B_PRIVATE")]
pub type Tpm2bPrivate<'a> = Tpm2bSized<'a, limits::Private>;
impl_marshal!(Tpm2bPrivate<'_>);

// ---------------------------------------------------------------------------
// Tpm2bIdObject
// ---------------------------------------------------------------------------
/// `TPM2B_ID_OBJECT` structure defined in TPM 2.0 Part 2: Structures, Section 12.3 (Table 221).
///
/// A sized buffer wrapping `TPMS_ID_OBJECT`, containing an encrypted credential payload used in `TPM2_ActivateCredential`.
#[doc(alias = "TPM2B_ID_OBJECT")]
pub type Tpm2bIdObject<'a> = Tpm2bSized<'a, limits::IdObject>;
impl_marshal!(Tpm2bIdObject<'_>);

impl<'a> Tpm2bIdObject<'a> {
    pub fn to_struct(&self) -> Result<TpmsIdObject<'a>, UnmarshalError> {
        let mut src = self.as_slice();
        let res = TpmsIdObject::unmarshal(&mut src)?;
        if !src.is_empty() {
            return Err(UnmarshalError::SIZE);
        }
        Ok(res)
    }

    pub fn from_struct_in(
        val: &TpmsIdObject<'_>,
        buf: &'a mut [u8; TpmsIdObject::MAX_SIZE],
    ) -> Result<Self, UnmarshalError> {
        if val.enc_identity_len > Tpm2bDigest::MAX_SIZE {
            return Err(UnmarshalError::SIZE);
        }
        let len = val.marshal(buf);
        Self::from_bytes(&buf[..len])
    }
}

#[cfg(test)]
impl Tpm2bIdObject<'static> {
    pub fn from_struct(val: &TpmsIdObject<'_>) -> Result<Self, UnmarshalError> {
        let buf = std::boxed::Box::leak(std::boxed::Box::new([0u8; TpmsIdObject::MAX_SIZE]));
        Self::from_struct_in(val, buf)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bNvPublic
// ---------------------------------------------------------------------------
/// `TPM2B_NV_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 13.2 (Table 228).
///
/// A sized buffer wrapping `TPMS_NV_PUBLIC`, defining the public parameters of an NV Index
/// (index handle, name hash algorithm, attributes, policy, and data size).
#[doc(alias = "TPM2B_NV_PUBLIC")]
pub type Tpm2bNvPublic<'a> = Tpm2b<TpmsNvPublic<'a>>;
impl_marshal!(Tpm2bNvPublic<'_>);

// ---------------------------------------------------------------------------
// Tpm2bContextSensitive
// ---------------------------------------------------------------------------
/// `TPM2B_CONTEXT_SENSITIVE` structure defined in TPM 2.0 Part 2: Structures, Section 14.3 (Table 232).
///
/// A sized buffer holding the encrypted sensitive portion of a saved object or session context.
#[doc(alias = "TPM2B_CONTEXT_SENSITIVE")]
pub type Tpm2bContextSensitive<'a> = Tpm2bSized<'a, limits::ContextSensitive>;
impl_marshal!(Tpm2bContextSensitive<'_>);

// ---------------------------------------------------------------------------
// Tpm2bContextData
// ---------------------------------------------------------------------------
/// `TPM2B_CONTEXT_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 14.3 (Table 235).
///
/// A sized buffer holding integrity values and encrypted data for a saved context
/// in `TPM2_ContextSave` and `TPM2_ContextLoad`.
#[doc(alias = "TPM2B_CONTEXT_DATA")]
pub type Tpm2bContextData<'a> = Tpm2bSized<'a, limits::Context>;
impl_marshal!(Tpm2bContextData<'_>);

impl<'a> Tpm2bContextData<'a> {
    pub fn to_struct(&self) -> Result<TpmsContextData<'a>, UnmarshalError> {
        let mut src = self.as_slice();
        let res = TpmsContextData::unmarshal(&mut src)?;
        if !src.is_empty() {
            return Err(UnmarshalError::SIZE);
        }
        Ok(res)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bCreationData
// ---------------------------------------------------------------------------
/// `TPM2B_CREATION_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 15.1 (Table 239).
///
/// A sized buffer wrapping `TPMS_CREATION_DATA`, generated by the TPM upon object creation (`TPM2_Create`, `TPM2_CreatePrimary`)
/// to document the environment in which the object was created.
#[doc(alias = "TPM2B_CREATION_DATA")]
pub type Tpm2bCreationData<'a> = Tpm2b<TpmsCreationData<'a>>;
impl_marshal!(Tpm2bCreationData<'_>);

// ---------------------------------------------------------------------------
// Extra HEAD Tpm2b Types
// ---------------------------------------------------------------------------
/// `TPM2B_VENDOR_PROPERTY` structure.
#[doc(alias = "TPM2B_VENDOR_PROPERTY")]
pub type Tpm2bVendorProperty<'a> = Tpm2bSized<'a, limits::VendorProperty>;
impl_marshal!(Tpm2bVendorProperty<'_>);

/// `TPM2B_SHARED_SECRET` structure.
#[doc(alias = "TPM2B_SHARED_SECRET")]
pub type Tpm2bSharedSecret<'a> = Tpm2bSized<'a, limits::SharedSecret>;
impl_marshal!(Tpm2bSharedSecret<'_>);

/// `TPM2B_KEM_CIPHERTEXT` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.11.
///
/// A sized buffer holding the ciphertext from a Key Encapsulation Mechanism
/// (`sizeof(TPMU_KEM_CIPHERTEXT)` = `max(sizeof(TPMS_ECC_POINT), MAX_MLKEM_CT_SIZE)` = 1568 bytes).
#[doc(alias = "TPM2B_KEM_CIPHERTEXT")]
pub type Tpm2bKemCiphertext<'a> = Tpm2bSized<'a, limits::KemCiphertext>;
impl_marshal!(Tpm2bKemCiphertext<'_>);

/// `TPM2B_SIGNATURE_CTX` structure defined in TPM 2.0 Part 2: Structures, Section 11.3.6.
///
/// A sized buffer containing additional signature context (`sizeof(TPMU_SIGNATURE_CTX)` = 255 bytes).
#[doc(alias = "TPM2B_SIGNATURE_CTX")]
pub type Tpm2bSignatureCtx<'a> = Tpm2bSized<'a, limits::SignatureCtx>;
impl_marshal!(Tpm2bSignatureCtx<'_>);

/// `TPM2B_SIGNATURE_HINT` structure.
#[doc(alias = "TPM2B_SIGNATURE_HINT")]
pub type Tpm2bSignatureHint<'a> = Tpm2bSized<'a, limits::SignatureHint>;
impl_marshal!(Tpm2bSignatureHint<'_>);

/// `TPM2B_NV_PUBLIC_2` structure defined in TPM 2.0 Part 2: Structures, Section 13.7 (Table 232).
///
/// A sized buffer wrapping [`TpmtNvPublic2`], defining the generalized public area of an NV Index.
#[doc(alias = "TPM2B_NV_PUBLIC_2")]
pub type Tpm2bNvPublic2<'a> = Tpm2b<TpmtNvPublic2<'a>>;
impl_marshal!(Tpm2bNvPublic2<'_>);

/// `TPM2B_PUBLIC_KEY_MLKEM` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.5.2.
///
/// A sized buffer holding an ML-KEM encapsulation (public) key (`MAX_MLKEM_PUB_SIZE` = 1568 bytes).
#[doc(alias = "TPM2B_PUBLIC_KEY_MLKEM")]
pub type Tpm2bPublicKeyMlkem<'a> = Tpm2bSized<'a, limits::PublicKeyMlkem>;
impl_marshal!(Tpm2bPublicKeyMlkem<'_>);

/// `TPM2B_PRIVATE_KEY_MLKEM` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.5.3.
///
/// A sized buffer holding an ML-KEM decapsulation seed (`d || z`, `MAX_MLKEM_PRIV_SIZE` = 64 bytes).
#[doc(alias = "TPM2B_PRIVATE_KEY_MLKEM")]
pub type Tpm2bPrivateKeyMlkem<'a> = Tpm2bSized<'a, limits::PrivateKeyMlkem>;
impl_marshal!(Tpm2bPrivateKeyMlkem<'_>);

/// `TPM2B_PUBLIC_KEY_MLDSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.6.3.
///
/// A sized buffer holding an ML-DSA verification (public) key (`MAX_MLDSA_PUB_SIZE` = 2592 bytes).
#[doc(alias = "TPM2B_PUBLIC_KEY_MLDSA")]
pub type Tpm2bPublicKeyMldsa<'a> = Tpm2bSized<'a, limits::PublicKeyMldsa>;
impl_marshal!(Tpm2bPublicKeyMldsa<'_>);

/// `TPM2B_PRIVATE_KEY_MLDSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.6.4.
///
/// A sized buffer holding an ML-DSA signing seed (`xi`, `MAX_MLDSA_PRIV_SIZE` = 32 bytes).
#[doc(alias = "TPM2B_PRIVATE_KEY_MLDSA")]
pub type Tpm2bPrivateKeyMldsa<'a> = Tpm2bSized<'a, limits::PrivateKeyMldsa>;
impl_marshal!(Tpm2bPrivateKeyMldsa<'_>);

/// `TPM2B_SIGNATURE_MLDSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.6.5.
///
/// A sized buffer holding an ML-DSA signature (`MAX_MLDSA_SIG_SIZE` = 4627 bytes).
#[doc(alias = "TPM2B_SIGNATURE_MLDSA")]
pub type Tpm2bSignatureMldsa<'a> = Tpm2bSized<'a, limits::SignatureMldsa>;
impl_marshal!(Tpm2bSignatureMldsa<'_>);

/// Re-exports of [`crate::limits`] tag types for backwards compatibility.
pub mod tags {
    pub use crate::limits::{*, Tag as Tpm2bTag};
}
