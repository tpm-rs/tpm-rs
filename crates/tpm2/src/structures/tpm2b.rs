use core::{fmt, marker::PhantomData};

use crate::{errors::UnmarshalError, *};

/// A length-prefixed (`u16`) buffer wrapping a structured TPM payload `T`.
///
/// For example a [`Tpm2bPublic`] wraps a [`TpmtPublic`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Tpm2b<T>(pub T);

impl<const N: usize, T: Marshal<MaxBuffer = [u8; N]>> Tpm2b<T> {
    /// Helper constant to access the capacity of a `Tpm2b` type. For example,
    /// [`Tpm2bPublic::CAP`] is equal to [`TpmtPublic::MAX_SIZE`].
    pub const CAP: usize = N;

    const fn max_size() -> usize {
        2 + N
    }

    fn marshal_helper<const M: usize>(&self, buf: &mut [u8; M]) -> usize {
        // This check ensures these unwrap()/slicing ops don't panic.
        const { assert!(M == Self::max_size()) };
        let (head, rest) = buf.split_first_chunk_mut::<2>().unwrap();
        let dst: &mut [u8; N] = rest.try_into().unwrap();

        // count <= N <= 0x7FFF < u16::MAX, so unwrap()/slicing ops don't panic.
        const { assert!(N <= 0x7FFF) };
        let len = self.0.marshal(dst);
        len + u16::try_from(len).unwrap().marshal(head)
    }
}

impl<'a, T: Unmarshal<'a>> Unmarshal<'a> for Tpm2b<T> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let len: usize = u16::unmarshal(src)?.into();
        let mut buf: &'a [u8];
        (buf, *src) = src.split_at_checked(len).ok_or(UnmarshalError)?;

        let t = T::unmarshal(&mut buf)?;
        match buf.len() {
            0 => Ok(Self(t)),
            _ => Err(UnmarshalError),
        }
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
        Self::new(&[]).unwrap()
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

    pub const fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() > Self::CAP {
            return None;
        }
        Some(Self {
            buf,
            tag: PhantomData,
        })
    }

    pub const fn as_slice(self) -> &'a [u8] {
        debug_assert!(self.buf.len() <= Self::CAP);
        if let Some((head, _)) = self.buf.split_at_checked(Self::CAP) {
            head
        } else {
            self.buf
        }
    }

    const fn max_size() -> usize {
        2 + Self::CAP
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
        let buf: &'a [u8];
        (buf, *src) = src.split_at_checked(len).ok_or(UnmarshalError)?;

        Self::new(buf).ok_or(UnmarshalError)
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

/// `TPM2B_AUTH` type alias defined in TPM 2.0 Part 2: Structures, Section 10.4.4 (Table 77).
///
/// Type alias for `Tpm2bDigest` representing an authorization value.
#[doc(alias = "TPM2B_AUTH")]
pub type Tpm2bAuth<'a> = Tpm2bDigest<'a>;

// ---------------------------------------------------------------------------
// Tpm2bTimeout
// ---------------------------------------------------------------------------
/// `TPM2B_TIMEOUT` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.10 (Table 95).
///
/// A sized buffer (up to 8 bytes) used to provide the timeout value for an authorization ticket
/// (such as tickets created by `TPM2_PolicySigned` or `TPM2_PolicySecret`).
#[doc(alias = "TPM2B_TIMEOUT")]
pub type Tpm2bTimeout<'a> = Tpm2bSized<'a, limits::Timeout>;
impl_marshal!(Tpm2bTimeout<'_>);

// ---------------------------------------------------------------------------
// Tpm2bData
// ---------------------------------------------------------------------------
/// `TPM2B_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.3 (Table 88).
///
/// A sized buffer used for general data parameters (such as key parameters or nonce values)
/// up to the size of a digest.
#[doc(alias = "TPM2B_DATA")]
pub type Tpm2bData<'a> = Tpm2bSized<'a, limits::Data>;
impl_marshal!(Tpm2bData<'_>);

// ---------------------------------------------------------------------------
// Tpm2bEvent
// ---------------------------------------------------------------------------
/// `TPM2B_EVENT` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.7 (Table 92).
///
/// A sized buffer holding event data passed into `TPM2_PCR_Event` or `TPM2_EventSequenceComplete`.
#[doc(alias = "TPM2B_EVENT")]
pub type Tpm2bEvent<'a> = Tpm2bSized<'a, limits::Event>;
impl_marshal!(Tpm2bEvent<'_>);

// ---------------------------------------------------------------------------
// Tpm2bMaxBuffer
// ---------------------------------------------------------------------------
/// `TPM2B_MAX_BUFFER` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.8 (Table 93).
///
/// A sized buffer holding up to [`limits::MAX_2B_BUFFER_SIZE`] bytes, used for
/// bulk data transfer in hash, sequence, and encryption commands.
#[doc(alias = "TPM2B_MAX_BUFFER")]
pub type Tpm2bMaxBuffer<'a> = Tpm2bSized<'a, limits::MaxBuffer>;
impl_marshal!(Tpm2bMaxBuffer<'_>);

// ---------------------------------------------------------------------------
// Tpm2bMaxNvBuffer
// ---------------------------------------------------------------------------
/// `TPM2B_MAX_NV_BUFFER` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.9 (Table 94).
///
/// A sized buffer holding up to [`limits::MAX_NV_BUFFER_SIZE`] bytes, used for
/// NV index read and write operations.
#[doc(alias = "TPM2B_MAX_NV_BUFFER")]
pub type Tpm2bMaxNvBuffer<'a> = Tpm2bSized<'a, limits::MaxNvBuffer>;
impl_marshal!(Tpm2bMaxNvBuffer<'_>);

// ---------------------------------------------------------------------------
// Tpm2bIv
// ---------------------------------------------------------------------------
/// `TPM2B_IV` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.11 (Table 96).
///
/// A sized buffer holding an initialization vector (IV) for symmetric block ciphers, sized to the
/// largest block size of any implemented symmetric cipher on the TPM.
#[doc(alias = "TPM2B_IV")]
pub type Tpm2bIv<'a> = Tpm2bSized<'a, limits::Iv>;
impl_marshal!(Tpm2bIv<'_>);

// ---------------------------------------------------------------------------
// Tpm2bName
// ---------------------------------------------------------------------------
/// `TPM2B_NAME` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.12 (Table 99).
///
/// A sized buffer holding a TPM entity Name (which consists of a 2-byte hash algorithm ID followed
/// by the hash digest of the entity's public area, or a 4-byte handle for permanent entities).
#[doc(alias = "TPM2B_NAME")]
pub type Tpm2bName<'a> = Tpm2bSized<'a, limits::Name>;
impl_marshal!(Tpm2bName<'_>);

// ---------------------------------------------------------------------------
// Tpm2bAttest
// ---------------------------------------------------------------------------
/// `TPM2B_ATTEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.24 (Table 143).
///
/// A sized buffer holding a marshaled `TPMS_ATTEST` structure. This buffer is generated and signed
/// by the TPM during attestation commands (`TPM2_Certify`, `TPM2_Quote`, `TPM2_GetTime`, etc.).
#[doc(alias = "TPM2B_ATTEST")]
pub type Tpm2bAttest<'a> = Tpm2b<TpmsAttest<'a>>;
impl_marshal!(Tpm2bAttest<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSymKey
// ---------------------------------------------------------------------------
/// `TPM2B_SYM_KEY` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.6 (Table 153).
///
/// A sized buffer holding a symmetric encryption key value (up to `TPM2_MAX_SYM_KEY_BYTES`).
#[doc(alias = "TPM2B_SYM_KEY")]
pub type Tpm2bSymKey<'a> = Tpm2bSized<'a, limits::SymKey>;
impl_marshal!(Tpm2bSymKey<'_>);

// ---------------------------------------------------------------------------
// Tpm2bLabel
// ---------------------------------------------------------------------------
/// `TPM2B_LABEL` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.8 (Table 155).
///
/// A sized buffer holding a label or context string used in key derivation functions (KDF)
/// or protocol parameter generation.
#[doc(alias = "TPM2B_LABEL")]
pub type Tpm2bLabel<'a> = Tpm2bSized<'a, limits::Label>;
impl_marshal!(Tpm2bLabel<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSensitiveData
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.17 (Table 160).
///
/// A sized buffer holding sensitive data (such as a symmetric key or private data) for object creation
/// or unsealing operations.
#[doc(alias = "TPM2B_SENSITIVE_DATA")]
pub type Tpm2bSensitiveData<'a> = Tpm2bSized<'a, limits::SensitiveData>;
impl_marshal!(Tpm2bSensitiveData<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSensitiveCreate
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE_CREATE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.2 (Table 161).
///
/// A sized buffer wrapping `TPMS_SENSITIVE_CREATE`, containing the user authorization value and sensitive data
/// passed to `TPM2_Create` or `TPM2_CreatePrimary`.
#[doc(alias = "TPM2B_SENSITIVE_CREATE")]
pub type Tpm2bSensitiveCreate<'a> = Tpm2b<TpmsSensitiveCreate<'a>>;
impl_marshal!(Tpm2bSensitiveCreate<'_>);

// ---------------------------------------------------------------------------
// Tpm2bPublicKeyRsa
// ---------------------------------------------------------------------------
/// `TPM2B_PUBLIC_KEY_RSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.1.5 (Table 183).
///
/// A sized buffer holding the modulus of an RSA public key, up to
/// [`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`] bytes.
#[doc(alias = "TPM2B_PUBLIC_KEY_RSA")]
pub type Tpm2bPublicKeyRsa<'a> = Tpm2bSized<'a, limits::PublicKeyRsa>;
impl_marshal!(Tpm2bPublicKeyRsa<'_>);

// ---------------------------------------------------------------------------
// Tpm2bPrivateKeyRsa
// ---------------------------------------------------------------------------
/// `TPM2B_PRIVATE_KEY_RSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.1.6 (Table 187).
///
/// A sized buffer holding an RSA private prime factor (P or Q), up to
/// [`TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES`] bytes.
#[doc(alias = "TPM2B_PRIVATE_KEY_RSA")]
pub type Tpm2bPrivateKeyRsa<'a> = Tpm2bSized<'a, limits::PrivateKeyRsa>;
impl_marshal!(Tpm2bPrivateKeyRsa<'_>);

// ---------------------------------------------------------------------------
// Tpm2bEccParameter
// ---------------------------------------------------------------------------
/// `TPM2B_ECC_PARAMETER` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.1 (Table 188).
///
/// A sized buffer holding a single ECC coordinate or parameter value (X or Y coordinate).
#[doc(alias = "TPM2B_ECC_PARAMETER")]
pub type Tpm2bEccParameter<'a> = Tpm2bSized<'a, limits::EccParameter>;
impl_marshal!(Tpm2bEccParameter<'_>);

// ---------------------------------------------------------------------------
// Tpm2bEccPoint
// ---------------------------------------------------------------------------
/// `TPM2B_ECC_POINT` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.2 (Table 190).
///
/// A sized buffer wrapping a `TPMS_ECC_POINT` structure, containing affine X and Y coordinates for an ECC point.
#[doc(alias = "TPM2B_ECC_POINT")]
pub type Tpm2bEccPoint<'a> = Tpm2b<TpmsEccPoint<'a>>;
impl_marshal!(Tpm2bEccPoint<'_>);

// ---------------------------------------------------------------------------
// Tpm2bEncryptedSecret
// ---------------------------------------------------------------------------
/// `TPM2B_ENCRYPTED_SECRET` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.4 (Table 197).
///
/// A sized buffer holding an encrypted secret value used for salted auth sessions in `TPM2_StartAuthSession`
/// or key duplication (`TPM2_Duplicate`).
#[doc(alias = "TPM2B_ENCRYPTED_SECRET")]
pub type Tpm2bEncryptedSecret<'a> = Tpm2bSized<'a, limits::EncryptedSecret>;
impl_marshal!(Tpm2bEncryptedSecret<'_>);

// ---------------------------------------------------------------------------
// Tpm2bPublic
// ---------------------------------------------------------------------------
/// `TPM2B_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.4 (Table 212).
///
/// A sized buffer wrapping `TPMT_PUBLIC`, defining the public area of a TPM object (key type, attributes,
/// auth policy, parameters, and public key data).
#[doc(alias = "TPM2B_PUBLIC")]
pub type Tpm2bPublic<'a> = Tpm2b<TpmtPublic<'a>>;
impl_marshal!(Tpm2bPublic<'_>);

// ---------------------------------------------------------------------------
// Tpm2bSensitive
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 217).
///
/// A sized buffer wrapping `TPMT_SENSITIVE`, defining the sensitive/private area of an object
/// (containing the authorization value, seed, and private key material).
#[doc(alias = "TPM2B_SENSITIVE")]
pub type Tpm2bSensitive<'a> = Tpm2b<TpmtSensitive<'a>>;
impl_marshal!(Tpm2bSensitive<'_>);

// Implement Marshal/Unmarshal for Option<Tpm2bSensitive<'a>> to support
// public-only keys in TPM2_LoadExternal (which use an empty buffer).
impl Marshal for Option<Tpm2bSensitive<'_>> {
    const MAX_SIZE: usize = Tpm2bSensitive::MAX_SIZE;
    type MaxBuffer = <Tpm2bSensitive<'static> as Marshal>::MaxBuffer;

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(s) => s.marshal(dst),
            None => 0u16.marshal(dst.first_chunk_mut().unwrap()),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<Tpm2bSensitive<'a>> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        if let Some(rest) = src.strip_prefix(&[0, 0]) {
            *src = rest;
            return Ok(None);
        }
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
// Tpm2bContextData
// ---------------------------------------------------------------------------
/// `TPM2B_CONTEXT_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 14.3 (Table 235).
///
/// A sized buffer wrapping `TPMS_CONTEXT_DATA`, holding integrity values and encrypted data for a saved context
/// in `TPM2_ContextSave` and `TPM2_ContextLoad`.
#[doc(alias = "TPM2B_CONTEXT_DATA")]
pub type Tpm2bContextData<'a> = Tpm2bSized<'a, limits::Context>;
impl_marshal!(Tpm2bContextData<'_>);

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
