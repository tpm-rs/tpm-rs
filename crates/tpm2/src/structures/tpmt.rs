use crate::{
    errors::UnmarshalError,
    marshal::{marshal_helper, max},
    *,
};
use TpmiAlgHash::*;

/// `TPMT_HA` structure defined in TPM 2.0 Part 2: Structures, Section 10.3.3 (Table 86).
///
/// A tagged hash-agile structure containing a hash algorithm identifier (`TPMI_ALG_HASH`) and the corresponding hash digest.
/// Used throughout the TPM stack to provide hash agility.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtHa<'a> {
    #[cfg(feature = "sha1")]
    Sha1(&'a [u8; Sha1.digest_size()]) = Alg::SHA1.tag(),
    #[cfg(feature = "sha256")]
    Sha256(&'a [u8; Sha256.digest_size()]) = Alg::SHA256.tag(),
    #[cfg(feature = "sha384")]
    Sha384(&'a [u8; Sha384.digest_size()]) = Alg::SHA384.tag(),
    #[cfg(feature = "sha512")]
    Sha512(&'a [u8; Sha512.digest_size()]) = Alg::SHA512.tag(),
    #[cfg(feature = "sm3_256")]
    Sm3_256(&'a [u8; Sm3_256.digest_size()]) = Alg::SM3_256.tag(),
    #[cfg(feature = "sha3_256")]
    Sha3_256(&'a [u8; Sha3_256.digest_size()]) = Alg::SHA3_256.tag(),
    #[cfg(feature = "sha3_384")]
    Sha3_384(&'a [u8; Sha3_384.digest_size()]) = Alg::SHA3_384.tag(),
    #[cfg(feature = "sha3_512")]
    Sha3_512(&'a [u8; Sha3_512.digest_size()]) = Alg::SHA3_512.tag(),
}

impl<'a> TpmtHa<'a> {
    /// The maximum digest size (in bytes) across all supported TPM2 hash algorithms.
    pub const MAX_DIGEST_SIZE: usize = max(&[
        #[cfg(feature = "sha1")]
        Sha1.digest_size(),
        #[cfg(feature = "sha256")]
        Sha256.digest_size(),
        #[cfg(feature = "sha384")]
        Sha384.digest_size(),
        #[cfg(feature = "sha512")]
        Sha512.digest_size(),
        #[cfg(feature = "sm3_256")]
        Sm3_256.digest_size(),
        #[cfg(feature = "sha3_256")]
        Sha3_256.digest_size(),
        #[cfg(feature = "sha3_384")]
        Sha3_384.digest_size(),
        #[cfg(feature = "sha3_512")]
        Sha3_512.digest_size(),
    ]);
    /// The maximum number of implemented hash algorithms (`HASH_COUNT`).
    ///
    /// Computed dynamically from the enabled hash algorithm features, matching
    /// `TPM2_NUM_PCR_BANKS`. Bounds `TPML_DIGEST_VALUES` and `TPML_PCR_SELECTION` counts.
    #[doc(alias = "TPM2_NUM_PCR_BANKS")]
    pub const HASH_COUNT: usize = TPM2_NUM_PCR_BANKS as usize;

    /// Default zero-initialized tagged hash digest selected from the enabled hash
    /// algorithm features via [`TpmiAlgHash::DEFAULT_HASH`].
    pub const DEFAULT_HA: Self = match Self::new(
        TpmiAlgHash::DEFAULT_HASH,
        &[0u8; TpmiAlgHash::DEFAULT_HASH.digest_size()],
    ) {
        Some(ha) => ha,
        None => unreachable!(),
    };

    /// Creates a new `TpmtHa` from a hash algorithm and a digest slice.
    ///
    /// Returns `None` if `digest.len()` does not match `hash_alg.digest_size()`.
    pub const fn new(hash_alg: TpmiAlgHash, digest: &'a [u8]) -> Option<Self> {
        match hash_alg {
            #[cfg(feature = "sha1")]
            Sha1 => match digest.first_chunk() {
                Some(b) if digest.len() == Sha1.digest_size() => Some(Self::Sha1(b)),
                _ => None,
            },
            #[cfg(feature = "sha256")]
            Sha256 => match digest.first_chunk() {
                Some(b) if digest.len() == Sha256.digest_size() => Some(Self::Sha256(b)),
                _ => None,
            },
            #[cfg(feature = "sha384")]
            Sha384 => match digest.first_chunk() {
                Some(b) if digest.len() == Sha384.digest_size() => Some(Self::Sha384(b)),
                _ => None,
            },
            #[cfg(feature = "sha512")]
            Sha512 => match digest.first_chunk() {
                Some(b) if digest.len() == Sha512.digest_size() => Some(Self::Sha512(b)),
                _ => None,
            },
            #[cfg(feature = "sm3_256")]
            Sm3_256 => match digest.first_chunk() {
                Some(b) if digest.len() == Sm3_256.digest_size() => Some(Self::Sm3_256(b)),
                _ => None,
            },
            #[cfg(feature = "sha3_256")]
            Sha3_256 => match digest.first_chunk() {
                Some(b) if digest.len() == Sha3_256.digest_size() => Some(Self::Sha3_256(b)),
                _ => None,
            },
            #[cfg(feature = "sha3_384")]
            Sha3_384 => match digest.first_chunk() {
                Some(b) if digest.len() == Sha3_384.digest_size() => Some(Self::Sha3_384(b)),
                _ => None,
            },
            #[cfg(feature = "sha3_512")]
            Sha3_512 => match digest.first_chunk() {
                Some(b) if digest.len() == Sha3_512.digest_size() => Some(Self::Sha3_512(b)),
                _ => None,
            },
        }
    }

    /// Creates a new `TpmtHa` from an [`Alg`] and a digest slice.
    ///
    /// Returns `None` if `alg` is not a supported hash algorithm or if `digest.len()`
    /// does not match the algorithm's digest size.
    pub fn from_alg(alg: Alg, digest: &'a [u8]) -> Option<Self> {
        let hash_alg = Option::<TpmiAlgHash>::try_from(alg).ok().flatten()?;
        Self::new(hash_alg, digest)
    }

    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(_) => Sha1,
            #[cfg(feature = "sha256")]
            Self::Sha256(_) => Sha256,
            #[cfg(feature = "sha384")]
            Self::Sha384(_) => Sha384,
            #[cfg(feature = "sha512")]
            Self::Sha512(_) => Sha512,
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(_) => Sm3_256,
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(_) => Sha3_256,
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(_) => Sha3_384,
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(_) => Sha3_512,
        }
    }

    pub const fn digest(self) -> &'a [u8] {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(b) => b,
            #[cfg(feature = "sha256")]
            Self::Sha256(b) => b,
            #[cfg(feature = "sha384")]
            Self::Sha384(b) => b,
            #[cfg(feature = "sha512")]
            Self::Sha512(b) => b,
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(b) => b,
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(b) => b,
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(b) => b,
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(b) => b,
        }
    }
}

impl Default for TpmtHa<'_> {
    #[inline(always)]
    fn default() -> Self {
        Self::DEFAULT_HA
    }
}

impl<'a> Marshal for TpmtHa<'a> {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + TpmiAlgHash::MAX_DIGEST_BYTES;
    type MaxBuffer = [u8; TpmtHa::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtHa::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.hash_alg(), dst, 0);
        let digest = self.digest();
        dst[count..count + digest.len()].copy_from_slice(digest);
        count + digest.len()
    }
}

impl<'a> TpmtHa<'a> {
    fn unmarshal_digest(hash_alg: TpmiAlgHash, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match hash_alg {
            #[cfg(feature = "sha1")]
            TpmiAlgHash::Sha1 => Self::Sha1(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha256")]
            TpmiAlgHash::Sha256 => Self::Sha256(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha384")]
            TpmiAlgHash::Sha384 => Self::Sha384(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => Self::Sha512(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sm3_256")]
            TpmiAlgHash::Sm3_256 => Self::Sm3_256(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha3_256")]
            TpmiAlgHash::Sha3_256 => Self::Sha3_256(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha3_384")]
            TpmiAlgHash::Sha3_384 => Self::Sha3_384(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha3_512")]
            TpmiAlgHash::Sha3_512 => Self::Sha3_512(Unmarshal::unmarshal(src)?),
        })
    }
}

impl<'a> Unmarshal<'a> for TpmtHa<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let hash_alg = TpmiAlgHash::unmarshal(src)?;
        Self::unmarshal_digest(hash_alg, src)
    }
}

impl<'a> Marshal for Option<TpmtHa<'a>> {
    const MAX_SIZE: usize = TpmtHa::MAX_SIZE;
    type MaxBuffer = [u8; TpmtHa::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(ha) => ha.marshal(dst),
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtHa<'a>> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match Option::<TpmiAlgHash>::unmarshal(src)? {
            Some(hash_alg) => TpmtHa::unmarshal_digest(hash_alg, src).map(Some),
            None => Ok(None),
        }
    }
}

/// `TPMT_KEYEDHASH_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.10 (Table 164).
///
/// Tagged structure selecting a scheme for a keyed hash object (HMAC or XOR).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtKeyedHashScheme {
    Hmac(TpmiAlgHash) = Alg::HMAC.tag(),
    ExclusiveOr(TpmsSchemeXor) = Alg::XOR.tag(),
}

impl Marshal for TpmtKeyedHashScheme {
    const MAX_SIZE: usize = <Option<TpmtKeyedHashScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Some(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmtKeyedHashScheme {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match Option::<TpmtKeyedHashScheme>::unmarshal(src)? {
            Some(scheme) => Ok(scheme),
            None => Err(UnmarshalError::VALUE),
        }
    }
}

impl Marshal for Option<TpmtKeyedHashScheme> {
    const MAX_SIZE: usize = Alg::MAX_SIZE + max(&[TpmiAlgHash::MAX_SIZE, TpmsSchemeXor::MAX_SIZE]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(TpmtKeyedHashScheme::Hmac(hash)) => {
                let count = marshal_helper(&Alg::HMAC, dst, 0);
                marshal_helper(hash, dst, count)
            }
            Some(TpmtKeyedHashScheme::ExclusiveOr(xor)) => {
                let count = marshal_helper(&Alg::XOR, dst, 0);
                marshal_helper(xor, dst, count)
            }
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtKeyedHashScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::unmarshal(src)?;
        match selector {
            Alg::NULL => Ok(None),
            Alg::HMAC => Ok(Some(TpmtKeyedHashScheme::Hmac(Unmarshal::unmarshal(src)?))),
            Alg::XOR => Ok(Some(TpmtKeyedHashScheme::ExclusiveOr(
                Unmarshal::unmarshal(src)?,
            ))),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}

/// `TPMT_SYM_DEF_OBJECT` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.5 (Table 152).
///
/// Used to select a symmetric block cipher algorithm and key size (AES, SM4, Camellia, not XOR).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtSymDefObject {
    #[cfg(feature = "aes128")]
    Aes128(Option<TpmiAlgSymMode>),
    #[cfg(feature = "aes192")]
    Aes192(Option<TpmiAlgSymMode>),
    #[cfg(feature = "aes256")]
    Aes256(Option<TpmiAlgSymMode>),
    #[cfg(feature = "sm4_128")]
    Sm4_128(Option<TpmiAlgSymMode>),
    #[cfg(feature = "camellia128")]
    Camellia128(Option<TpmiAlgSymMode>),
    #[cfg(feature = "camellia192")]
    Camellia192(Option<TpmiAlgSymMode>),
    #[cfg(feature = "camellia256")]
    Camellia256(Option<TpmiAlgSymMode>),
}

impl TpmtSymDefObject {
    pub const MAX_KEY_BITS: usize = max(&[
        #[cfg(feature = "aes128")]
        128,
        #[cfg(feature = "aes192")]
        192,
        #[cfg(feature = "aes256")]
        256,
        #[cfg(feature = "sm4_128")]
        128,
        #[cfg(feature = "camellia128")]
        128,
        #[cfg(feature = "camellia192")]
        192,
        #[cfg(feature = "camellia256")]
        256,
    ]);
    pub const MAX_KEY_BYTES: usize = Self::MAX_KEY_BITS.div_ceil(8);
    pub const MAX_BLOCK_SIZE_BYTES: usize = 16;

    #[doc(alias = "TPMI_ALG_SYM_OBJECT")]
    pub const fn algorithm(self) -> Alg {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(_) => Alg::AES,
            #[cfg(feature = "aes192")]
            Self::Aes192(_) => Alg::AES,
            #[cfg(feature = "aes256")]
            Self::Aes256(_) => Alg::AES,
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(_) => Alg::SM4,
            #[cfg(feature = "camellia128")]
            Self::Camellia128(_) => Alg::CAMELLIA,
            #[cfg(feature = "camellia192")]
            Self::Camellia192(_) => Alg::CAMELLIA,
            #[cfg(feature = "camellia256")]
            Self::Camellia256(_) => Alg::CAMELLIA,
        }
    }

    pub const fn key_bits(self) -> u16 {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(_) => 128,
            #[cfg(feature = "aes192")]
            Self::Aes192(_) => 192,
            #[cfg(feature = "aes256")]
            Self::Aes256(_) => 256,
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(_) => 128,
            #[cfg(feature = "camellia128")]
            Self::Camellia128(_) => 128,
            #[cfg(feature = "camellia192")]
            Self::Camellia192(_) => 192,
            #[cfg(feature = "camellia256")]
            Self::Camellia256(_) => 256,
        }
    }

    pub const fn mode(self) -> Option<TpmiAlgSymMode> {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(m) => m,
            #[cfg(feature = "aes192")]
            Self::Aes192(m) => m,
            #[cfg(feature = "aes256")]
            Self::Aes256(m) => m,
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(m) => m,
            #[cfg(feature = "camellia128")]
            Self::Camellia128(m) => m,
            #[cfg(feature = "camellia192")]
            Self::Camellia192(m) => m,
            #[cfg(feature = "camellia256")]
            Self::Camellia256(m) => m,
        }
    }

    pub const fn with_mode(self, mode: Option<TpmiAlgSymMode>) -> Self {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(_) => Self::Aes128(mode),
            #[cfg(feature = "aes192")]
            Self::Aes192(_) => Self::Aes192(mode),
            #[cfg(feature = "aes256")]
            Self::Aes256(_) => Self::Aes256(mode),
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(_) => Self::Sm4_128(mode),
            #[cfg(feature = "camellia128")]
            Self::Camellia128(_) => Self::Camellia128(mode),
            #[cfg(feature = "camellia192")]
            Self::Camellia192(_) => Self::Camellia192(mode),
            #[cfg(feature = "camellia256")]
            Self::Camellia256(_) => Self::Camellia256(mode),
        }
    }

    pub const fn aes_cfb(key_bits: u16) -> Result<Self, UnmarshalError> {
        Self::from_parts(Alg::AES, key_bits, Some(TpmiAlgSymMode::CFB))
    }

    pub const fn from_parts(
        algorithm: Alg,
        key_bits: u16,
        mode: Option<TpmiAlgSymMode>,
    ) -> Result<Self, UnmarshalError> {
        match (algorithm, key_bits) {
            #[cfg(feature = "aes128")]
            (Alg::AES, 128) => Ok(Self::Aes128(mode)),
            #[cfg(feature = "aes192")]
            (Alg::AES, 192) => Ok(Self::Aes192(mode)),
            #[cfg(feature = "aes256")]
            (Alg::AES, 256) => Ok(Self::Aes256(mode)),
            #[cfg(feature = "sm4_128")]
            (Alg::SM4, 128) => Ok(Self::Sm4_128(mode)),
            #[cfg(feature = "camellia128")]
            (Alg::CAMELLIA, 128) => Ok(Self::Camellia128(mode)),
            #[cfg(feature = "camellia192")]
            (Alg::CAMELLIA, 192) => Ok(Self::Camellia192(mode)),
            #[cfg(feature = "camellia256")]
            (Alg::CAMELLIA, 256) => Ok(Self::Camellia256(mode)),
            #[cfg(any(feature = "aes128", feature = "aes192", feature = "aes256"))]
            (Alg::AES, _) => Err(UnmarshalError::VALUE),
            #[cfg(feature = "sm4_128")]
            (Alg::SM4, _) => Err(UnmarshalError::VALUE),
            #[cfg(any(
                feature = "camellia128",
                feature = "camellia192",
                feature = "camellia256"
            ))]
            (Alg::CAMELLIA, _) => Err(UnmarshalError::VALUE),
            _ => Err(UnmarshalError::SYMMETRIC),
        }
    }
}

impl Marshal for TpmtSymDefObject {
    const MAX_SIZE: usize = Alg::MAX_SIZE + u16::MAX_SIZE + Option::<TpmiAlgSymMode>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.algorithm(), dst, 0);
        let count = marshal_helper(&self.key_bits(), dst, count);
        marshal_helper(&self.mode(), dst, count)
    }
}

impl TpmtSymDefObject {
    fn unmarshal_with_algorithm(algorithm: Alg, src: &mut &[u8]) -> Result<Self, UnmarshalError> {
        let is_valid_alg = match algorithm {
            #[cfg(any(feature = "aes128", feature = "aes192", feature = "aes256"))]
            Alg::AES => true,
            #[cfg(feature = "sm4_128")]
            Alg::SM4 => true,
            #[cfg(any(
                feature = "camellia128",
                feature = "camellia192",
                feature = "camellia256"
            ))]
            Alg::CAMELLIA => true,
            _ => false,
        };
        if !is_valid_alg {
            return Err(UnmarshalError::SYMMETRIC);
        }
        let key_bits: u16 = Unmarshal::unmarshal(src)?;
        let is_valid_key_bits = match (algorithm, key_bits) {
            #[cfg(feature = "aes128")]
            (Alg::AES, 128) => true,
            #[cfg(feature = "aes192")]
            (Alg::AES, 192) => true,
            #[cfg(feature = "aes256")]
            (Alg::AES, 256) => true,
            #[cfg(feature = "sm4_128")]
            (Alg::SM4, 128) => true,
            #[cfg(feature = "camellia128")]
            (Alg::CAMELLIA, 128) => true,
            #[cfg(feature = "camellia192")]
            (Alg::CAMELLIA, 192) => true,
            #[cfg(feature = "camellia256")]
            (Alg::CAMELLIA, 256) => true,
            _ => false,
        };
        if !is_valid_key_bits {
            return Err(UnmarshalError::VALUE);
        }
        let mode = Unmarshal::unmarshal(src)?;
        Self::from_parts(algorithm, key_bits, mode)
    }
}

impl<'a> Unmarshal<'a> for TpmtSymDefObject {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let algorithm = Alg::unmarshal(src)?;
        Self::unmarshal_with_algorithm(algorithm, src)
    }
}

impl Marshal for Option<TpmtSymDefObject> {
    const MAX_SIZE: usize = TpmtSymDefObject::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(obj) => obj.marshal(dst),
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtSymDefObject> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let algorithm = Alg::unmarshal(src)?;
        if algorithm == Alg::NULL {
            Ok(None)
        } else {
            TpmtSymDefObject::unmarshal_with_algorithm(algorithm, src).map(Some)
        }
    }
}

/// `TPMT_SYM_DEF` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.4 (Table 151).
///
/// Tagged structure selecting a symmetric block cipher or XOR mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtSymDef {
    Cipher(TpmtSymDefObject),
    Xor(TpmiAlgHash),
}

impl TpmtSymDef {
    pub const fn algorithm(&self) -> Alg {
        match self {
            Self::Cipher(obj) => obj.algorithm(),
            Self::Xor(_) => Alg::XOR,
        }
    }

    pub const fn key_bits(&self) -> u16 {
        match self {
            Self::Cipher(obj) => obj.key_bits(),
            Self::Xor(_) => 0,
        }
    }

    pub const fn mode(&self) -> Option<TpmiAlgSymMode> {
        match self {
            Self::Cipher(obj) => obj.mode(),
            Self::Xor(_) => None,
        }
    }
}

impl From<TpmtSymDefObject> for TpmtSymDef {
    fn from(obj: TpmtSymDefObject) -> Self {
        Self::Cipher(obj)
    }
}

impl Marshal for Option<TpmtSymDef> {
    const MAX_SIZE: usize = max(&[
        TpmtSymDefObject::MAX_SIZE,
        Alg::MAX_SIZE + TpmiAlgHash::MAX_SIZE,
    ]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(TpmtSymDef::Cipher(obj)) => marshal_helper(obj, dst, 0),
            Some(TpmtSymDef::Xor(hash)) => {
                let count = marshal_helper(&Alg::XOR, dst, 0);
                marshal_helper(hash, dst, count)
            }
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtSymDef> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let algorithm = Alg::unmarshal(src)?;
        match algorithm {
            Alg::NULL => Ok(None),
            Alg::XOR => {
                let hash = Unmarshal::unmarshal(src)?;
                Ok(Some(TpmtSymDef::Xor(hash)))
            }
            _ => TpmtSymDefObject::unmarshal_with_algorithm(algorithm, src)
                .map(TpmtSymDef::Cipher)
                .map(Some),
        }
    }
}

/// `TPMT_SIGNATURE` structure defined in TPM 2.0 Part 2: Structures, Section 11.3.4 (Table 173 / Table 200).
///
/// Tagged algorithm-agile signature structure containing a signature algorithm ID (`sigAlg`) and the signature payload (`TPMU_SIGNATURE`).
#[doc(alias = "TPMT_SIGNATURE")]
#[doc(alias = "TPMU_SIGNATURE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtSignature<'a> {
    #[cfg(feature = "rsassa")]
    Rsassa(TpmsSignatureRsa<'a>) = Alg::RSASSA.tag(),
    #[cfg(feature = "rsapss")]
    Rsapss(TpmsSignatureRsa<'a>) = Alg::RSAPSS.tag(),
    #[cfg(feature = "ecdsa")]
    Ecdsa(TpmsSignatureEcc<'a>) = Alg::ECDSA.tag(),
    #[cfg(feature = "ecdaa")]
    Ecdaa(TpmsSignatureEcc<'a>) = Alg::ECDAA.tag(),
    #[cfg(feature = "sm2")]
    Sm2(TpmsSignatureEcc<'a>) = Alg::SM2.tag(),
    #[cfg(feature = "ecschnorr")]
    Ecschnorr(TpmsSignatureEcc<'a>) = Alg::ECSCHNORR.tag(),
    Eddsa(Tpm2bSignatureEddsa<'a>) = Alg::EDDSA.tag(),
    HashEddsa(Tpm2bSignatureEddsa<'a>) = Alg::HASH_EDDSA.tag(),
    Hmac(TpmtHa<'a>) = Alg::HMAC.tag(),
}

impl<'a> TpmtSignature<'a> {
    #[doc(alias = "TPMI_ALG_SIG_SCHEME")]
    pub const fn sig_alg(self) -> Alg {
        match self {
            Self::Hmac(_) => Alg::HMAC,
            #[cfg(feature = "rsassa")]
            Self::Rsassa(_) => Alg::RSASSA,
            #[cfg(feature = "rsapss")]
            Self::Rsapss(_) => Alg::RSAPSS,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(_) => Alg::ECDSA,
            #[cfg(feature = "ecdaa")]
            Self::Ecdaa(_) => Alg::ECDAA,
            #[cfg(feature = "sm2")]
            Self::Sm2(_) => Alg::SM2,
            #[cfg(feature = "ecschnorr")]
            Self::Ecschnorr(_) => Alg::ECSCHNORR,
            Self::Eddsa(_) => Alg::EDDSA,
            Self::HashEddsa(_) => Alg::HASH_EDDSA,
        }
    }
}

impl Marshal for TpmtSignature<'_> {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + max(&[
            TpmsSignatureRsa::MAX_SIZE,
            TpmsSignatureEcc::MAX_SIZE,
            Tpm2bSignatureEddsa::MAX_SIZE,
            TpmtHa::MAX_SIZE,
        ]);
    type MaxBuffer = [u8; TpmtSignature::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            #[cfg(feature = "rsassa")]
            Self::Rsassa(x) => {
                let count = marshal_helper(&Alg::RSASSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "rsapss")]
            Self::Rsapss(x) => {
                let count = marshal_helper(&Alg::RSAPSS, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(x) => {
                let count = marshal_helper(&Alg::ECDSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecdaa")]
            Self::Ecdaa(x) => {
                let count = marshal_helper(&Alg::ECDAA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "sm2")]
            Self::Sm2(x) => {
                let count = marshal_helper(&Alg::SM2, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecschnorr")]
            Self::Ecschnorr(x) => {
                let count = marshal_helper(&Alg::ECSCHNORR, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Eddsa(x) => {
                let count = marshal_helper(&Alg::EDDSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::HashEddsa(x) => {
                let count = marshal_helper(&Alg::HASH_EDDSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Hmac(x) => {
                let count = marshal_helper(&Alg::HMAC, dst, 0);
                marshal_helper(x, dst, count)
            }
        }
    }
}

impl<'a> TpmtSignature<'a> {
    fn unmarshal_with_selector(selector: Alg, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let sig_scheme = TpmiAlgSigScheme::try_from(selector)?;
        match sig_scheme {
            #[cfg(feature = "rsassa")]
            TpmiAlgSigScheme::Rsassa => Ok(Self::Rsassa(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "rsapss")]
            TpmiAlgSigScheme::Rsapss => Ok(Self::Rsapss(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "ecdsa")]
            TpmiAlgSigScheme::Ecdsa => Ok(Self::Ecdsa(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "ecdaa")]
            TpmiAlgSigScheme::Ecdaa => Ok(Self::Ecdaa(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "sm2")]
            TpmiAlgSigScheme::Sm2 => Ok(Self::Sm2(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "ecschnorr")]
            TpmiAlgSigScheme::Ecschnorr => Ok(Self::Ecschnorr(Unmarshal::unmarshal(src)?)),
            TpmiAlgSigScheme::Eddsa => Ok(Self::Eddsa(Unmarshal::unmarshal(src)?)),
            TpmiAlgSigScheme::HashEddsa => Ok(Self::HashEddsa(Unmarshal::unmarshal(src)?)),
            TpmiAlgSigScheme::Hmac => Ok(Self::Hmac(Unmarshal::unmarshal(src)?)),
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtSignature<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::unmarshal(src)?;
        Self::unmarshal_with_selector(selector, src)
    }
}

impl<'a> Marshal for Option<TpmtSignature<'a>> {
    const MAX_SIZE: usize = TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; TpmtSignature::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(sig) => sig.marshal(dst),
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtSignature<'a>> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::unmarshal(src)?;
        if selector == Alg::NULL {
            Ok(None)
        } else {
            TpmtSignature::unmarshal_with_selector(selector, src).map(Some)
        }
    }
}

/// `TPMT_SIG_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.1.3 (Table 172).
///
/// Tagged signature scheme structure specifying a signature algorithm (`RSAPSS`, `RSASSA`, `ECDSA`,
/// `ECDAA`, `SM2`, `ECSCHNORR`, `EDDSA`, `HASH_EDDSA`, `HMAC`) and its scheme parameters.
#[doc(alias = "TPMT_SIG_SCHEME")]
#[doc(alias = "TPMU_SIG_SCHEME")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtSigScheme {
    #[cfg(feature = "rsassa")]
    Rsassa(TpmiAlgHash) = Alg::RSASSA.tag(),
    #[cfg(feature = "rsapss")]
    Rsapss(TpmiAlgHash) = Alg::RSAPSS.tag(),
    #[cfg(feature = "ecdsa")]
    Ecdsa(TpmiAlgHash) = Alg::ECDSA.tag(),
    #[cfg(feature = "ecdaa")]
    Ecdaa(TpmsSchemeEcdaa) = Alg::ECDAA.tag(),
    #[cfg(feature = "sm2")]
    Sm2(TpmiAlgHash) = Alg::SM2.tag(),
    #[cfg(feature = "ecschnorr")]
    Ecschnorr(TpmiAlgHash) = Alg::ECSCHNORR.tag(),
    Eddsa = Alg::EDDSA.tag(),
    HashEddsa = Alg::HASH_EDDSA.tag(),
    Hmac(TpmiAlgHash) = Alg::HMAC.tag(),
}

impl TpmtSigScheme {
    pub const fn scheme(&self) -> TpmiAlgSigScheme {
        match self {
            #[cfg(feature = "rsassa")]
            Self::Rsassa(_) => TpmiAlgSigScheme::Rsassa,
            #[cfg(feature = "rsapss")]
            Self::Rsapss(_) => TpmiAlgSigScheme::Rsapss,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(_) => TpmiAlgSigScheme::Ecdsa,
            #[cfg(feature = "ecdaa")]
            Self::Ecdaa(_) => TpmiAlgSigScheme::Ecdaa,
            #[cfg(feature = "sm2")]
            Self::Sm2(_) => TpmiAlgSigScheme::Sm2,
            #[cfg(feature = "ecschnorr")]
            Self::Ecschnorr(_) => TpmiAlgSigScheme::Ecschnorr,
            Self::Eddsa => TpmiAlgSigScheme::Eddsa,
            Self::HashEddsa => TpmiAlgSigScheme::HashEddsa,
            Self::Hmac(_) => TpmiAlgSigScheme::Hmac,
        }
    }

    pub const fn algorithm(self) -> Alg {
        match self {
            #[cfg(feature = "rsassa")]
            Self::Rsassa(_) => Alg::RSASSA,
            #[cfg(feature = "rsapss")]
            Self::Rsapss(_) => Alg::RSAPSS,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(_) => Alg::ECDSA,
            #[cfg(feature = "ecdaa")]
            Self::Ecdaa(_) => Alg::ECDAA,
            #[cfg(feature = "sm2")]
            Self::Sm2(_) => Alg::SM2,
            #[cfg(feature = "ecschnorr")]
            Self::Ecschnorr(_) => Alg::ECSCHNORR,
            Self::Eddsa => Alg::EDDSA,
            Self::HashEddsa => Alg::HASH_EDDSA,
            Self::Hmac(_) => Alg::HMAC,
        }
    }

    pub const fn hash_alg(self) -> Option<TpmiAlgHash> {
        match self {
            #[cfg(feature = "rsassa")]
            Self::Rsassa(h) => Some(h),
            #[cfg(feature = "rsapss")]
            Self::Rsapss(h) => Some(h),
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(h) => Some(h),
            #[cfg(feature = "sm2")]
            Self::Sm2(h) => Some(h),
            #[cfg(feature = "ecschnorr")]
            Self::Ecschnorr(h) => Some(h),
            Self::Hmac(h) => Some(h),
            #[cfg(feature = "ecdaa")]
            Self::Ecdaa(s) => Some(s.hash_alg),
            Self::Eddsa | Self::HashEddsa => None,
        }
    }
}

impl Marshal for TpmtSigScheme {
    const MAX_SIZE: usize =
        Alg::MAX_SIZE + max(&[TpmiAlgHash::MAX_SIZE, TpmsSchemeEcdaa::MAX_SIZE]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Some(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmtSigScheme {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let sig_scheme = TpmiAlgSigScheme::unmarshal(src)?;
        match sig_scheme {
            #[cfg(feature = "rsassa")]
            TpmiAlgSigScheme::Rsassa => Ok(Self::Rsassa(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "rsapss")]
            TpmiAlgSigScheme::Rsapss => Ok(Self::Rsapss(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "ecdsa")]
            TpmiAlgSigScheme::Ecdsa => Ok(Self::Ecdsa(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "ecdaa")]
            TpmiAlgSigScheme::Ecdaa => Ok(Self::Ecdaa(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "sm2")]
            TpmiAlgSigScheme::Sm2 => Ok(Self::Sm2(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "ecschnorr")]
            TpmiAlgSigScheme::Ecschnorr => Ok(Self::Ecschnorr(Unmarshal::unmarshal(src)?)),
            TpmiAlgSigScheme::Eddsa => Ok(Self::Eddsa),
            TpmiAlgSigScheme::HashEddsa => Ok(Self::HashEddsa),
            TpmiAlgSigScheme::Hmac => Ok(Self::Hmac(Unmarshal::unmarshal(src)?)),
        }
    }
}

impl Marshal for Option<TpmtSigScheme> {
    const MAX_SIZE: usize =
        Alg::MAX_SIZE + max(&[TpmiAlgHash::MAX_SIZE, TpmsSchemeEcdaa::MAX_SIZE]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            #[cfg(feature = "rsassa")]
            Some(TpmtSigScheme::Rsassa(x)) => {
                let count = marshal_helper(&Alg::RSASSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "rsapss")]
            Some(TpmtSigScheme::Rsapss(x)) => {
                let count = marshal_helper(&Alg::RSAPSS, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecdsa")]
            Some(TpmtSigScheme::Ecdsa(x)) => {
                let count = marshal_helper(&Alg::ECDSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecdaa")]
            Some(TpmtSigScheme::Ecdaa(x)) => {
                let count = marshal_helper(&Alg::ECDAA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "sm2")]
            Some(TpmtSigScheme::Sm2(x)) => {
                let count = marshal_helper(&Alg::SM2, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecschnorr")]
            Some(TpmtSigScheme::Ecschnorr(x)) => {
                let count = marshal_helper(&Alg::ECSCHNORR, dst, 0);
                marshal_helper(x, dst, count)
            }
            Some(TpmtSigScheme::Eddsa) => marshal_helper(&Alg::EDDSA, dst, 0),
            Some(TpmtSigScheme::HashEddsa) => marshal_helper(&Alg::HASH_EDDSA, dst, 0),
            Some(TpmtSigScheme::Hmac(x)) => {
                let count = marshal_helper(&Alg::HMAC, dst, 0);
                marshal_helper(x, dst, count)
            }
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtSigScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector: Option<TpmiAlgSigScheme> = Unmarshal::unmarshal(src)?;
        match selector {
            None => Ok(None),
            #[cfg(feature = "rsassa")]
            Some(TpmiAlgSigScheme::Rsassa) => {
                Ok(Some(TpmtSigScheme::Rsassa(Unmarshal::unmarshal(src)?)))
            }
            #[cfg(feature = "rsapss")]
            Some(TpmiAlgSigScheme::Rsapss) => {
                Ok(Some(TpmtSigScheme::Rsapss(Unmarshal::unmarshal(src)?)))
            }
            #[cfg(feature = "ecdsa")]
            Some(TpmiAlgSigScheme::Ecdsa) => {
                Ok(Some(TpmtSigScheme::Ecdsa(Unmarshal::unmarshal(src)?)))
            }
            #[cfg(feature = "ecdaa")]
            Some(TpmiAlgSigScheme::Ecdaa) => {
                Ok(Some(TpmtSigScheme::Ecdaa(Unmarshal::unmarshal(src)?)))
            }
            #[cfg(feature = "sm2")]
            Some(TpmiAlgSigScheme::Sm2) => Ok(Some(TpmtSigScheme::Sm2(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "ecschnorr")]
            Some(TpmiAlgSigScheme::Ecschnorr) => {
                Ok(Some(TpmtSigScheme::Ecschnorr(Unmarshal::unmarshal(src)?)))
            }
            Some(TpmiAlgSigScheme::Eddsa) => Ok(Some(TpmtSigScheme::Eddsa)),
            Some(TpmiAlgSigScheme::HashEddsa) => Ok(Some(TpmtSigScheme::HashEddsa)),
            Some(TpmiAlgSigScheme::Hmac) => {
                Ok(Some(TpmtSigScheme::Hmac(Unmarshal::unmarshal(src)?)))
            }
        }
    }
}

/// `TPMT_RSA_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.1.3 (Table 182).
///
/// Tagged RSA scheme structure specifying an RSA scheme (RSAPSS, RSASSA, OAEP, RSAES) and associated hash algorithm.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(
    any(
        feature = "rsassa",
        feature = "rsapss",
        feature = "oaep",
        feature = "rsaes"
    ),
    repr(u16)
)]
pub enum TpmtRsaScheme {
    #[cfg(feature = "rsassa")]
    Rsassa(TpmiAlgHash) = Alg::RSASSA.tag(),
    #[cfg(feature = "rsapss")]
    Rsapss(TpmiAlgHash) = Alg::RSAPSS.tag(),
    #[cfg(feature = "oaep")]
    Oaep(TpmiAlgHash) = Alg::OAEP.tag(),
    #[cfg(feature = "rsaes")]
    Rsaes = Alg::RSAES.tag(),
}

impl TpmtRsaScheme {
    pub const fn scheme(&self) -> Alg {
        match *self {
            #[cfg(feature = "rsassa")]
            Self::Rsassa(_) => Alg::RSASSA,
            #[cfg(feature = "rsapss")]
            Self::Rsapss(_) => Alg::RSAPSS,
            #[cfg(feature = "oaep")]
            Self::Oaep(_) => Alg::OAEP,
            #[cfg(feature = "rsaes")]
            Self::Rsaes => Alg::RSAES,
        }
    }

    pub const fn hash_alg(&self) -> Option<TpmiAlgHash> {
        match *self {
            #[cfg(feature = "rsassa")]
            Self::Rsassa(h) => Some(h),
            #[cfg(feature = "rsapss")]
            Self::Rsapss(h) => Some(h),
            #[cfg(feature = "oaep")]
            Self::Oaep(h) => Some(h),
            #[cfg(feature = "rsaes")]
            Self::Rsaes => None,
        }
    }
}

impl Marshal for TpmtRsaScheme {
    const MAX_SIZE: usize = Alg::MAX_SIZE + TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[cfg_attr(
        not(any(
            feature = "rsassa",
            feature = "rsapss",
            feature = "oaep",
            feature = "rsaes"
        )),
        allow(unused_variables)
    )]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match *self {
            #[cfg(feature = "rsassa")]
            Self::Rsassa(ref x) => {
                let count = marshal_helper(&Alg::RSASSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "rsapss")]
            Self::Rsapss(ref x) => {
                let count = marshal_helper(&Alg::RSAPSS, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "oaep")]
            Self::Oaep(ref x) => {
                let count = marshal_helper(&Alg::OAEP, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "rsaes")]
            Self::Rsaes => marshal_helper(&Alg::RSAES, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtRsaScheme {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match Option::<TpmtRsaScheme>::unmarshal(src)? {
            Some(scheme) => Ok(scheme),
            None => Err(UnmarshalError::VALUE),
        }
    }
}

impl Marshal for Option<TpmtRsaScheme> {
    const MAX_SIZE: usize = TpmtRsaScheme::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(scheme) => scheme.marshal(dst),
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtRsaScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::unmarshal(src)?;
        match selector {
            Alg::NULL => Ok(None),
            #[cfg(feature = "rsassa")]
            Alg::RSASSA => Ok(Some(TpmtRsaScheme::Rsassa(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "rsapss")]
            Alg::RSAPSS => Ok(Some(TpmtRsaScheme::Rsapss(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "oaep")]
            Alg::OAEP => Ok(Some(TpmtRsaScheme::Oaep(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "rsaes")]
            Alg::RSAES => Ok(Some(TpmtRsaScheme::Rsaes)),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}

/// `TPMT_RSA_DECRYPT` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.4.5 (Table 184).
///
/// Tagged RSA decrypt scheme structure specifying an RSA decryption scheme (`TPM_ALG_OAEP`, `TPM_ALG_RSAES`)
/// and associated hash algorithm. Its selector is `TPMI_ALG_RSA_DECRYPT` (Section 11.2.4.4, Table 183),
/// which returns `TPM_RC_VALUE` (`UnmarshalError::VALUE`) for unsupported scheme selectors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(any(feature = "oaep", feature = "rsaes"), repr(u16))]
pub enum TpmtRsaDecrypt {
    #[cfg(feature = "oaep")]
    Oaep(TpmiAlgHash) = Alg::OAEP.tag(),
    #[cfg(feature = "rsaes")]
    Rsaes = Alg::RSAES.tag(),
}

impl TpmtRsaDecrypt {
    pub const fn scheme(&self) -> Alg {
        match *self {
            #[cfg(feature = "oaep")]
            Self::Oaep(_) => Alg::OAEP,
            #[cfg(feature = "rsaes")]
            Self::Rsaes => Alg::RSAES,
        }
    }

    pub const fn hash_alg(&self) -> Option<TpmiAlgHash> {
        match *self {
            #[cfg(feature = "oaep")]
            Self::Oaep(h) => Some(h),
            #[cfg(feature = "rsaes")]
            Self::Rsaes => None,
        }
    }
}

impl Marshal for TpmtRsaDecrypt {
    const MAX_SIZE: usize = Alg::MAX_SIZE + TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[cfg_attr(not(any(feature = "oaep", feature = "rsaes")), allow(unused_variables))]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match *self {
            #[cfg(feature = "oaep")]
            Self::Oaep(ref x) => {
                let count = marshal_helper(&Alg::OAEP, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "rsaes")]
            Self::Rsaes => marshal_helper(&Alg::RSAES, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtRsaDecrypt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::unmarshal(src)?;
        match selector {
            #[cfg(feature = "oaep")]
            Alg::OAEP => Ok(Self::Oaep(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "rsaes")]
            Alg::RSAES => Ok(Self::Rsaes),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}

impl Marshal for Option<TpmtRsaDecrypt> {
    const MAX_SIZE: usize = TpmtRsaDecrypt::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(scheme) => scheme.marshal(dst),
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtRsaDecrypt> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::unmarshal(src)?;
        match selector {
            Alg::NULL => Ok(None),
            #[cfg(feature = "oaep")]
            Alg::OAEP => Ok(Some(TpmtRsaDecrypt::Oaep(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "rsaes")]
            Alg::RSAES => Ok(Some(TpmtRsaDecrypt::Rsaes)),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}

/// `TPMT_ECC_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.5 (Table 193).
///
/// Tagged ECC scheme structure specifying an ECC scheme (`ECDSA`, `ECDAA`, `SM2`, `ECSCHNORR`,
/// `EDDSA`, `HASH_EDDSA`, `ECDH`, `ECMQV`) and associated parameters.
#[doc(alias = "TPMT_ECC_SCHEME")]
#[doc(alias = "TPMU_ECC_SCHEME")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtEccScheme {
    #[cfg(feature = "ecdsa")]
    Ecdsa(TpmiAlgHash) = Alg::ECDSA.tag(),
    #[cfg(feature = "ecdaa")]
    Ecdaa(TpmsSchemeEcdaa) = Alg::ECDAA.tag(),
    #[cfg(feature = "sm2")]
    Sm2(TpmiAlgHash) = Alg::SM2.tag(),
    #[cfg(feature = "ecschnorr")]
    Ecschnorr(TpmiAlgHash) = Alg::ECSCHNORR.tag(),
    Eddsa = Alg::EDDSA.tag(),
    HashEddsa = Alg::HASH_EDDSA.tag(),
    #[cfg(feature = "ecdh")]
    Ecdh(TpmiAlgHash) = Alg::ECDH.tag(),
    #[cfg(feature = "ecmqv")]
    Ecmqv(TpmiAlgHash) = Alg::ECMQV.tag(),
}

impl TpmtEccScheme {
    pub const fn scheme(&self) -> Alg {
        match self {
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(_) => Alg::ECDSA,
            #[cfg(feature = "ecdaa")]
            Self::Ecdaa(_) => Alg::ECDAA,
            #[cfg(feature = "sm2")]
            Self::Sm2(_) => Alg::SM2,
            #[cfg(feature = "ecschnorr")]
            Self::Ecschnorr(_) => Alg::ECSCHNORR,
            Self::Eddsa => Alg::EDDSA,
            Self::HashEddsa => Alg::HASH_EDDSA,
            #[cfg(feature = "ecdh")]
            Self::Ecdh(_) => Alg::ECDH,
            #[cfg(feature = "ecmqv")]
            Self::Ecmqv(_) => Alg::ECMQV,
        }
    }

    pub const fn hash_alg(&self) -> Option<TpmiAlgHash> {
        match *self {
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(h) => Some(h),
            #[cfg(feature = "sm2")]
            Self::Sm2(h) => Some(h),
            #[cfg(feature = "ecschnorr")]
            Self::Ecschnorr(h) => Some(h),
            #[cfg(feature = "ecdh")]
            Self::Ecdh(h) => Some(h),
            #[cfg(feature = "ecmqv")]
            Self::Ecmqv(h) => Some(h),
            #[cfg(feature = "ecdaa")]
            Self::Ecdaa(s) => Some(s.hash_alg),
            Self::Eddsa | Self::HashEddsa => None,
        }
    }
}

impl Marshal for TpmtEccScheme {
    const MAX_SIZE: usize =
        Alg::MAX_SIZE + max(&[TpmiAlgHash::MAX_SIZE, TpmsSchemeEcdaa::MAX_SIZE]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Some(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmtEccScheme {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match Option::<TpmtEccScheme>::unmarshal(src)? {
            Some(scheme) => Ok(scheme),
            None => Err(UnmarshalError::SCHEME),
        }
    }
}

impl Marshal for Option<TpmtEccScheme> {
    const MAX_SIZE: usize =
        Alg::MAX_SIZE + max(&[TpmiAlgHash::MAX_SIZE, TpmsSchemeEcdaa::MAX_SIZE]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            #[cfg(feature = "ecdsa")]
            Some(TpmtEccScheme::Ecdsa(x)) => {
                let count = marshal_helper(&Alg::ECDSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecdaa")]
            Some(TpmtEccScheme::Ecdaa(x)) => {
                let count = marshal_helper(&Alg::ECDAA, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "sm2")]
            Some(TpmtEccScheme::Sm2(x)) => {
                let count = marshal_helper(&Alg::SM2, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecschnorr")]
            Some(TpmtEccScheme::Ecschnorr(x)) => {
                let count = marshal_helper(&Alg::ECSCHNORR, dst, 0);
                marshal_helper(x, dst, count)
            }
            Some(TpmtEccScheme::Eddsa) => marshal_helper(&Alg::EDDSA, dst, 0),
            Some(TpmtEccScheme::HashEddsa) => marshal_helper(&Alg::HASH_EDDSA, dst, 0),
            #[cfg(feature = "ecdh")]
            Some(TpmtEccScheme::Ecdh(x)) => {
                let count = marshal_helper(&Alg::ECDH, dst, 0);
                marshal_helper(x, dst, count)
            }
            #[cfg(feature = "ecmqv")]
            Some(TpmtEccScheme::Ecmqv(x)) => {
                let count = marshal_helper(&Alg::ECMQV, dst, 0);
                marshal_helper(x, dst, count)
            }
            None => marshal_helper(&Alg::NULL, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtEccScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::unmarshal(src)?;
        match selector {
            Alg::NULL => Ok(None),
            #[cfg(feature = "ecdsa")]
            Alg::ECDSA => Ok(Some(TpmtEccScheme::Ecdsa(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "ecdaa")]
            Alg::ECDAA => Ok(Some(TpmtEccScheme::Ecdaa(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "sm2")]
            Alg::SM2 => Ok(Some(TpmtEccScheme::Sm2(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "ecschnorr")]
            Alg::ECSCHNORR => Ok(Some(TpmtEccScheme::Ecschnorr(Unmarshal::unmarshal(src)?))),
            Alg::EDDSA => Ok(Some(TpmtEccScheme::Eddsa)),
            Alg::HASH_EDDSA => Ok(Some(TpmtEccScheme::HashEddsa)),
            #[cfg(feature = "ecdh")]
            Alg::ECDH => Ok(Some(TpmtEccScheme::Ecdh(Unmarshal::unmarshal(src)?))),
            #[cfg(feature = "ecmqv")]
            Alg::ECMQV => Ok(Some(TpmtEccScheme::Ecmqv(Unmarshal::unmarshal(src)?))),
            _ => Err(UnmarshalError::SCHEME),
        }
    }
}

impl TryFrom<TpmtRsaScheme> for TpmtSigScheme {
    type Error = ();

    fn try_from(scheme: TpmtRsaScheme) -> Result<Self, Self::Error> {
        match scheme {
            #[cfg(feature = "rsapss")]
            TpmtRsaScheme::Rsapss(s) => Ok(Self::Rsapss(s)),
            #[cfg(feature = "rsassa")]
            TpmtRsaScheme::Rsassa(s) => Ok(Self::Rsassa(s)),
            #[cfg(feature = "oaep")]
            TpmtRsaScheme::Oaep(_) => Err(()),
            #[cfg(feature = "rsaes")]
            TpmtRsaScheme::Rsaes => Err(()),
        }
    }
}

impl TryFrom<TpmtEccScheme> for TpmtSigScheme {
    type Error = ();

    fn try_from(scheme: TpmtEccScheme) -> Result<Self, Self::Error> {
        match scheme {
            #[cfg(feature = "ecdsa")]
            TpmtEccScheme::Ecdsa(s) => Ok(Self::Ecdsa(s)),
            #[cfg(feature = "ecdaa")]
            TpmtEccScheme::Ecdaa(s) => Ok(Self::Ecdaa(s)),
            #[cfg(feature = "sm2")]
            TpmtEccScheme::Sm2(s) => Ok(Self::Sm2(s)),
            #[cfg(feature = "ecschnorr")]
            TpmtEccScheme::Ecschnorr(s) => Ok(Self::Ecschnorr(s)),
            TpmtEccScheme::Eddsa => Ok(Self::Eddsa),
            TpmtEccScheme::HashEddsa => Ok(Self::HashEddsa),
            #[cfg(feature = "ecdh")]
            TpmtEccScheme::Ecdh(_) => Err(()),
            #[cfg(feature = "ecmqv")]
            TpmtEccScheme::Ecmqv(_) => Err(()),
        }
    }
}

/// `TPMT_KDF_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.11 (Table 177).
///
/// Tagged KDF scheme structure specifying a key derivation function algorithm and associated hash algorithm.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtKdfScheme {
    Mgf1(TpmiAlgHash) = Alg::MGF1.tag(),
    Hkdf(TpmiAlgHash) = Alg::HKDF.tag(),
    Kdf1Sp800_56a(TpmiAlgHash) = Alg::KDF1_SP800_56A.tag(),
    Kdf2(TpmiAlgHash) = Alg::KDF2.tag(),
    Kdf1Sp800_108(TpmiAlgHash) = Alg::KDF1_SP800_108.tag(),
}

impl TpmtKdfScheme {
    /// Returns the algorithm selector (scheme) for this KDF scheme.
    pub const fn scheme(&self) -> TpmiAlgKdf {
        match self {
            Self::Mgf1(_) => TpmiAlgKdf::Mgf1,
            Self::Hkdf(_) => TpmiAlgKdf::Hkdf,
            Self::Kdf1Sp800_56a(_) => TpmiAlgKdf::Kdf1Sp800_56a,
            Self::Kdf2(_) => TpmiAlgKdf::Kdf2,
            Self::Kdf1Sp800_108(_) => TpmiAlgKdf::Kdf1Sp800_108,
        }
    }

    /// Returns the associated hash algorithm.
    pub const fn hash_alg(&self) -> TpmiAlgHash {
        match *self {
            Self::Mgf1(h)
            | Self::Hkdf(h)
            | Self::Kdf1Sp800_56a(h)
            | Self::Kdf2(h)
            | Self::Kdf1Sp800_108(h) => h,
        }
    }
}

impl Marshal for TpmtKdfScheme {
    const MAX_SIZE: usize = <Option<TpmtKdfScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Some(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmtKdfScheme {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match Option::<TpmtKdfScheme>::unmarshal(src)? {
            Some(scheme) => Ok(scheme),
            None => Err(UnmarshalError::KDF),
        }
    }
}

impl Marshal for Option<TpmtKdfScheme> {
    const MAX_SIZE: usize = <Option<TpmiAlgKdf>>::MAX_SIZE + TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Some(TpmtKdfScheme::Mgf1(x)) => {
                let count = marshal_helper(&Some(TpmiAlgKdf::Mgf1), dst, 0);
                marshal_helper(x, dst, count)
            }
            Some(TpmtKdfScheme::Hkdf(x)) => {
                let count = marshal_helper(&Some(TpmiAlgKdf::Hkdf), dst, 0);
                marshal_helper(x, dst, count)
            }
            Some(TpmtKdfScheme::Kdf1Sp800_56a(x)) => {
                let count = marshal_helper(&Some(TpmiAlgKdf::Kdf1Sp800_56a), dst, 0);
                marshal_helper(x, dst, count)
            }
            Some(TpmtKdfScheme::Kdf2(x)) => {
                let count = marshal_helper(&Some(TpmiAlgKdf::Kdf2), dst, 0);
                marshal_helper(x, dst, count)
            }
            Some(TpmtKdfScheme::Kdf1Sp800_108(x)) => {
                let count = marshal_helper(&Some(TpmiAlgKdf::Kdf1Sp800_108), dst, 0);
                marshal_helper(x, dst, count)
            }
            None => marshal_helper(&Option::<TpmiAlgKdf>::None, dst, 0),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtKdfScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector: Option<TpmiAlgKdf> = Unmarshal::unmarshal(src)?;
        match selector {
            Some(TpmiAlgKdf::Mgf1) => Ok(Some(TpmtKdfScheme::Mgf1(Unmarshal::unmarshal(src)?))),
            Some(TpmiAlgKdf::Hkdf) => Ok(Some(TpmtKdfScheme::Hkdf(Unmarshal::unmarshal(src)?))),
            Some(TpmiAlgKdf::Kdf1Sp800_56a) => Ok(Some(TpmtKdfScheme::Kdf1Sp800_56a(
                Unmarshal::unmarshal(src)?,
            ))),
            Some(TpmiAlgKdf::Kdf2) => Ok(Some(TpmtKdfScheme::Kdf2(Unmarshal::unmarshal(src)?))),
            Some(TpmiAlgKdf::Kdf1Sp800_108) => Ok(Some(TpmtKdfScheme::Kdf1Sp800_108(
                Unmarshal::unmarshal(src)?,
            ))),
            None => Ok(None),
        }
    }
}

/// `TPMT_PUBLIC_PARMS` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.3.6 (Table 210).
///
/// Tagged structure specifying algorithm parameters for an object type, used in `TPM2_TestParms` to validate parameter sets.
#[doc(alias = "TPMT_PUBLIC_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtPublicParms {
    KeyedHash(Option<TpmtKeyedHashScheme>) = Alg::KEYEDHASH.tag(),
    Sym(TpmtSymDefObject) = Alg::SYMCIPHER.tag(),
    Rsa(TpmsRsaParms) = Alg::RSA.tag(),
    Ecc(TpmsEccParms) = Alg::ECC.tag(),
    Mldsa(TpmsMldsaParms) = Alg::MLDSA.tag(),
    HashMldsa(TpmsHashMldsaParms) = Alg::HASH_MLDSA.tag(),
    Mlkem(TpmsMlkemParms) = Alg::MLKEM.tag(),
}

impl TpmtPublicParms {
    pub const MAX_SHARED_SECRET_BYTES: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;
    pub const MAX_KEM_CIPHERTEXT_BYTES: usize = max(&[
        TpmsEccPoint::MAX_SIZE,
        crate::constants::TPM2_MAX_MLKEM_CT_SIZE,
    ]);
    pub const MAX_ENCRYPTED_SECRET_BYTES: usize = max(&[
        TpmsEccPoint::MAX_SIZE,
        crate::constants::TPM2_MAX_RSA_KEY_BYTES as usize,
        Tpm2bDigest::MAX_SIZE,
    ]);

    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn algorithm(self) -> Alg {
        match self {
            Self::KeyedHash(_) => Alg::KEYEDHASH,
            Self::Sym(_) => Alg::SYMCIPHER,
            Self::Rsa(_) => Alg::RSA,
            Self::Ecc(_) => Alg::ECC,
            Self::Mldsa(_) => Alg::MLDSA,
            Self::HashMldsa(_) => Alg::HASH_MLDSA,
            Self::Mlkem(_) => Alg::MLKEM,
        }
    }
}

impl Marshal for TpmtPublicParms {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + max(&[
            <Option<TpmtKeyedHashScheme>>::MAX_SIZE,
            TpmtSymDefObject::MAX_SIZE,
            TpmsRsaParms::MAX_SIZE,
            TpmsEccParms::MAX_SIZE,
            TpmsMldsaParms::MAX_SIZE,
            TpmsHashMldsaParms::MAX_SIZE,
            TpmsMlkemParms::MAX_SIZE,
        ]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        match self {
            Self::KeyedHash(x) => {
                let count = marshal_helper(&Alg::KEYEDHASH, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Sym(x) => {
                let count = marshal_helper(&Alg::SYMCIPHER, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Rsa(x) => {
                let count = marshal_helper(&Alg::RSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Ecc(x) => {
                let count = marshal_helper(&Alg::ECC, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Mldsa(x) => {
                let count = marshal_helper(&Alg::MLDSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::HashMldsa(x) => {
                let count = marshal_helper(&Alg::HASH_MLDSA, dst, 0);
                marshal_helper(x, dst, count)
            }
            Self::Mlkem(x) => {
                let count = marshal_helper(&Alg::MLKEM, dst, 0);
                marshal_helper(x, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtPublicParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::from(TpmiAlgPublic::unmarshal(src)?);
        match selector {
            Alg::KEYEDHASH => Ok(Self::KeyedHash(Unmarshal::unmarshal(src)?)),
            Alg::SYMCIPHER => Ok(Self::Sym(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "rsa")]
            Alg::RSA => Ok(Self::Rsa(Unmarshal::unmarshal(src)?)),
            #[cfg(feature = "ecc")]
            Alg::ECC => Ok(Self::Ecc(Unmarshal::unmarshal(src)?)),
            Alg::MLDSA => Ok(Self::Mldsa(Unmarshal::unmarshal(src)?)),
            Alg::HASH_MLDSA => Ok(Self::HashMldsa(Unmarshal::unmarshal(src)?)),
            Alg::MLKEM => Ok(Self::Mlkem(Unmarshal::unmarshal(src)?)),
            _ => Err(UnmarshalError::TYPE),
        }
    }
}

impl Default for TpmtPublicParms {
    fn default() -> Self {
        Self::KeyedHash(None)
    }
}

/// Common trait for all `TpmtTk*` ticket types.
pub trait Ticket {
    fn tag(&self) -> TpmSt;
    fn hierarchy(&self) -> Handle;
    fn digest(&self) -> Tpm2bDigest<'_>;
}

/// `TPMT_TK_CREATION` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.5 (Table 104).
///
/// Creation ticket produced by `TPM2_Create` or `TPM2_CreatePrimary` to prove that a creation digest was produced by the TPM.
#[doc(alias = "TPMT_TK_CREATION")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtTkCreation<'a> {
    Creation(Handle, Tpm2bDigest<'a>) = TpmSt::CREATION.tag(),
}

impl<'a> TpmtTkCreation<'a> {
    pub const fn new(hierarchy: Handle, digest: Tpm2bDigest<'a>) -> Self {
        Self::Creation(hierarchy, digest)
    }

    pub const fn tag(&self) -> u16 {
        match self {
            Self::Creation(..) => TpmSt::CREATION.id(),
        }
    }

    pub const fn hierarchy(&self) -> Handle {
        match self {
            Self::Creation(hierarchy, _) => *hierarchy,
        }
    }

    pub const fn digest(&self) -> &Tpm2bDigest<'a> {
        match self {
            Self::Creation(_, digest) => digest,
        }
    }
}

impl Ticket for TpmtTkCreation<'_> {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Creation(..) => TpmSt::CREATION,
        }
    }

    fn hierarchy(&self) -> Handle {
        self.hierarchy()
    }

    fn digest(&self) -> Tpm2bDigest<'_> {
        *self.digest()
    }
}

impl Marshal for TpmtTkCreation<'_> {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmtTkCreation::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtTkCreation::MAX_SIZE]) -> usize {
        let Self::Creation(hierarchy, digest) = self;
        let count = marshal_helper(&TpmSt::CREATION.id(), dst, 0);
        let count = marshal_helper(hierarchy, dst, count);
        marshal_helper(digest, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtTkCreation<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let tag = u16::unmarshal(src)?;
        if tag != TpmSt::CREATION.id() {
            return Err(UnmarshalError::TAG);
        }
        let hierarchy = TpmiRhHierarchy::unmarshal(src)?.0;
        let digest = Tpm2bDigest::unmarshal(src)?;
        Ok(Self::Creation(hierarchy, digest))
    }
}

impl Default for TpmtTkCreation<'_> {
    fn default() -> Self {
        Self::Creation(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_TK_AUTH` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.7 (Table 106).
///
/// Authorization ticket produced by `TPM2_PolicySigned` or `TPM2_PolicySecret` when authorization has an expiration time.
#[doc(alias = "TPMT_TK_AUTH")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtTkAuth<'a> {
    Signed(Handle, Tpm2bDigest<'a>) = TpmSt::AUTH_SIGNED.tag(),
    Secret(Handle, Tpm2bDigest<'a>) = TpmSt::AUTH_SECRET.tag(),
}

impl<'a> TpmtTkAuth<'a> {
    pub const fn tag(&self) -> u16 {
        match self {
            Self::Signed(..) => TpmSt::AUTH_SIGNED.id(),
            Self::Secret(..) => TpmSt::AUTH_SECRET.id(),
        }
    }

    pub const fn hierarchy(&self) -> Handle {
        match self {
            Self::Signed(hierarchy, _) | Self::Secret(hierarchy, _) => *hierarchy,
        }
    }

    pub const fn digest(&self) -> &Tpm2bDigest<'a> {
        match self {
            Self::Signed(_, digest) | Self::Secret(_, digest) => digest,
        }
    }
}

impl Ticket for TpmtTkAuth<'_> {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Signed(..) => TpmSt::AUTH_SIGNED,
            Self::Secret(..) => TpmSt::AUTH_SECRET,
        }
    }

    fn hierarchy(&self) -> Handle {
        self.hierarchy()
    }

    fn digest(&self) -> Tpm2bDigest<'_> {
        *self.digest()
    }
}

impl Marshal for TpmtTkAuth<'_> {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmtTkAuth::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtTkAuth::MAX_SIZE]) -> usize {
        let (tag, hierarchy, digest) = match self {
            Self::Signed(h, d) => (TpmSt::AUTH_SIGNED.id(), h, d),
            Self::Secret(h, d) => (TpmSt::AUTH_SECRET.id(), h, d),
        };
        let count = marshal_helper(&tag, dst, 0);
        let count = marshal_helper(hierarchy, dst, count);
        marshal_helper(digest, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtTkAuth<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let tag = u16::unmarshal(src)?;
        if tag != TpmSt::AUTH_SIGNED.id() && tag != TpmSt::AUTH_SECRET.id() {
            return Err(UnmarshalError::TAG);
        }
        let hierarchy = TpmiRhHierarchy::unmarshal(src)?.0;
        let digest = Tpm2bDigest::unmarshal(src)?;
        if tag == TpmSt::AUTH_SIGNED.id() {
            Ok(Self::Signed(hierarchy, digest))
        } else {
            Ok(Self::Secret(hierarchy, digest))
        }
    }
}

/// `TPMT_TK_VERIFIED` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.6 (Table 105).
///
/// Verification ticket produced by `TPM2_VerifySignature`, `TPM2_VerifySequenceComplete`, or
/// `TPM2_VerifyDigestSignature` proving that a signature was verified by the TPM.
#[doc(alias = "TPMT_TK_VERIFIED")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtTkVerified<'a> {
    Verified(Handle, Tpm2bDigest<'a>) = TpmSt::VERIFIED.tag(),
    MessageVerified(Handle, Tpm2bDigest<'a>) = TpmSt::MESSAGE_VERIFIED.tag(),
    DigestVerified(Handle, TpmiAlgHash, Tpm2bDigest<'a>) = TpmSt::DIGEST_VERIFIED.tag(),
}

impl<'a> TpmtTkVerified<'a> {
    pub const fn new(hierarchy: Handle, digest: Tpm2bDigest<'a>) -> Self {
        Self::Verified(hierarchy, digest)
    }

    pub const fn new_message_verified(hierarchy: Handle, digest: Tpm2bDigest<'a>) -> Self {
        Self::MessageVerified(hierarchy, digest)
    }

    pub const fn new_digest_verified(
        hierarchy: Handle,
        digest_verified: TpmiAlgHash,
        digest: Tpm2bDigest<'a>,
    ) -> Self {
        Self::DigestVerified(hierarchy, digest_verified, digest)
    }

    pub const fn tag(&self) -> u16 {
        match self {
            Self::Verified(..) => TpmSt::VERIFIED.id(),
            Self::MessageVerified(..) => TpmSt::MESSAGE_VERIFIED.id(),
            Self::DigestVerified(..) => TpmSt::DIGEST_VERIFIED.id(),
        }
    }

    pub const fn hierarchy(&self) -> Handle {
        match self {
            Self::Verified(hierarchy, _)
            | Self::MessageVerified(hierarchy, _)
            | Self::DigestVerified(hierarchy, _, _) => *hierarchy,
        }
    }

    pub const fn metadata(&self) -> TpmuTkVerifiedMeta {
        match self {
            Self::Verified(..) => TpmuTkVerifiedMeta::Verified,
            Self::MessageVerified(..) => TpmuTkVerifiedMeta::MessageVerified,
            Self::DigestVerified(_, alg, _) => TpmuTkVerifiedMeta::DigestVerified(*alg),
        }
    }

    pub const fn digest(&self) -> &Tpm2bDigest<'a> {
        match self {
            Self::Verified(_, digest)
            | Self::MessageVerified(_, digest)
            | Self::DigestVerified(_, _, digest) => digest,
        }
    }

    pub const fn hmac(&self) -> &Tpm2bDigest<'a> {
        self.digest()
    }
}

impl Ticket for TpmtTkVerified<'_> {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Verified(..) => TpmSt::VERIFIED,
            Self::MessageVerified(..) => TpmSt::MESSAGE_VERIFIED,
            Self::DigestVerified(..) => TpmSt::DIGEST_VERIFIED,
        }
    }

    fn hierarchy(&self) -> Handle {
        self.hierarchy()
    }

    fn digest(&self) -> Tpm2bDigest<'_> {
        *self.digest()
    }
}

impl Marshal for TpmtTkVerified<'_> {
    const MAX_SIZE: usize =
        TpmSt::MAX_SIZE + Handle::MAX_SIZE + TpmiAlgHash::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmtTkVerified::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtTkVerified::MAX_SIZE]) -> usize {
        match self {
            Self::Verified(hierarchy, digest) => {
                let count = marshal_helper(&TpmSt::VERIFIED.id(), dst, 0);
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
            Self::MessageVerified(hierarchy, digest) => {
                let count = marshal_helper(&TpmSt::MESSAGE_VERIFIED.id(), dst, 0);
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
            Self::DigestVerified(hierarchy, alg, digest) => {
                let count = marshal_helper(&TpmSt::DIGEST_VERIFIED.id(), dst, 0);
                let count = marshal_helper(hierarchy, dst, count);
                let count = marshal_helper(alg, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkVerified<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let tag = u16::unmarshal(src)?;
        if tag != TpmSt::VERIFIED.id()
            && tag != TpmSt::MESSAGE_VERIFIED.id()
            && tag != TpmSt::DIGEST_VERIFIED.id()
        {
            return Err(UnmarshalError::TAG);
        }
        let hierarchy = TpmiRhHierarchy::unmarshal(src)?.0;
        let metadata = TpmuTkVerifiedMeta::unmarshal_variant(TpmSt::new(tag), src)?;
        let digest = Tpm2bDigest::unmarshal(src)?;
        match metadata {
            TpmuTkVerifiedMeta::Verified => Ok(Self::Verified(hierarchy, digest)),
            TpmuTkVerifiedMeta::MessageVerified => Ok(Self::MessageVerified(hierarchy, digest)),
            TpmuTkVerifiedMeta::DigestVerified(alg) => {
                Ok(Self::DigestVerified(hierarchy, alg, digest))
            }
        }
    }
}

impl Default for TpmtTkVerified<'_> {
    fn default() -> Self {
        Self::Verified(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_TK_HASHCHECK` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.8 (Table 107).
///
/// Hash check ticket produced by `TPM2_Hash` or `TPM2_SequenceComplete` proving that a hash digest was computed by the TPM.
#[doc(alias = "TPMT_TK_HASHCHECK")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtTkHashcheck<'a> {
    Hashcheck(Handle, Tpm2bDigest<'a>) = TpmSt::HASHCHECK.tag(),
}

impl<'a> TpmtTkHashcheck<'a> {
    pub const fn new(hierarchy: Handle, digest: Tpm2bDigest<'a>) -> Self {
        Self::Hashcheck(hierarchy, digest)
    }

    pub const fn tag(&self) -> u16 {
        match self {
            Self::Hashcheck(..) => TpmSt::HASHCHECK.id(),
        }
    }

    pub const fn hierarchy(&self) -> Handle {
        match self {
            Self::Hashcheck(hierarchy, _) => *hierarchy,
        }
    }

    pub const fn digest(&self) -> &Tpm2bDigest<'a> {
        match self {
            Self::Hashcheck(_, digest) => digest,
        }
    }
}

impl Ticket for TpmtTkHashcheck<'_> {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Hashcheck(..) => TpmSt::HASHCHECK,
        }
    }

    fn hierarchy(&self) -> Handle {
        self.hierarchy()
    }

    fn digest(&self) -> Tpm2bDigest<'_> {
        *self.digest()
    }
}

impl Marshal for TpmtTkHashcheck<'_> {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmtTkHashcheck::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtTkHashcheck::MAX_SIZE]) -> usize {
        let Self::Hashcheck(hierarchy, digest) = self;
        let count = marshal_helper(&TpmSt::HASHCHECK.id(), dst, 0);
        let count = marshal_helper(hierarchy, dst, count);
        marshal_helper(digest, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtTkHashcheck<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let tag = u16::unmarshal(src)?;
        if tag != TpmSt::HASHCHECK.id() {
            return Err(UnmarshalError::TAG);
        }
        let hierarchy = TpmiRhHierarchy::unmarshal(src)?.0;
        let digest = Tpm2bDigest::unmarshal(src)?;
        Ok(Self::Hashcheck(hierarchy, digest))
    }
}

impl Default for TpmtTkHashcheck<'_> {
    fn default() -> Self {
        Self::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.4 (Table 211).
///
/// Defines the public area of a TPM object (object type, name algorithm, object attributes, auth policy, parameters, and public key data).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmtPublic<'a> {
    pub name_alg: Option<TpmiAlgHash>,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest<'a>,
    pub parms_and_id: PublicParmsAndId<'a>,
}

impl TpmtPublic<'_> {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn algorithm(self) -> Alg {
        self.parms_and_id.algorithm()
    }
    pub const fn parms(self) -> TpmtPublicParms {
        self.parms_and_id.parms()
    }
}

impl Marshal for TpmtPublic<'_> {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + <Option<TpmiAlgHash>>::MAX_SIZE
        + TpmaObject::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + PublicParmsAndId::MAX_SIZE;
    type MaxBuffer = [u8; TpmtPublic::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtPublic::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.parms_and_id.algorithm(), dst, 0);
        let count = marshal_helper(&self.name_alg, dst, count);
        let count = marshal_helper(&self.object_attributes, dst, count);
        let count = marshal_helper(&self.auth_policy, dst, count);
        marshal_helper(&self.parms_and_id, dst, count)
    }
}

impl<'a> TpmtPublic<'a> {
    /// Unmarshals a `TPMT_PUBLIC` structure, optionally allowing `name_alg == TPM_ALG_NULL` (`None`).
    ///
    /// When `allow_null_name_alg` is `false` (standard `TPMT_PUBLIC`, Table 211), `TPM_ALG_NULL` is
    /// rejected with [`UnmarshalError::HASH`]. When `true` (`+TPMT_PUBLIC`), `TPM_ALG_NULL` is
    /// unmarshalled as `None`.
    pub fn unmarshal_with_flag(
        src: &mut &'a [u8],
        allow_null_name_alg: bool,
    ) -> Result<Self, UnmarshalError> {
        let selector = Alg::from(TpmiAlgPublic::unmarshal(src)?);
        let name_alg = if allow_null_name_alg {
            Option::<TpmiAlgHash>::unmarshal(src)?
        } else {
            Some(TpmiAlgHash::unmarshal(src)?)
        };
        Ok(TpmtPublic {
            name_alg,
            object_attributes: Unmarshal::unmarshal(src)?,
            auth_policy: Unmarshal::unmarshal(src)?,
            parms_and_id: PublicParmsAndId::unmarshal_variant(selector, src)?,
        })
    }

    /// Unmarshals a nullable `+TPMT_PUBLIC` structure, permitting `name_alg == TPM_ALG_NULL` (`None`).
    pub fn unmarshal_nullable(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Self::unmarshal_with_flag(src, true)
    }

    /// Unmarshals a `TPMT_PUBLIC` structure from a template (`UnmarshalToPublic` in the TPM 2.0
    /// reference implementation, Part 2 Section 12.2.6 Table 213).
    ///
    /// When `derivation` is `false`, unmarshals a standard `TPMT_PUBLIC` (`name_alg` cannot be
    /// `TPM_ALG_NULL`) and returns `(public_area, None)`.
    /// When `derivation` is `true`, unmarshals `TPMU_PUBLIC_PARMS` followed by `TPMS_DERIVE`
    /// (`label` and `context`) from the `unique` slot and returns `(public_area, Some(derive))`.
    pub fn unmarshal_for_template(
        src: &mut &'a [u8],
        derivation: bool,
    ) -> Result<(Self, Option<TpmsDerive<'a>>), UnmarshalError> {
        if derivation {
            let selector = Alg::from(TpmiAlgPublic::unmarshal(src)?);
            let name_alg = Some(TpmiAlgHash::unmarshal(src)?);
            let object_attributes = TpmaObject::unmarshal(src)?;
            let auth_policy = Tpm2bDigest::unmarshal(src)?;
            let (parms_and_id, derive) =
                PublicParmsAndId::unmarshal_variant_derivation(selector, src)?;
            Ok((
                TpmtPublic {
                    name_alg,
                    object_attributes,
                    auth_policy,
                    parms_and_id,
                },
                Some(derive),
            ))
        } else {
            Ok((Self::unmarshal_with_flag(src, false)?, None))
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtPublic<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Self::unmarshal_with_flag(src, false)
    }
}

/// `TPMT_SENSITIVE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 216).
///
/// Defines the sensitive/private area of a TPM object (sensitive type, auth value, seed value, and private key composite).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmtSensitive<'a> {
    pub auth_value: Tpm2bAuth<'a>,
    pub seed_value: Tpm2bDigest<'a>,
    pub sensitive: TpmuSensitiveComposite<'a>,
}

impl TpmtSensitive<'_> {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn sensitive_type(self) -> Alg {
        self.sensitive.sensitive_type()
    }
}

impl Marshal for TpmtSensitive<'_> {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + Tpm2bAuth::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + TpmuSensitiveComposite::MAX_SIZE;
    type MaxBuffer = [u8; TpmtSensitive::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtSensitive::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.sensitive_type(), dst, 0);
        let count = marshal_helper(&self.auth_value, dst, count);
        let count = marshal_helper(&self.seed_value, dst, count);
        marshal_helper(&self.sensitive, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtSensitive<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::from(TpmiAlgPublic::unmarshal(src)?);
        let auth_value = Unmarshal::unmarshal(src)?;
        let seed_value = Unmarshal::unmarshal(src)?;
        let sensitive = TpmuSensitiveComposite::unmarshal_variant(selector, src)?;
        Ok(Self {
            auth_value,
            seed_value,
            sensitive,
        })
    }
}

impl Default for TpmtSensitive<'_> {
    fn default() -> Self {
        Self {
            auth_value: Default::default(),
            seed_value: Default::default(),
            sensitive: TpmuSensitiveComposite::KeyedHash(Default::default()),
        }
    }
}

/// `TPMT_NV_PUBLIC_2` structure defined in TPM 2.0 Part 2: Structures, Section 13.7 (Table 231).
///
/// Tagged NV Index public area structure containing a [`TpmHt`] handle type selector (`handle_type`)
/// and the corresponding [`TpmuNvPublic2`] public area union (`public_area`).
#[doc(alias = "TPMT_NV_PUBLIC_2")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmtNvPublic2<'a> {
    pub handle_type: TpmHt,
    pub public_area: TpmuNvPublic2<'a>,
}

impl<'a> TpmtNvPublic2<'a> {
    pub const fn new(public_area: TpmuNvPublic2<'a>) -> Self {
        Self {
            handle_type: public_area.handle_type(),
            public_area,
        }
    }

    pub const fn handle_type(&self) -> TpmHt {
        self.handle_type
    }
}

impl Default for TpmtNvPublic2<'_> {
    fn default() -> Self {
        Self {
            handle_type: TpmHt::NVIndex,
            public_area: TpmuNvPublic2::NvIndex(TpmsNvPublic::default()),
        }
    }
}

impl Marshal for TpmtNvPublic2<'_> {
    const MAX_SIZE: usize = TpmHt::MAX_SIZE + TpmuNvPublic2::MAX_SIZE;
    type MaxBuffer = [u8; TpmtNvPublic2::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtNvPublic2::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.handle_type, dst, 0);
        marshal_helper(&self.public_area, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtNvPublic2<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let raw_ht = u8::unmarshal(src)?;
        let handle_type = TpmHt::try_from(raw_ht).map_err(|_| UnmarshalError::SELECTOR)?;
        let public_area = TpmuNvPublic2::unmarshal_variant(handle_type, src)?;
        Ok(Self {
            handle_type,
            public_area,
        })
    }
}
