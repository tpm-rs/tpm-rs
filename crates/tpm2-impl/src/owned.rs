//! Owned, fixed-capacity equivalents of borrowed `Tpm2bSized<'a, Tag>` and `TpmtPublic<'a>`
//! structures for persistent state in `tpm2-impl` (`GlobalState`, `TransientObject`, `SessionState`, etc.).

use tpm2::errors::UnmarshalError;
use tpm2::{
    Alg, Handle, Marshal, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bEccParameter, Tpm2bLabel, Tpm2bName, Tpm2bNonce, Tpm2bNvPublic, Tpm2bPrivateKeyMldsa,
    Tpm2bPrivateKeyMlkem, Tpm2bPrivateKeyRsa, Tpm2bPublic, Tpm2bPublicKeyMldsa,
    Tpm2bPublicKeyMlkem, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSized, Tpm2bSymKey, TpmaNv,
    TpmaObject, TpmaSession, TpmiAlgHash, TpmsAuthCommand, TpmsDerive, TpmsEccParms, TpmsEccPoint,
    TpmsHashMldsaParms, TpmsMldsaParms, TpmsMlkemParms, TpmsNvPublic, TpmsRsaParms,
    TpmsSignatureEcc, TpmsSignatureRsa, TpmtKeyedHashScheme, TpmtPublic, TpmtPublicParms,
    TpmtSignature, TpmtSymDefObject, Unmarshal, tags::Tpm2bTag,
};

/// A fixed-capacity owned byte buffer mirroring a `TPM2B` structure (`size: u16` + `[u8; CAP]`).
#[derive(Clone, Copy, Debug)]
pub struct OwnedTpm2b<const CAP: usize> {
    pub size: u16,
    pub buffer: [u8; CAP],
}

impl<const CAP: usize> OwnedTpm2b<CAP> {
    pub const CAP: usize = CAP;

    pub const fn empty() -> Self {
        Self {
            size: 0,
            buffer: [0u8; CAP],
        }
    }

    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > CAP {
            return None;
        }
        let mut buffer = [0u8; CAP];
        buffer[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            size: bytes.len() as u16,
            buffer,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UnmarshalError> {
        Self::new(bytes).ok_or(UnmarshalError::SIZE)
    }

    pub const fn get_size(&self) -> u16 {
        self.size
    }

    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }

    pub fn as_slice(&self) -> &[u8] {
        self.get_buffer()
    }

    pub fn as_tpm2b<Tag: Tpm2bTag>(&self) -> Tpm2bSized<'_, Tag> {
        Tpm2bSized::from_bytes(self.get_buffer()).unwrap()
    }
}

impl<const CAP: usize> Default for OwnedTpm2b<CAP> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const CAP: usize> PartialEq for OwnedTpm2b<CAP> {
    fn eq(&self, other: &Self) -> bool {
        self.get_buffer() == other.get_buffer()
    }
}

impl<const CAP: usize> Eq for OwnedTpm2b<CAP> {}

impl<const CAP: usize, Tag: Tpm2bTag> PartialEq<Tpm2bSized<'_, Tag>> for OwnedTpm2b<CAP> {
    fn eq(&self, other: &Tpm2bSized<'_, Tag>) -> bool {
        self.get_buffer() == other.as_slice()
    }
}

impl<const CAP: usize, Tag: Tpm2bTag> PartialEq<OwnedTpm2b<CAP>> for Tpm2bSized<'_, Tag> {
    fn eq(&self, other: &OwnedTpm2b<CAP>) -> bool {
        self.as_slice() == other.get_buffer()
    }
}

impl<const CAP: usize, Tag: Tpm2bTag> From<Tpm2bSized<'_, Tag>> for OwnedTpm2b<CAP> {
    fn from(val: Tpm2bSized<'_, Tag>) -> Self {
        Self::from_bytes(val.as_slice()).unwrap()
    }
}

impl<const CAP: usize, Tag: Tpm2bTag> From<&Tpm2bSized<'_, Tag>> for OwnedTpm2b<CAP> {
    fn from(val: &Tpm2bSized<'_, Tag>) -> Self {
        Self::from_bytes(val.as_slice()).unwrap()
    }
}

impl<const CAP: usize> AsRef<[u8]> for OwnedTpm2b<CAP> {
    fn as_ref(&self) -> &[u8] {
        self.get_buffer()
    }
}

macro_rules! impl_owned_marshal {
    ($($cap:expr => $max:expr),* $(,)?) => {
        $(
            impl Marshal for OwnedTpm2b<$cap> {
                const MAX_SIZE: usize = $max;
                type MaxBuffer = [u8; $max];

                fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
                    let len = self.size as usize;
                    dst[0..2].copy_from_slice(&self.size.to_be_bytes());
                    dst[2..2 + len].copy_from_slice(&self.buffer[..len]);
                    2 + len
                }
            }
        )*
    };
}

impl_owned_marshal!(
    32 => 34,
    64 => 66,
    66 => 68,
    128 => 130,
    256 => 258,
    512 => 514,
    1568 => 1570,
    2592 => 2594,
);

impl<'a, const CAP: usize> Unmarshal<'a> for OwnedTpm2b<CAP> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let len = u16::unmarshal(src)? as usize;
        if len > CAP {
            return Err(UnmarshalError::SIZE);
        }
        if src.len() < len {
            return Err(UnmarshalError::INSUFFICIENT);
        }
        let mut buffer = [0u8; CAP];
        buffer[..len].copy_from_slice(&src[..len]);
        *src = &src[len..];
        Ok(Self {
            size: len as u16,
            buffer,
        })
    }
}

pub type OwnedDigest = OwnedTpm2b<{ Tpm2bDigest::CAP }>;
pub type OwnedAuth = OwnedTpm2b<{ Tpm2bAuth::CAP }>;
pub type OwnedNonce = OwnedTpm2b<{ Tpm2bNonce::CAP }>;
pub type OwnedName = OwnedTpm2b<{ Tpm2bName::CAP }>;
pub type OwnedData = OwnedTpm2b<{ Tpm2bData::CAP }>;
pub type OwnedLabel = OwnedTpm2b<{ Tpm2bLabel::CAP }>;
pub type OwnedPublicKeyRsa = OwnedTpm2b<{ Tpm2bPublicKeyRsa::CAP }>;
pub type OwnedPrivateKeyRsa = OwnedTpm2b<{ Tpm2bPrivateKeyRsa::CAP }>;
pub type OwnedEccParameter = OwnedTpm2b<{ Tpm2bEccParameter::CAP }>;
pub type OwnedSensitiveData = OwnedTpm2b<{ Tpm2bSensitiveData::CAP }>;
pub type OwnedSymKey = OwnedTpm2b<{ Tpm2bSymKey::CAP }>;
pub type OwnedPublicKeyMldsa = OwnedTpm2b<{ Tpm2bPublicKeyMldsa::CAP }>;
pub type OwnedPrivateKeyMldsa = OwnedTpm2b<{ Tpm2bPrivateKeyMldsa::CAP }>;
pub type OwnedPublicKeyMlkem = OwnedTpm2b<{ Tpm2bPublicKeyMlkem::CAP }>;
pub type OwnedPrivateKeyMlkem = OwnedTpm2b<{ Tpm2bPrivateKeyMlkem::CAP }>;

/// Owned equivalent of `TpmsEccPoint<'a>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnedEccPoint {
    pub x: OwnedEccParameter,
    pub y: OwnedEccParameter,
}

impl OwnedEccPoint {
    pub fn as_tpms(&self) -> TpmsEccPoint<'_> {
        TpmsEccPoint {
            x: self.x.as_tpm2b(),
            y: self.y.as_tpm2b(),
        }
    }
}

impl From<TpmsEccPoint<'_>> for OwnedEccPoint {
    fn from(p: TpmsEccPoint<'_>) -> Self {
        Self {
            x: OwnedEccParameter::from(p.x),
            y: OwnedEccParameter::from(p.y),
        }
    }
}

impl From<&TpmsEccPoint<'_>> for OwnedEccPoint {
    fn from(p: &TpmsEccPoint<'_>) -> Self {
        Self {
            x: OwnedEccParameter::from(&p.x),
            y: OwnedEccParameter::from(&p.y),
        }
    }
}

impl Marshal for OwnedEccPoint {
    const MAX_SIZE: usize = TpmsEccPoint::MAX_SIZE;
    type MaxBuffer = <TpmsEccPoint<'static> as Marshal>::MaxBuffer;

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.as_tpms().marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for OwnedEccPoint {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(TpmsEccPoint::unmarshal(src)?.into())
    }
}

/// Owned equivalent of `TpmsDerive<'a>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnedDerive {
    pub label: OwnedLabel,
    pub context: OwnedLabel,
}

impl OwnedDerive {
    pub fn as_tpms(&self) -> TpmsDerive<'_> {
        TpmsDerive {
            label: self.label.as_tpm2b(),
            context: self.context.as_tpm2b(),
        }
    }
}

impl From<TpmsDerive<'_>> for OwnedDerive {
    fn from(d: TpmsDerive<'_>) -> Self {
        Self {
            label: OwnedLabel::from(d.label),
            context: OwnedLabel::from(d.context),
        }
    }
}

/// Owned equivalent of `PublicParmsAndId<'a>`.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnedPublicParmsAndId {
    KeyedHash(Option<TpmtKeyedHashScheme>, OwnedDigest),
    Sym(TpmtSymDefObject, OwnedDigest),
    Rsa(TpmsRsaParms, OwnedPublicKeyRsa),
    Ecc(TpmsEccParms, OwnedEccPoint),
    Mldsa(TpmsMldsaParms, OwnedPublicKeyMldsa),
    HashMldsa(TpmsHashMldsaParms, OwnedPublicKeyMldsa),
    Mlkem(TpmsMlkemParms, OwnedPublicKeyMlkem),
}

impl Default for OwnedPublicParmsAndId {
    fn default() -> Self {
        Self::KeyedHash(None, OwnedDigest::default())
    }
}

impl OwnedPublicParmsAndId {
    pub const fn parms(&self) -> TpmtPublicParms {
        match self {
            Self::KeyedHash(p, _) => TpmtPublicParms::KeyedHash(*p),
            Self::Sym(p, _) => TpmtPublicParms::Sym(*p),
            Self::Rsa(p, _) => TpmtPublicParms::Rsa(*p),
            Self::Ecc(p, _) => TpmtPublicParms::Ecc(*p),
            Self::Mldsa(p, _) => TpmtPublicParms::Mldsa(*p),
            Self::HashMldsa(p, _) => TpmtPublicParms::HashMldsa(*p),
            Self::Mlkem(p, _) => TpmtPublicParms::Mlkem(*p),
        }
    }

    pub const fn algorithm(&self) -> Alg {
        self.parms().algorithm()
    }

    pub fn as_borrowed(&self) -> PublicParmsAndId<'_> {
        match self {
            Self::KeyedHash(p, u) => PublicParmsAndId::KeyedHash(*p, u.as_tpm2b()),
            Self::Sym(p, u) => PublicParmsAndId::Sym(*p, u.as_tpm2b()),
            Self::Rsa(p, u) => PublicParmsAndId::Rsa(*p, u.as_tpm2b()),
            Self::Ecc(p, u) => PublicParmsAndId::Ecc(*p, u.as_tpms()),
            Self::Mldsa(p, u) => PublicParmsAndId::Mldsa(*p, u.as_tpm2b()),
            Self::HashMldsa(p, u) => PublicParmsAndId::HashMldsa(*p, u.as_tpm2b()),
            Self::Mlkem(p, u) => PublicParmsAndId::Mlkem(*p, u.as_tpm2b()),
        }
    }
}

impl From<PublicParmsAndId<'_>> for OwnedPublicParmsAndId {
    fn from(p: PublicParmsAndId<'_>) -> Self {
        match p {
            PublicParmsAndId::KeyedHash(parms, unique) => {
                Self::KeyedHash(parms, OwnedDigest::from(unique))
            }
            PublicParmsAndId::Sym(parms, unique) => Self::Sym(parms, OwnedDigest::from(unique)),
            PublicParmsAndId::Rsa(parms, unique) => {
                Self::Rsa(parms, OwnedPublicKeyRsa::from(unique))
            }
            PublicParmsAndId::Ecc(parms, unique) => Self::Ecc(parms, OwnedEccPoint::from(unique)),
            PublicParmsAndId::Mldsa(parms, unique) => {
                Self::Mldsa(parms, OwnedPublicKeyMldsa::from(unique))
            }
            PublicParmsAndId::HashMldsa(parms, unique) => {
                Self::HashMldsa(parms, OwnedPublicKeyMldsa::from(unique))
            }
            PublicParmsAndId::Mlkem(parms, unique) => {
                Self::Mlkem(parms, OwnedPublicKeyMlkem::from(unique))
            }
        }
    }
}

impl From<&PublicParmsAndId<'_>> for OwnedPublicParmsAndId {
    fn from(p: &PublicParmsAndId<'_>) -> Self {
        (*p).into()
    }
}

/// Owned equivalent of `TpmtPublic<'a>`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OwnedPublic {
    pub name_alg: Option<TpmiAlgHash>,
    pub object_attributes: TpmaObject,
    pub auth_policy: OwnedDigest,
    pub parms_and_id: OwnedPublicParmsAndId,
}

impl OwnedPublic {
    pub const fn algorithm(&self) -> Alg {
        self.parms_and_id.algorithm()
    }

    pub const fn parms(&self) -> TpmtPublicParms {
        self.parms_and_id.parms()
    }

    pub fn as_tpmt(&self) -> TpmtPublic<'_> {
        TpmtPublic {
            name_alg: self.name_alg,
            object_attributes: self.object_attributes,
            auth_policy: self.auth_policy.as_tpm2b(),
            parms_and_id: self.parms_and_id.as_borrowed(),
        }
    }

    pub fn as_tpm2b(&self) -> Tpm2bPublic<'_> {
        Tpm2b(self.as_tpmt())
    }

    pub fn to_struct(&self) -> Result<TpmtPublic<'_>, UnmarshalError> {
        if self.name_alg.is_none() {
            return Err(UnmarshalError::HASH);
        }
        Ok(self.as_tpmt())
    }

    pub fn to_struct_nullable(&self) -> Result<TpmtPublic<'_>, UnmarshalError> {
        Ok(self.as_tpmt())
    }

    pub fn unmarshal_nullable(src: &mut &[u8]) -> Result<Self, UnmarshalError> {
        Ok(TpmtPublic::unmarshal_nullable(src)?.into())
    }

    pub fn unmarshal_for_template<'a>(
        src: &mut &'a [u8],
        derivation: bool,
    ) -> Result<(Self, Option<TpmsDerive<'a>>), UnmarshalError> {
        let (pub_area, derive) = TpmtPublic::unmarshal_for_template(src, derivation)?;
        Ok((pub_area.into(), derive))
    }
}

impl From<TpmtPublic<'_>> for OwnedPublic {
    fn from(p: TpmtPublic<'_>) -> Self {
        Self {
            name_alg: p.name_alg,
            object_attributes: p.object_attributes,
            auth_policy: OwnedDigest::from(p.auth_policy),
            parms_and_id: OwnedPublicParmsAndId::from(p.parms_and_id),
        }
    }
}

impl From<&TpmtPublic<'_>> for OwnedPublic {
    fn from(p: &TpmtPublic<'_>) -> Self {
        (*p).into()
    }
}

impl Marshal for OwnedPublic {
    const MAX_SIZE: usize = TpmtPublic::MAX_SIZE;
    type MaxBuffer = <TpmtPublic<'static> as Marshal>::MaxBuffer;

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.as_tpmt().marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for OwnedPublic {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(TpmtPublic::unmarshal(src)?.into())
    }
}

/// Owned equivalent of `TpmsAuthCommand<'a>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedAuthCommand {
    pub session_handle: Handle,
    pub nonce: OwnedNonce,
    pub session_attributes: TpmaSession,
    pub hmac: OwnedAuth,
}

impl Default for OwnedAuthCommand {
    fn default() -> Self {
        Self {
            session_handle: Handle::RS_PW,
            nonce: OwnedNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: OwnedAuth::default(),
        }
    }
}

impl OwnedAuthCommand {
    pub fn as_tpms(&self) -> TpmsAuthCommand<'_> {
        TpmsAuthCommand {
            session_handle: self.session_handle,
            nonce: self.nonce.as_tpm2b(),
            session_attributes: self.session_attributes,
            hmac: self.hmac.as_tpm2b(),
        }
    }
}

impl From<TpmsAuthCommand<'_>> for OwnedAuthCommand {
    fn from(a: TpmsAuthCommand<'_>) -> Self {
        Self {
            session_handle: a.session_handle,
            nonce: OwnedNonce::from(a.nonce),
            session_attributes: a.session_attributes,
            hmac: OwnedAuth::from(a.hmac),
        }
    }
}

impl From<&TpmsAuthCommand<'_>> for OwnedAuthCommand {
    fn from(a: &TpmsAuthCommand<'_>) -> Self {
        (*a).into()
    }
}

/// Trait for abstracting over `OwnedAuthCommand` and `TpmsAuthCommand<'_>`.
pub trait AuthCommandLike {
    fn session_handle(&self) -> Handle;
    fn hmac_bytes(&self) -> &[u8];
}

impl AuthCommandLike for OwnedAuthCommand {
    fn session_handle(&self) -> Handle {
        self.session_handle
    }
    fn hmac_bytes(&self) -> &[u8] {
        self.hmac.get_buffer()
    }
}

impl AuthCommandLike for TpmsAuthCommand<'_> {
    fn session_handle(&self) -> Handle {
        self.session_handle
    }
    fn hmac_bytes(&self) -> &[u8] {
        self.hmac.as_slice()
    }
}

impl Marshal for OwnedAuthCommand {
    const MAX_SIZE: usize = TpmsAuthCommand::MAX_SIZE;
    type MaxBuffer = <TpmsAuthCommand<'static> as Marshal>::MaxBuffer;

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.as_tpms().marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for OwnedAuthCommand {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(TpmsAuthCommand::unmarshal(src)?.into())
    }
}

/// Owned equivalent of `TpmtSignature<'a>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedSignature {
    Rsassa {
        hash: TpmiAlgHash,
        sig: OwnedPublicKeyRsa,
    },
    Rsapss {
        hash: TpmiAlgHash,
        sig: OwnedPublicKeyRsa,
    },
    Ecdsa {
        hash: TpmiAlgHash,
        signature_r: OwnedEccParameter,
        signature_s: OwnedEccParameter,
    },
    Ecdaa {
        hash: TpmiAlgHash,
        signature_r: OwnedEccParameter,
        signature_s: OwnedEccParameter,
    },
    Sm2 {
        hash: TpmiAlgHash,
        signature_r: OwnedEccParameter,
        signature_s: OwnedEccParameter,
    },
    Ecschnorr {
        hash: TpmiAlgHash,
        signature_r: OwnedEccParameter,
        signature_s: OwnedEccParameter,
    },
}

impl OwnedSignature {
    pub fn as_tpmt(&self) -> TpmtSignature<'_> {
        match self {
            Self::Rsassa { hash, sig } => TpmtSignature::Rsassa(TpmsSignatureRsa {
                hash: *hash,
                sig: sig.as_tpm2b(),
            }),
            Self::Rsapss { hash, sig } => TpmtSignature::Rsapss(TpmsSignatureRsa {
                hash: *hash,
                sig: sig.as_tpm2b(),
            }),
            Self::Ecdsa {
                hash,
                signature_r,
                signature_s,
            } => TpmtSignature::Ecdsa(TpmsSignatureEcc {
                hash: *hash,
                signature_r: signature_r.as_tpm2b(),
                signature_s: signature_s.as_tpm2b(),
            }),
            Self::Ecdaa {
                hash,
                signature_r,
                signature_s,
            } => TpmtSignature::Ecdaa(TpmsSignatureEcc {
                hash: *hash,
                signature_r: signature_r.as_tpm2b(),
                signature_s: signature_s.as_tpm2b(),
            }),
            Self::Sm2 {
                hash,
                signature_r,
                signature_s,
            } => TpmtSignature::Sm2(TpmsSignatureEcc {
                hash: *hash,
                signature_r: signature_r.as_tpm2b(),
                signature_s: signature_s.as_tpm2b(),
            }),
            Self::Ecschnorr {
                hash,
                signature_r,
                signature_s,
            } => TpmtSignature::Ecschnorr(TpmsSignatureEcc {
                hash: *hash,
                signature_r: signature_r.as_tpm2b(),
                signature_s: signature_s.as_tpm2b(),
            }),
        }
    }
}

/// Owned equivalent of `TpmsNvPublic<'a>`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnedNvPublic {
    pub nv_index: Handle,
    pub name_alg: TpmiAlgHash,
    pub attributes: TpmaNv,
    pub auth_policy: OwnedDigest,
    pub data_size: u16,
}

impl Default for OwnedNvPublic {
    fn default() -> Self {
        Self {
            nv_index: Handle::RH_NULL,
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::empty(),
            auth_policy: OwnedDigest::default(),
            data_size: 0,
        }
    }
}

impl OwnedNvPublic {
    pub fn as_tpms(&self) -> TpmsNvPublic<'_> {
        TpmsNvPublic {
            nv_index: self.nv_index,
            name_alg: self.name_alg,
            attributes: self.attributes,
            auth_policy: self.auth_policy.as_tpm2b(),
            data_size: self.data_size,
        }
    }

    pub fn as_tpm2b(&self) -> Tpm2bNvPublic<'_> {
        Tpm2b(self.as_tpms())
    }
}

impl From<TpmsNvPublic<'_>> for OwnedNvPublic {
    fn from(p: TpmsNvPublic<'_>) -> Self {
        Self {
            nv_index: p.nv_index,
            name_alg: p.name_alg,
            attributes: p.attributes,
            auth_policy: OwnedDigest::from(p.auth_policy),
            data_size: p.data_size,
        }
    }
}
