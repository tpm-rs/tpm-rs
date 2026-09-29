use crate::{
    errors::UnmarshalError,
    marshal::{marshal_helper, max},
    *,
};

/// `TPMU_ATTEST` union structure defined in TPM 2.0 Part 2: Structures, Section 10.4.23 (Table 142).
///
/// Union of attestation structures (`TPMS_CERTIFY_INFO`, `TPMS_CREATION_INFO`, `TPMS_QUOTE_INFO`,
/// `TPMS_COMMAND_AUDIT_INFO`, `TPMS_SESSION_AUDIT_INFO`, `TPMS_TIME_ATTEST_INFO`, `TPMS_NV_CERTIFY_INFO`,
/// `TPMS_NV_DIGEST_CERTIFY_INFO`), selected by a `TPMI_ST_ATTEST` structure tag inside `TPMS_ATTEST`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmuAttest<'a> {
    Certify(TpmsCertifyInfo<'a>) = TpmSt::ATTEST_CERTIFY.id(),
    Creation(TpmsCreationInfo<'a>) = TpmSt::ATTEST_CREATION.id(),
    Quote(TpmsQuoteInfo<'a>) = TpmSt::ATTEST_QUOTE.id(),
    CommandAudit(TpmsCommandAuditInfo<'a>) = TpmSt::ATTEST_COMMAND_AUDIT.id(),
    SessionAudit(TpmsSessionAuditInfo<'a>) = TpmSt::ATTEST_SESSION_AUDIT.id(),
    Time(TpmsTimeAttestInfo) = TpmSt::ATTEST_TIME.id(),
    Nv(TpmsNvCertifyInfo<'a>) = TpmSt::ATTEST_NV.id(),
    NvDigest(TpmsNvDigestCertifyInfo<'a>) = TpmSt::ATTEST_NV_DIGEST.id(),
}

impl TpmuAttest<'_> {
    #[doc(alias = "TPMI_ST_ATTEST")]
    pub fn attested_type(&self) -> TpmSt {
        match self {
            Self::Certify(_) => TpmSt::ATTEST_CERTIFY,
            Self::Creation(_) => TpmSt::ATTEST_CREATION,
            Self::Quote(_) => TpmSt::ATTEST_QUOTE,
            Self::CommandAudit(_) => TpmSt::ATTEST_COMMAND_AUDIT,
            Self::SessionAudit(_) => TpmSt::ATTEST_SESSION_AUDIT,
            Self::Time(_) => TpmSt::ATTEST_TIME,
            Self::Nv(_) => TpmSt::ATTEST_NV,
            Self::NvDigest(_) => TpmSt::ATTEST_NV_DIGEST,
        }
    }
}

impl Marshal for TpmuAttest<'_> {
    const MAX_SIZE: usize = max(&[
        TpmsCertifyInfo::MAX_SIZE,
        TpmsCreationInfo::MAX_SIZE,
        TpmsQuoteInfo::MAX_SIZE,
        TpmsCommandAuditInfo::MAX_SIZE,
        TpmsSessionAuditInfo::MAX_SIZE,
        TpmsTimeAttestInfo::MAX_SIZE,
        TpmsNvCertifyInfo::MAX_SIZE,
        TpmsNvDigestCertifyInfo::MAX_SIZE,
    ]);
    type MaxBuffer = [u8; TpmuAttest::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmuAttest::MAX_SIZE]) -> usize {
        match self {
            Self::Certify(x) => marshal_helper(x, dst, 0),
            Self::Creation(x) => marshal_helper(x, dst, 0),
            Self::Quote(x) => marshal_helper(x, dst, 0),
            Self::CommandAudit(x) => marshal_helper(x, dst, 0),
            Self::SessionAudit(x) => marshal_helper(x, dst, 0),
            Self::Time(x) => marshal_helper(x, dst, 0),
            Self::Nv(x) => marshal_helper(x, dst, 0),
            Self::NvDigest(x) => marshal_helper(x, dst, 0),
        }
    }
}

impl<'a> TpmuAttest<'a> {
    pub fn unmarshal_variant(selector: TpmSt, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match selector {
            TpmSt::ATTEST_CERTIFY => Ok(Self::Certify(TpmsCertifyInfo::unmarshal(src)?)),
            TpmSt::ATTEST_CREATION => Ok(Self::Creation(TpmsCreationInfo::unmarshal(src)?)),
            TpmSt::ATTEST_QUOTE => Ok(Self::Quote(TpmsQuoteInfo::unmarshal(src)?)),
            TpmSt::ATTEST_COMMAND_AUDIT => {
                Ok(Self::CommandAudit(TpmsCommandAuditInfo::unmarshal(src)?))
            }
            TpmSt::ATTEST_SESSION_AUDIT => {
                Ok(Self::SessionAudit(TpmsSessionAuditInfo::unmarshal(src)?))
            }
            TpmSt::ATTEST_TIME => Ok(Self::Time(TpmsTimeAttestInfo::unmarshal(src)?)),
            TpmSt::ATTEST_NV => Ok(Self::Nv(TpmsNvCertifyInfo::unmarshal(src)?)),
            TpmSt::ATTEST_NV_DIGEST => Ok(Self::NvDigest(TpmsNvDigestCertifyInfo::unmarshal(src)?)),
            _ => Err(UnmarshalError::SELECTOR),
        }
    }
}

/// `TPMU_SENSITIVE_COMPOSITE` union structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 215).
///
/// Union of sensitive private key or data components inside `TPMT_SENSITIVE`, selected by object type
/// (RSA private key, ECC private key parameter, symmetric key, or keyedhash data).
#[doc(alias = "TPMU_SENSITIVE_COMPOSITE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmuSensitiveComposite<'a> {
    KeyedHash(Tpm2bSensitiveData<'a>) = Alg::KEYEDHASH.id(),
    Sym(Tpm2bSymKey<'a>) = Alg::SYMCIPHER.id(),
    Rsa(Tpm2bPrivateKeyRsa<'a>) = Alg::RSA.id(),
    Ecc(Tpm2bEccParameter<'a>) = Alg::ECC.id(),
    Mldsa(Tpm2bPrivateKeyMldsa<'a>) = Alg::MLDSA.id(),
    HashMldsa(Tpm2bPrivateKeyMldsa<'a>) = Alg::HASH_MLDSA.id(),
    Mlkem(Tpm2bPrivateKeyMlkem<'a>) = Alg::MLKEM.id(),
}

impl TpmuSensitiveComposite<'_> {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn sensitive_type(self) -> Alg {
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

impl Marshal for TpmuSensitiveComposite<'_> {
    const MAX_SIZE: usize = max(&[
        Tpm2bPrivateKeyRsa::MAX_SIZE,
        Tpm2bEccParameter::MAX_SIZE,
        Tpm2bSensitiveData::MAX_SIZE,
        Tpm2bSymKey::MAX_SIZE,
        Tpm2bPrivateKeyMldsa::MAX_SIZE,
        Tpm2bPrivateKeyMlkem::MAX_SIZE,
    ]);
    type MaxBuffer = [u8; TpmuSensitiveComposite::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmuSensitiveComposite::MAX_SIZE]) -> usize {
        match self {
            Self::Rsa(x) => marshal_helper(x, dst, 0),
            Self::Ecc(x) => marshal_helper(x, dst, 0),
            Self::KeyedHash(x) => marshal_helper(x, dst, 0),
            Self::Sym(x) => marshal_helper(x, dst, 0),
            Self::Mldsa(x) | Self::HashMldsa(x) => marshal_helper(x, dst, 0),
            Self::Mlkem(x) => marshal_helper(x, dst, 0),
        }
    }
}

impl<'a> TpmuSensitiveComposite<'a> {
    pub fn unmarshal_variant(selector: Alg, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match selector {
            #[cfg(feature = "rsa")]
            Alg::RSA => Ok(Self::Rsa(Tpm2bPrivateKeyRsa::unmarshal(src)?)),
            #[cfg(feature = "ecc")]
            Alg::ECC => Ok(Self::Ecc(Tpm2bEccParameter::unmarshal(src)?)),
            Alg::KEYEDHASH => Ok(Self::KeyedHash(Tpm2bSensitiveData::unmarshal(src)?)),
            Alg::SYMCIPHER => Ok(Self::Sym(Tpm2bSymKey::unmarshal(src)?)),
            Alg::MLDSA => Ok(Self::Mldsa(Tpm2bPrivateKeyMldsa::unmarshal(src)?)),
            Alg::HASH_MLDSA => Ok(Self::HashMldsa(Tpm2bPrivateKeyMldsa::unmarshal(src)?)),
            Alg::MLKEM => Ok(Self::Mlkem(Tpm2bPrivateKeyMlkem::unmarshal(src)?)),
            _ => Err(UnmarshalError::SELECTOR),
        }
    }
}

/// `TPMU_PUBLIC_PARMS` union defined in TPM 2.0 Part 2: Structures, Section 12.2.3.7 (Table 209).
pub type TpmuPublicParms = TpmtPublicParms;

/// `TPMU_PUBLIC_ID` union defined in TPM 2.0 Part 2: Structures, Section 12.2.3.2 (Table 204).
///
/// Union of object unique identifiers selected by object `type` (`TPMI_ALG_PUBLIC`).
#[doc(alias = "TPMU_PUBLIC_ID")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmuPublicId<'a> {
    KeyedHash(Tpm2bDigest<'a>) = Alg::KEYEDHASH.tag(),
    Sym(Tpm2bDigest<'a>) = Alg::SYMCIPHER.tag(),
    Rsa(Tpm2bPublicKeyRsa<'a>) = Alg::RSA.tag(),
    Ecc(TpmsEccPoint<'a>) = Alg::ECC.tag(),
    Mldsa(Tpm2bPublicKeyMldsa<'a>) = Alg::MLDSA.tag(),
    HashMldsa(Tpm2bPublicKeyMldsa<'a>) = Alg::HASH_MLDSA.tag(),
    Mlkem(Tpm2bPublicKeyMlkem<'a>) = Alg::MLKEM.tag(),
}

impl<'a> TpmuPublicId<'a> {
    pub fn unmarshal_variant(selector: Alg, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
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
            _ => Err(UnmarshalError::SELECTOR),
        }
    }
}

impl Marshal for TpmuPublicId<'_> {
    const MAX_SIZE: usize = max(&[
        Tpm2bDigest::MAX_SIZE,
        Tpm2bPublicKeyRsa::MAX_SIZE,
        TpmsEccPoint::MAX_SIZE,
        Tpm2bPublicKeyMldsa::MAX_SIZE,
        Tpm2bPublicKeyMlkem::MAX_SIZE,
    ]);
    type MaxBuffer = [u8; TpmuPublicId::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmuPublicId::MAX_SIZE]) -> usize {
        match self {
            Self::KeyedHash(id) | Self::Sym(id) => marshal_helper(id, dst, 0),
            Self::Rsa(id) => marshal_helper(id, dst, 0),
            Self::Ecc(point) => marshal_helper(point, dst, 0),
            Self::Mldsa(id) | Self::HashMldsa(id) => marshal_helper(id, dst, 0),
            Self::Mlkem(id) => marshal_helper(id, dst, 0),
        }
    }
}

/// Internal union representing public object parameters (`TPMU_PUBLIC_PARMS`) and unique identifier (`TPMU_PUBLIC_ID`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum PublicParmsAndId<'a> {
    KeyedHash(Option<TpmtKeyedHashScheme>, Tpm2bDigest<'a>) = Alg::KEYEDHASH.tag(),
    Sym(TpmtSymDefObject, Tpm2bDigest<'a>) = Alg::SYMCIPHER.tag(),
    Rsa(TpmsRsaParms, Tpm2bPublicKeyRsa<'a>) = Alg::RSA.tag(),
    Ecc(TpmsEccParms, TpmsEccPoint<'a>) = Alg::ECC.tag(),
    Mldsa(TpmsMldsaParms, Tpm2bPublicKeyMldsa<'a>) = Alg::MLDSA.tag(),
    HashMldsa(TpmsHashMldsaParms, Tpm2bPublicKeyMldsa<'a>) = Alg::HASH_MLDSA.tag(),
    Mlkem(TpmsMlkemParms, Tpm2bPublicKeyMlkem<'a>) = Alg::MLKEM.tag(),
}

impl PublicParmsAndId<'_> {
    pub const fn parms(self) -> TpmtPublicParms {
        match self {
            Self::KeyedHash(p, _) => TpmtPublicParms::KeyedHash(p),
            Self::Sym(p, _) => TpmtPublicParms::Sym(p),
            Self::Rsa(p, _) => TpmtPublicParms::Rsa(p),
            Self::Ecc(p, _) => TpmtPublicParms::Ecc(p),
            Self::Mldsa(p, _) => TpmtPublicParms::Mldsa(p),
            Self::HashMldsa(p, _) => TpmtPublicParms::HashMldsa(p),
            Self::Mlkem(p, _) => TpmtPublicParms::Mlkem(p),
        }
    }

    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn algorithm(self) -> Alg {
        self.parms().algorithm()
    }
}

impl<'a> PublicParmsAndId<'a> {
    pub const fn public_id(self) -> TpmuPublicId<'a> {
        match self {
            Self::KeyedHash(_, id) => TpmuPublicId::KeyedHash(id),
            Self::Sym(_, id) => TpmuPublicId::Sym(id),
            Self::Rsa(_, id) => TpmuPublicId::Rsa(id),
            Self::Ecc(_, point) => TpmuPublicId::Ecc(point),
            Self::Mldsa(_, id) => TpmuPublicId::Mldsa(id),
            Self::HashMldsa(_, id) => TpmuPublicId::HashMldsa(id),
            Self::Mlkem(_, id) => TpmuPublicId::Mlkem(id),
        }
    }

    pub fn unmarshal_variant(selector: Alg, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match selector {
            Alg::KEYEDHASH => Ok(Self::KeyedHash(
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
            )),
            Alg::SYMCIPHER => Ok(Self::Sym(
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
            )),
            #[cfg(feature = "rsa")]
            Alg::RSA => Ok(Self::Rsa(
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
            )),
            #[cfg(feature = "ecc")]
            Alg::ECC => Ok(Self::Ecc(
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
            )),
            Alg::MLDSA => Ok(Self::Mldsa(
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
            )),
            Alg::HASH_MLDSA => Ok(Self::HashMldsa(
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
            )),
            Alg::MLKEM => Ok(Self::Mlkem(
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
            )),
            _ => Err(UnmarshalError::SELECTOR),
        }
    }

    /// Unmarshals public parameters (`TPMU_PUBLIC_PARMS`) and a `TPMS_DERIVE` (`label` and `context`)
    /// from `src` for derivation parent templates (`TPM2_CreateLoaded` when `derivation` is true).
    ///
    /// Returns a `PublicParmsAndId` with default (empty) unique identifier along with the unmarshaled `TpmsDerive`.
    pub fn unmarshal_variant_derivation(
        selector: Alg,
        src: &mut &'a [u8],
    ) -> Result<(Self, TpmsDerive<'a>), UnmarshalError> {
        let parms_and_id = match selector {
            Alg::KEYEDHASH => Self::KeyedHash(Unmarshal::unmarshal(src)?, Tpm2bDigest::default()),
            Alg::SYMCIPHER => Self::Sym(Unmarshal::unmarshal(src)?, Tpm2bDigest::default()),
            #[cfg(feature = "rsa")]
            Alg::RSA => Self::Rsa(Unmarshal::unmarshal(src)?, Tpm2bPublicKeyRsa::default()),
            #[cfg(feature = "ecc")]
            Alg::ECC => Self::Ecc(Unmarshal::unmarshal(src)?, TpmsEccPoint::default()),
            Alg::MLDSA => Self::Mldsa(Unmarshal::unmarshal(src)?, Tpm2bPublicKeyMldsa::default()),
            Alg::HASH_MLDSA => {
                Self::HashMldsa(Unmarshal::unmarshal(src)?, Tpm2bPublicKeyMldsa::default())
            }
            Alg::MLKEM => Self::Mlkem(Unmarshal::unmarshal(src)?, Tpm2bPublicKeyMlkem::default()),
            _ => return Err(UnmarshalError::SELECTOR),
        };
        let derive = TpmsDerive::unmarshal(src)?;
        Ok((parms_and_id, derive))
    }
}

impl Marshal for PublicParmsAndId<'_> {
    const MAX_SIZE: usize = max(&[
        <Option<TpmtKeyedHashScheme>>::MAX_SIZE
            + max(&[Tpm2bDigest::MAX_SIZE, TpmsDerive::MAX_SIZE]),
        TpmtSymDefObject::MAX_SIZE + max(&[Tpm2bDigest::MAX_SIZE, TpmsDerive::MAX_SIZE]),
        TpmsRsaParms::MAX_SIZE + max(&[Tpm2bPublicKeyRsa::MAX_SIZE, TpmsDerive::MAX_SIZE]),
        TpmsEccParms::MAX_SIZE + max(&[TpmsEccPoint::MAX_SIZE, TpmsDerive::MAX_SIZE]),
        TpmsMldsaParms::MAX_SIZE + max(&[Tpm2bPublicKeyMldsa::MAX_SIZE, TpmsDerive::MAX_SIZE]),
        TpmsHashMldsaParms::MAX_SIZE + max(&[Tpm2bPublicKeyMldsa::MAX_SIZE, TpmsDerive::MAX_SIZE]),
        TpmsMlkemParms::MAX_SIZE + max(&[Tpm2bPublicKeyMlkem::MAX_SIZE, TpmsDerive::MAX_SIZE]),
    ]);
    type MaxBuffer = [u8; PublicParmsAndId::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; PublicParmsAndId::MAX_SIZE]) -> usize {
        match self {
            Self::KeyedHash(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
            Self::Sym(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
            Self::Rsa(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
            Self::Ecc(parms, point) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(point, dst, count)
            }
            Self::Mldsa(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
            Self::HashMldsa(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
            Self::Mlkem(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
        }
    }
}

impl Default for PublicParmsAndId<'_> {
    fn default() -> Self {
        Self::KeyedHash(None, Default::default())
    }
}

/// `TPMU_SET_CAPABILITIES` union structure defined in TPM 2.0 Part 2: Structures, Section 10.6.3 (Table 129).
///
/// Union of settable capability structures inside [`TpmsSetCapabilityData`], selected by a [`TpmCap`] selector.
/// No settable capabilities are currently defined in the base TPM 2.0 specification or C reference implementation;
/// unmarshalling any selector returns [`UnmarshalError::SELECTOR`].
#[doc(alias = "TPMU_SET_CAPABILITIES")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmuSetCapabilities<'a> {
    pub data: &'a [u8],
}

impl<'a> TpmuSetCapabilities<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn unmarshal_variant(
        _selector: TpmCap,
        _src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Err(UnmarshalError::SELECTOR)
    }
}

impl Marshal for TpmuSetCapabilities<'_> {
    const MAX_SIZE: usize = TpmsCapabilityData::MAX_SIZE - TpmCap::MAX_SIZE;
    type MaxBuffer = [u8; TpmuSetCapabilities::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let len = self.data.len().min(Self::MAX_SIZE);
        dst[..len].copy_from_slice(&self.data[..len]);
        len
    }
}

/// `TPMU_NV_PUBLIC_2` union structure defined in TPM 2.0 Part 2: Structures, Section 13.6 (Table 230).
///
/// Union of NV Index public area structures inside [`TpmtNvPublic2`], selected by [`TpmHt`]
/// (`TPM_HT_NV_INDEX`, `TPM_HT_EXTERNAL_NV`, or `TPM_HT_PERMANENT_NV`).
#[doc(alias = "TPMU_NV_PUBLIC_2")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TpmuNvPublic2<'a> {
    NvIndex(TpmsNvPublic<'a>) = TpmHt::NVIndex as u8,
    ExternalNv(TpmsNvPublicExpAttr<'a>) = TpmHt::ExternalNv as u8,
    PermanentNv(TpmsNvPublic<'a>) = TpmHt::PermanentNv as u8,
}

impl TpmuNvPublic2<'_> {
    #[doc(alias = "TPM_HT")]
    pub const fn handle_type(&self) -> TpmHt {
        match self {
            Self::NvIndex(_) => TpmHt::NVIndex,
            Self::ExternalNv(_) => TpmHt::ExternalNv,
            Self::PermanentNv(_) => TpmHt::PermanentNv,
        }
    }
}

impl Default for TpmuNvPublic2<'_> {
    fn default() -> Self {
        Self::NvIndex(TpmsNvPublic::default())
    }
}

impl Marshal for TpmuNvPublic2<'_> {
    const MAX_SIZE: usize = max(&[TpmsNvPublic::MAX_SIZE, TpmsNvPublicExpAttr::MAX_SIZE]);
    type MaxBuffer = [u8; TpmuNvPublic2::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmuNvPublic2::MAX_SIZE]) -> usize {
        match self {
            Self::NvIndex(x) => marshal_helper(x, dst, 0),
            Self::ExternalNv(x) => marshal_helper(x, dst, 0),
            Self::PermanentNv(x) => marshal_helper(x, dst, 0),
        }
    }
}

impl<'a> TpmuNvPublic2<'a> {
    pub fn unmarshal_variant(selector: TpmHt, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match selector {
            TpmHt::NVIndex => Ok(Self::NvIndex(TpmsNvPublic::unmarshal(src)?)),
            TpmHt::ExternalNv => Ok(Self::ExternalNv(TpmsNvPublicExpAttr::unmarshal(src)?)),
            TpmHt::PermanentNv => Ok(Self::PermanentNv(TpmsNvPublic::unmarshal(src)?)),
            _ => Err(UnmarshalError::SELECTOR),
        }
    }
}

/// `TPMU_TK_VERIFIED_META` union structure defined in TPM 2.0 Part 2: Structures, Section 10.4.5 (Table 104).
///
/// Union of additional metadata for a [`TpmtTkVerified`] ticket, selected by a [`TpmSt`] ticket structure tag
/// (`TPM_ST_VERIFIED`, `TPM_ST_MESSAGE_VERIFIED`, or `TPM_ST_DIGEST_VERIFIED`).
#[doc(alias = "TPMU_TK_VERIFIED_META")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u16)]
pub enum TpmuTkVerifiedMeta {
    #[default]
    Verified = TpmSt::VERIFIED.id(),
    MessageVerified = TpmSt::MESSAGE_VERIFIED.id(),
    DigestVerified(TpmiAlgHash) = TpmSt::DIGEST_VERIFIED.id(),
}

impl TpmuTkVerifiedMeta {
    pub const fn tag(&self) -> TpmSt {
        match self {
            Self::Verified => TpmSt::VERIFIED,
            Self::MessageVerified => TpmSt::MESSAGE_VERIFIED,
            Self::DigestVerified(_) => TpmSt::DIGEST_VERIFIED,
        }
    }

    pub fn unmarshal_variant(selector: TpmSt, src: &mut &[u8]) -> Result<Self, UnmarshalError> {
        match selector {
            TpmSt::VERIFIED => Ok(Self::Verified),
            TpmSt::MESSAGE_VERIFIED => Ok(Self::MessageVerified),
            TpmSt::DIGEST_VERIFIED => Ok(Self::DigestVerified(TpmiAlgHash::unmarshal(src)?)),
            _ => Err(UnmarshalError::TAG),
        }
    }
}

impl Marshal for TpmuTkVerifiedMeta {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; TpmuTkVerifiedMeta::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmuTkVerifiedMeta::MAX_SIZE]) -> usize {
        match self {
            Self::Verified | Self::MessageVerified => 0,
            Self::DigestVerified(alg) => marshal_helper(alg, dst, 0),
        }
    }
}
