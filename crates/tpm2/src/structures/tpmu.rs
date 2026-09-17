use crate::{
    errors::UnmarshalError,
    marshal::{marshal_helper, max},
    *,
};

/// `TPMU_ATTEST` union structure defined in TPM 2.0 Part 2: Structures, Section 10.4.23 (Table 142).
///
/// Union of attestation structures, selected by a `TPMI_ST_ATTEST` structure
/// tag inside [`TpmsAttest`].
#[doc(alias = "TPMU_ATTEST")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmuAttest<'a> {
    Certify(TpmsCertifyInfo<'a>),
    Creation(TpmsCreationInfo<'a>),
    Quote(TpmsQuoteInfo<'a>),
    CommandAudit(TpmsCommandAuditInfo<'a>),
    SessionAudit(TpmsSessionAuditInfo<'a>),
    Time(TpmsTimeAttestInfo),
    Nv(TpmsNvCertifyInfo<'a>),
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
        }
    }
}
impl<'a> TpmuAttest<'a> {
    pub fn unmarshal_variant(selector: TpmSt, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match selector {
            TpmSt::ATTEST_CERTIFY => Self::Certify(Unmarshal::unmarshal(src)?),
            TpmSt::ATTEST_CREATION => Self::Creation(Unmarshal::unmarshal(src)?),
            TpmSt::ATTEST_QUOTE => Self::Quote(Unmarshal::unmarshal(src)?),
            TpmSt::ATTEST_COMMAND_AUDIT => Self::CommandAudit(Unmarshal::unmarshal(src)?),
            TpmSt::ATTEST_SESSION_AUDIT => Self::SessionAudit(Unmarshal::unmarshal(src)?),
            TpmSt::ATTEST_TIME => Self::Time(Unmarshal::unmarshal(src)?),
            TpmSt::ATTEST_NV => Self::Nv(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        })
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
        }
    }
}

/// `TPMU_SENSITIVE_COMPOSITE` union structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 215).
///
/// Union of sensitive private key or data components inside [`TpmtSensitive`],
/// selected by object type.
#[doc(alias = "TPMU_SENSITIVE_COMPOSITE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmuSensitiveComposite<'a> {
    KeyedHash(Tpm2bSensitiveData<'a>),
    Sym(Tpm2bSymKey<'a>),
    Rsa(Tpm2bPrivateKeyRsa<'a>),
    Ecc(Tpm2bEccParameter<'a>),
}

impl TpmuSensitiveComposite<'_> {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn sensitive_type(self) -> Alg {
        match self {
            Self::KeyedHash(_) => Alg::KEYEDHASH,
            Self::Sym(_) => Alg::SYMCIPHER,
            Self::Rsa(_) => Alg::RSA,
            Self::Ecc(_) => Alg::ECC,
        }
    }
}
impl<'a> TpmuSensitiveComposite<'a> {
    pub fn unmarshal_variant(selector: Alg, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match selector {
            Alg::KEYEDHASH => Self::KeyedHash(Unmarshal::unmarshal(src)?),
            Alg::SYMCIPHER => Self::Sym(Unmarshal::unmarshal(src)?),
            Alg::RSA => Self::Rsa(Unmarshal::unmarshal(src)?),
            Alg::ECC => Self::Ecc(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        })
    }
}

impl Marshal for TpmuSensitiveComposite<'_> {
    const MAX_SIZE: usize = max(&[
        Tpm2bSensitiveData::MAX_SIZE,
        Tpm2bSymKey::MAX_SIZE,
        Tpm2bPrivateKeyRsa::MAX_SIZE,
        Tpm2bEccParameter::MAX_SIZE,
    ]);
    type MaxBuffer = [u8; TpmuSensitiveComposite::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmuSensitiveComposite::MAX_SIZE]) -> usize {
        match self {
            Self::KeyedHash(x) => marshal_helper(x, dst, 0),
            Self::Sym(x) => marshal_helper(x, dst, 0),
            Self::Rsa(x) => marshal_helper(x, dst, 0),
            Self::Ecc(x) => marshal_helper(x, dst, 0),
        }
    }
}
