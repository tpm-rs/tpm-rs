//! Types for an Object's Public Area
//!
//!
use crate::{
    Alg, Tpm2bDigest, Tpm2bPublicKeyMldsa, Tpm2bPublicKeyMlkem, Tpm2bPublicKeyRsa, TpmaObject,
    TpmiAlgHash, TpmsEccParms, TpmsEccPoint, TpmsHashMldsaParms, TpmsKeyedHashParms,
    TpmsMlkemParms, TpmsRsaParms, TpmsSymCipherParms,
};

/// `TPMT_PUBLIC`
#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TpmtPublic<'a> {
    pub name_alg: Option<TpmiAlgHash>,
    pub object_attriubtes: TpmaObject,
    pub auth_policy: Tpm2bDigest<'a>,
    pub public: Public<'a>,
}

/// `TPMU_PUBLIC_ID`
#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmuPublicId<'a> {
    KeyedHash(Tpm2bDigest<'a>) = Alg::KeyedHash.0,
    SymCipher(Tpm2bDigest<'a>) = Alg::SymCipher.0,
    Rsa(Tpm2bPublicKeyRsa<'a>) = Alg::Rsa.0,
    Ecc(TpmsEccPoint<'a>) = Alg::Ecc.0,
    Mldsa(Tpm2bPublicKeyMldsa<'a>) = Alg::Mldsa.0,
    HashMldsa(Tpm2bPublicKeyMldsa<'a>) = Alg::HashMldsa.0,
    Mlkem(Tpm2bPublicKeyMlkem<'a>) = Alg::Mlkem.0,
}

#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum Public<'a> {
    KeyedHash(TpmsKeyedHashParms, Tpm2bDigest<'a>) = Alg::KeyedHash.0,
    SymCipher(TpmsSymCipherParms, Tpm2bDigest<'a>) = Alg::SymCipher.0,
    Rsa(TpmsRsaParms, Tpm2bPublicKeyRsa<'a>) = Alg::Rsa.0,
    Ecc(TpmsEccParms, TpmsEccPoint<'a>) = Alg::Ecc.0,
    Mldsa(TpmsRsaParms, Tpm2bPublicKeyMldsa<'a>) = Alg::Mldsa.0,
    HashMldsa(TpmsHashMldsaParms, Tpm2bPublicKeyMldsa<'a>) = Alg::HashMldsa.0,
    Mlkem(TpmsMlkemParms, Tpm2bPublicKeyMlkem<'a>) = Alg::Mlkem.0,
}
