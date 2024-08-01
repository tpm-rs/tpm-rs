// =============================================================================
// USES
// =============================================================================

use crate::types::{
    TPM2AlgID, Tpm2bDigest, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash, TpmsEccParms, TpmsEccPoint,
    TpmsKeyedHashParms, TpmsRsaParms, TpmsSymCipherParms,
};
use tpm2_rs_errors::TpmRcResult;
use tpm2_rs_marshal::{Marshal, Marshalable, MarshalableEnum, UnmarshalBuf};

// =============================================================================
// TYPES
// =============================================================================

// We should probably have a special naming convention.
// TODO: We probably should not have these unnamed structs.
#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum PublicParmsAndId {
    KeyedHash(TpmsKeyedHashParms, Tpm2bDigest) = TPM2AlgID::KeyedHash.0,
    Sym(TpmsSymCipherParms, Tpm2bDigest) = TPM2AlgID::SymCipher.0,
    Rsa(TpmsRsaParms, Tpm2bPublicKeyRsa) = TPM2AlgID::RSA.0,
    Ecc(TpmsEccParms, TpmsEccPoint) = TPM2AlgID::ECC.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmtPublic {
    pub name_alg: TpmiAlgHash,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parms_and_id: PublicParmsAndId,
}

// =============================================================================
// TRAITS
// =============================================================================

// Custom overload of Marshalable, because the selector for parms_and_id is {un}marshaled first.
impl Marshalable for TpmtPublic {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
        let mut written = 0;
        written += self
            .parms_and_id
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.name_alg.try_marshal(&mut buffer[written..])?;
        written += self.object_attributes.try_marshal(&mut buffer[written..])?;
        written += self.auth_policy.try_marshal(&mut buffer[written..])?;
        written += self
            .parms_and_id
            .try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmtPublic {
            name_alg: TpmiAlgHash::try_unmarshal(buffer)?,
            object_attributes: TpmaObject::try_unmarshal(buffer)?,
            auth_policy: Tpm2bDigest::try_unmarshal(buffer)?,
            parms_and_id: PublicParmsAndId::try_unmarshal_variant(selector, buffer)?,
        })
    }
}
