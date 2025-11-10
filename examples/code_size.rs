#![no_std]

use tpm2::errors::{MarshalError, UnmarshalError};
use tpm2::marshal::{Limits, Marshal, Unmarshal};
use tpm2::{TpmaHashAlgs, TpmiAlgHash::*, TpmtHa};

pub struct Small;
impl Limits for Small {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs::from_alg(Sha256);
}

pub struct Medium;
impl Limits for Medium {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs::from_algs(&[Sha1, Sha256]);
}

pub struct Large;
impl Limits for Large {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs(!0);
}

pub fn marshal_small(ha: TpmtHa, buf: &mut [u8]) -> Result<(), MarshalError> {
    ha.marshal::<Small>(buf)?;
    Ok(())
}
pub fn marshal_medium(ha: TpmtHa, buf: &mut [u8]) -> Result<(), MarshalError> {
    ha.marshal::<Medium>(buf)?;
    Ok(())
}
pub fn marshal_large(ha: TpmtHa, buf: &mut [u8]) -> Result<(), MarshalError> {
    ha.marshal::<Large>(buf)?;
    Ok(())
}

pub fn unmarshal_small(buf: &[u8]) -> Result<TpmtHa<'_>, UnmarshalError> {
    let mut ha = TpmtHa::Sha256(&[0; Sha256.digest_size()]);
    ha.unmarshal::<Small>(buf)?;
    Ok(ha)
}
pub fn unmarshal_medium(buf: &[u8]) -> Result<TpmtHa<'_>, UnmarshalError> {
    let mut ha = TpmtHa::Sha256(&[0; Sha256.digest_size()]);
    ha.unmarshal::<Medium>(buf)?;
    Ok(ha)
}
pub fn unmarshal_large(buf: &[u8]) -> Result<TpmtHa<'_>, UnmarshalError> {
    let mut ha = TpmtHa::Sha256(&[0; Sha256.digest_size()]);
    ha.unmarshal::<Large>(buf)?;
    Ok(ha)
}

#[inline(never)]
pub fn get_digest(ha: TpmtHa<'_>) -> &[u8] {
    ha.digest()
}
