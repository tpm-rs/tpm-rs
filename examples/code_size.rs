#![no_std]

use tpm2::errors::{MarshalError, UnmarshalError};
use tpm2::marshal::{EccCurves, Limits, Marshal, RsaKeySizes, TpmaHashAlgs, Unmarshal};
use tpm2::{TpmiAlgHash::*, TpmiEccCurve, TpmtHa};

pub struct Small;
impl Limits for Small {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs::from_alg_list(&[Sha256]);
    const RSA_KEY_SIZES: RsaKeySizes = RsaKeySizes::NONE;
    const ECC_CURVES: EccCurves = EccCurves::from_curve_list(&[TpmiEccCurve::NIST_P256]);
}

pub struct Medium;
impl Limits for Medium {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs::from_alg_list(&[Sha1, Sha256]);
    const RSA_KEY_SIZES: RsaKeySizes = RsaKeySizes::from_key_bits_list(&[2048]);
    const ECC_CURVES: EccCurves = EccCurves::from_curve_list(&[
        TpmiEccCurve::NIST_P256,
        TpmiEccCurve::NIST_P384,
        TpmiEccCurve::BN_P256,
    ]);
}

pub struct Large;
impl Limits for Large {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs(u32::MAX);
    const RSA_KEY_SIZES: RsaKeySizes = RsaKeySizes::ALL;
    const ECC_CURVES: EccCurves = EccCurves::ALL;
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
