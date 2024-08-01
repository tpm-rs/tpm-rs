#![forbid(unsafe_code)]
use tpm2_rs_base::{
    commands::*,
    types::{TPM2Cap, TpmsCapabilityData, TPM2PT},
};
use tpm2_rs_client::*;
use tpm2_rs_errors::{TpmRcError, TpmResult};

// # Feature Client
//
// The feature client provides higher-level abstractions than the base TPM client.

// Gets the TPM manufacturer ID.
pub fn get_manufacturer_id<T>(tpm: &mut T) -> TpmResult<u32>
where
    T: Tpm,
{
    const CMD: GetCapabilityCmd = GetCapabilityCmd {
        capability: TPM2Cap::TPMProperties,
        property: TPM2PT::Manufacturer,
        property_count: 1,
    };
    let resp = run_command(&CMD, tpm)?;
    if let TpmsCapabilityData::TpmProperties(prop) = resp.capability_data {
        if prop.count() == 1 {
            Ok(prop.tpm_property()[0].value)
        } else {
            Err(TpmRcError::Size.into())
        }
    } else {
        Err(TpmRcError::Selector.into())
    }
}

#[cfg(test)]
mod tests;
