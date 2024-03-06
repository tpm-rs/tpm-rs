#![forbid(unsafe_code)]
use tpm2_rs_base::constants::{TPM2Cap, TPM2Handle, TPM2PT};
use tpm2_rs_base::errors::{TpmRcError, TpmResult};
use tpm2_rs_base::TpmsCapabilityData;
use tpm2_rs_base::{
    commands::*, Tpm2bAuth, Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
    Tpm2bSimple, Tpm2bStruct, TpmiRhHierarchy, TpmlPcrSelection, TpmsSensitiveCreate, TpmtPublic,
};
use tpm2_rs_client::*;

// # Feature Client
//
// The feature client provides higher-level abstractions than the base TPM client.

pub struct TpmClient<T: Tpm + ?Sized> {
    pub tpm: T,
}

impl<T: Tpm> TpmClient<T> {
    /// Gets the TPM manufacturer ID.
    pub fn get_manufacturer_id(&mut self) -> TpmResult<u32> {
        const CMD: GetCapabilityCmd = GetCapabilityCmd {
            capability: TPM2Cap::TPMProperties,
            property: TPM2PT::Manufacturer,
            property_count: 1,
        };
        let resp = get_capability(&mut self.tpm, &CMD)?;
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

    /// Creates a tpm-held primary key with the specified template and hierarchy.
    pub fn create_primary(
        &mut self,
        hierarchy: TpmiRhHierarchy,
        public: TpmtPublic,
        nonce: Option<&[u8]>,
    ) -> TpmResult<TPM2Handle> {
        let outside_info = if let Some(nonce) = nonce {
            Tpm2bData::from_bytes(nonce)?
        } else {
            Tpm2bData::default()
        };
        let in_sensitive = TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        };
        let in_public = Tpm2bPublic::from_struct(&public)?;
        let cmd = CreatePrimaryCmd {
            in_sensitive: Tpm2bSensitiveCreate::from_struct(&in_sensitive)?,
            in_public,
            outside_info,
            creation_pcr: TpmlPcrSelection::default(),
        };

        let (_, handle) = create_primary(&mut self.tpm, &cmd, hierarchy)?;
        // TODO: (automatically) free handles
        Ok(handle)
    }
}

#[cfg(test)]
mod tests;
