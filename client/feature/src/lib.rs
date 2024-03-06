#![forbid(unsafe_code)]
use tpm2_rs_base::commands::*;
use tpm2_rs_base::constants::{TPM2Cap, TPM2PT};
use tpm2_rs_base::errors::{TpmRcError, TpmResult};
use tpm2_rs_base::TpmsCapabilityData;
use tpm2_rs_client::*;

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
mod tests {
    use super::*;
    use tpm2_rs_base::constants::{TPM2AlgID, TPM2ST};
    use tpm2_rs_base::marshal::Marshalable;
    use tpm2_rs_base::{
        TpmaAlgorithm, TpmiYesNo, TpmlAlgProperty, TpmlTaggedTpmProperty, TpmsAlgProperty,
        TpmsTaggedProperty,
    };

    struct FakeTpm {
        len: usize,
        response: [u8; RESP_BUFFER_SIZE],
    }
    impl Default for FakeTpm {
        fn default() -> Self {
            FakeTpm {
                len: 0,
                response: [0; RESP_BUFFER_SIZE],
            }
        }
    }
    impl Tpm for FakeTpm {
        fn transact(&mut self, _: &[u8], response: &mut [u8]) -> TpmResult<()> {
            let mut tx_header = RespHeader {
                tag: TPM2ST::NoSessions,
                size: 0,
                rc: 0,
            };
            let off = tx_header.try_marshal(response)?;
            let length = off + self.len;
            if length > response.len() {
                return Err(TpmRcError::Size.into());
            }
            response[off..length].copy_from_slice(&self.response[..self.len]);
            tx_header.size = length as u32;
            tx_header.try_marshal(response)?;
            Ok(())
        }
    }

    #[test]
    fn test_get_manufacturer_too_many_properties() {
        let response = GetCapabilityResp {
            more_data: TpmiYesNo::NO,
            capability_data: TpmsCapabilityData::TpmProperties(
                TpmlTaggedTpmProperty::new(
                    &[TpmsTaggedProperty {
                        property: TPM2PT::Manufacturer,
                        value: 4,
                    }; 6],
                )
                .unwrap(),
            ),
        };
        let mut tpm = FakeTpm::default();
        tpm.len = response.try_marshal(&mut tpm.response).unwrap();

        assert_eq!(get_manufacturer_id(&mut tpm), Err(TpmRcError::Size.into()));
    }

    #[test]
    fn test_get_manufacturer_wrong_type_properties() {
        let response = GetCapabilityResp {
            more_data: TpmiYesNo::NO,
            capability_data: TpmsCapabilityData::Algorithms(
                TpmlAlgProperty::new(&[TpmsAlgProperty {
                    alg: TPM2AlgID::SHA256,
                    alg_properties: TpmaAlgorithm::empty(),
                }])
                .unwrap(),
            ),
        };
        let mut tpm = FakeTpm::default();
        tpm.len = response.try_marshal(&mut tpm.response).unwrap();

        assert_eq!(
            get_manufacturer_id(&mut tpm),
            Err(TpmRcError::Selector.into())
        );
    }
}
