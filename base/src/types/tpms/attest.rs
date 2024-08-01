// =============================================================================
// USES
// =============================================================================

use crate::types::{TPM2Generated, Tpm2bData, Tpm2bName, TpmsClockInfo, TpmuAttest};
use tpm2_rs_errors::TpmRcResult;
use tpm2_rs_marshal::{Marshalable, MarshalableEnum, UnmarshalBuf};

// =============================================================================
// TYPES
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct TpmsAttest {
    pub magic: TPM2Generated,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: TpmuAttest,
}

// =============================================================================
// TRAITS
// =============================================================================

// Custom overload of Marshalable, because the selector for attested is {un}marshaled separate from the field.
impl Marshalable for TpmsAttest {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
        let mut written = 0;
        written += self.magic.try_marshal(&mut buffer[written..])?;
        written += self
            .attested
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.qualified_signer.try_marshal(&mut buffer[written..])?;
        written += self.extra_data.try_marshal(&mut buffer[written..])?;
        written += self.clock_info.try_marshal(&mut buffer[written..])?;
        written += self.firmware_version.try_marshal(&mut buffer[written..])?;
        written += self.attested.try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
        let magic = TPM2Generated::try_unmarshal(buffer)?;
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmsAttest {
            magic,
            qualified_signer: Tpm2bName::try_unmarshal(buffer)?,
            extra_data: Tpm2bData::try_unmarshal(buffer)?,
            clock_info: TpmsClockInfo::try_unmarshal(buffer)?,
            firmware_version: u64::try_unmarshal(buffer)?,
            attested: TpmuAttest::try_unmarshal_variant(selector, buffer)?,
        })
    }
}
