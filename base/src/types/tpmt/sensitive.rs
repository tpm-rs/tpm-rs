// =============================================================================
// USES
// =============================================================================

use crate::types::{Tpm2bAuth, Tpm2bDigest, TpmuSensitiveComposite};
use tpm2_rs_errors::TpmRcResult;
use tpm2_rs_marshal::{Marshalable, MarshalableEnum, UnmarshalBuf};

// =============================================================================
// TYPES
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmtSensitive {
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TpmuSensitiveComposite,
}

// =============================================================================
// TRAITS
// =============================================================================

// Custom overload of Marshalable, because the selector for sensitive is {un}marshaled first.
impl Marshalable for TpmtSensitive {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
        let mut written = 0;
        written += self
            .sensitive
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.auth_value.try_marshal(&mut buffer[written..])?;
        written += self.seed_value.try_marshal(&mut buffer[written..])?;
        written += self.sensitive.try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmtSensitive {
            auth_value: Tpm2bAuth::try_unmarshal(buffer)?,
            seed_value: Tpm2bDigest::try_unmarshal(buffer)?,
            sensitive: TpmuSensitiveComposite::try_unmarshal_variant(selector, buffer)?,
        })
    }
}
