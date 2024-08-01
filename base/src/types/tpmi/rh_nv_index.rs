// =============================================================================
// USES
// =============================================================================

use crate::types::TpmHc;
use tpm2_rs_errors::TpmRcError;
use tpm2_rs_marshal::Marshal;

// =============================================================================
// TYPES
// =============================================================================

/// TpmiRhNvIndex represents an NV location (TPMI_RH_NV_INDEX).
/// See definition in Part 2: Structures, section 9.24.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiRhNvIndex(u32);

// =============================================================================
// TRAITS
// =============================================================================

impl TryFrom<u32> for TpmiRhNvIndex {
    type Error = TpmRcError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if TpmHc::is_nv_index(value) {
            Ok(TpmiRhNvIndex(value))
        } else {
            Err(TpmRcError::Value)
        }
    }
}
