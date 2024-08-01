// =============================================================================
// USES
// =============================================================================

use crate::types::{TPM2Handle, TpmHc};
use tpm2_rs_errors::TpmRcError;
use tpm2_rs_marshal::Marshal;

// =============================================================================
// TYPES
// =============================================================================

/// TpmiShAuthSessions represents handles referring to an authorization session (TPMI_SH_AUTH_SESSION).
/// See definition in Part 2: Structures, section 9.8.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiShAuthSession(u32);

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl TpmiShAuthSession {
    /// A password authorization.
    pub const RS_PW: TpmiShAuthSession = TpmiShAuthSession(TPM2Handle::RSPW.0);
}

// =============================================================================
// TRAITS
// =============================================================================

impl TryFrom<u32> for TpmiShAuthSession {
    type Error = TpmRcError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if TpmHc::is_hmac_session(value)
            || TpmHc::is_policy_session(value)
            || (value == Self::RS_PW.0)
        {
            Ok(TpmiShAuthSession(value))
        } else {
            Err(TpmRcError::Value)
        }
    }
}
