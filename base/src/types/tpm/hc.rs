// =============================================================================
// USES
// =============================================================================

use crate::{constants::TPM2_MAX_ACTIVE_SESSIONS, types::TPM2HT};
use tpm2_rs_marshal::Marshal;

// =============================================================================
// TYPE
// =============================================================================

/// TpmHc represents a TPM_HC.
/// See definition in Part 2: Structures, section 7.5.
#[derive(Copy, Clone, Debug, Default, Marshal)]
pub struct TpmHc(u32);

// =============================================================================
// IMPLEMENTATIONS
// =============================================================================

#[allow(non_upper_case_globals)]
impl TpmHc {
    /// Masks off the HR.
    const HRHandleMask: u32 = 0x00FFFFFF;
    /// Masks off the variable part.
    const HRRangeMask: u32 = 0xFF000000;
    /// Handle constant shift.
    const HRShift: u32 = 24;

    const fn new(handle_type: TPM2HT) -> TpmHc {
        TpmHc((handle_type.0 as u32) << TpmHc::HRShift)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    /// PCR handle range base.
    const HRPcr: TpmHc = TpmHc::new(TPM2HT::PCR);
    /// HMAC session handle range base.
    const HRHMACSession: TpmHc = TpmHc::new(TPM2HT::HMACSession);
    /// Policy session handle range base.
    const HRPolicySession: TpmHc = TpmHc::new(TPM2HT::PolicySession);
    /// Transient object handle range base.
    const HRTransient: TpmHc = TpmHc::new(TPM2HT::Transient);
    /// Persistent object handle range base.
    const HRPersistent: TpmHc = TpmHc::new(TPM2HT::Persistent);
    /// NV index handle range base.
    const HRNvIndex: TpmHc = TpmHc::new(TPM2HT::NVIndex);
    // TODO: Add remaining values and ranges, some of which are profile-dependent.

    /// The first HMAC session.
    pub const HmacSessionFirst: TpmHc = TpmHc::HRHMACSession;
    /// The last HMAC session.
    pub const HmacSessionLast: TpmHc = TpmHc(TpmHc::HRHMACSession.0 + TPM2_MAX_ACTIVE_SESSIONS - 1);
    /// Returns true if the value is a valid HMAC session handle.
    pub fn is_hmac_session(value: u32) -> bool {
        (TpmHc::HmacSessionFirst.0..=TpmHc::HmacSessionLast.0).contains(&value)
    }
    /// The first policy session.
    pub const PolicySessionFirst: TpmHc = TpmHc::HRPolicySession;
    /// The last policy session.
    pub const PolicySessionLast: TpmHc =
        TpmHc(TpmHc::HRPolicySession.0 + TPM2_MAX_ACTIVE_SESSIONS - 1);
    /// Returns true if the value is a valid policy session handle.
    pub fn is_policy_session(value: u32) -> bool {
        (TpmHc::PolicySessionFirst.0..=TpmHc::PolicySessionLast.0).contains(&value)
    }
    /// The first persistent object.
    pub const PersistentFirst: TpmHc = TpmHc::HRPersistent;
    /// The last persistent object.
    pub const PersistentLast: TpmHc = TpmHc(TpmHc::HRPersistent.0 + 0x00FFFFFF);
    /// The first allowed NV index.
    pub const NVIndexFirst: TpmHc = TpmHc::HRNvIndex;
    /// The last allowed NV index.
    pub const NVIndexLast: TpmHc = TpmHc(TpmHc::NVIndexFirst.0 + 0x00FFFFFF);
    /// Returns true if the value is an allowed NV index.
    pub fn is_nv_index(value: u32) -> bool {
        (TpmHc::NVIndexFirst.0..=TpmHc::NVIndexLast.0).contains(&value)
    }
}
