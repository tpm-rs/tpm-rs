// [TPM2.0 1.83] 9 Start-up
mod startup;
// [TPM2.0 1.83] 10 Testing
mod testing;
// [TPM2.0 1.83] 11 Session Commands
mod session;
// [TPM2.0 1.83] 12 Object Commands
mod object;
// [TPM2.0 1.83] 13 Duplication Commands
mod duplication;
// [TPM2.0 1.83] 14 Asymmetric Primitives
mod asymmetric;
// [TPM2.0 1.83] 15 Symmetric Primitives
mod symmetric;
// [TPM2.0 1.83] 16 Random Number Generator
mod random;
// [TPM2.0 1.83] 17 Hash/HMAC/Event Sequences
mod hash_hmac_event;
// [TPM2.0 1.83] 18 Attestation Commands
mod attestation;
// [TPM2.0 1.83] 19 Ephemeral EC Keys
mod ephemeral;
// [TPM2.0 1.83] 20 Signing and Signature Verification
mod signature;
// [TPM2.0 1.83] 21 Command Audit
mod command_audit;
// [TPM2.0 1.83] 22 Integrity Collection (PCR)
mod pcr;
// [TPM2.0 1.83] 23 Enhanced Authorization (EA) Commands
mod enhanced_auth;
// [TPM2.0 1.83] 24 Hierarchy Commands
mod hierarchy;
// [TPM2.0 1.83] 25 Dictionary Attack Functions
mod dictionary_attack;
// [TPM2.0 1.83] 26 Miscellaneous Management Functions
mod miscellaneous;
// [TPM2.0 1.83] 27 Field Upgrade
mod field_upgrade;
// [TPM2.0 1.83] 28 Context Management
mod context;
// [TPM2.0 1.83] 29 Clocks and Timers, 33 Authenticated Countdown Timer
mod clock_timer;
// [TPM2.0 1.83] 30 Capability Commands
mod capability;
// [TPM2.0 1.83] 31 Non-volatile Storage
mod nv_storage;
// [TPM2.0 1.83] 32 Attached Components
mod attached_components;
// [TPM2.0 1.83] 34 Vendor Specific
mod prelude;
mod vendor;

pub use prelude::*;

use crate::constants::TpmCc;
use crate::Marshalable;

/// Trait for a TPM command transaction.
pub trait TpmCommandProps: Marshalable {
    /// The command code.
    const CMD_CODE: TpmCc;
    /// The command handles type.
    type Handles: Marshalable + Default;
    /// The response parameters type.
    type RespT: Marshalable;
    /// The reponse handles type.
    type RespHandles: Marshalable;
}
