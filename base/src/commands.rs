use crate::constants::TpmCc;
use crate::Marshalable;

// [TPM2.0 1.83] 9 Start-up
mod startup;
pub use startup::*;

// [TPM2.0 1.83] 10 Testing
mod testing;
pub use testing::*;

// [TPM2.0 1.83] 11 Session Commands
mod session;
pub use session::*;

// [TPM2.0 1.83] 12 Object Commands
mod object;
pub use object::*;

// [TPM2.0 1.83] 13 Duplication Commands
mod duplication;
pub use duplication::*;

// [TPM2.0 1.83] 14 Asymmetric Primitives
mod asymmetric;
pub use asymmetric::*;

// [TPM2.0 1.83] 15 Symmetric Primitives
mod symmetric;
pub use symmetric::*;

// [TPM2.0 1.83] 16 Random Number Generator
mod random;
pub use random::*;

// [TPM2.0 1.83] 17 Hash/HMAC/Event Sequences
mod hash_hmac_event;
pub use hash_hmac_event::*;

// [TPM2.0 1.83] 18 Attestation Commands
mod attestation;
pub use attestation::*;

// [TPM2.0 1.83] 19 Ephemeral EC Keys
mod ephemeral;
pub use ephemeral::*;

// [TPM2.0 1.83] 20 Signing and Signature Verification
mod signature;
pub use signature::*;

// [TPM2.0 1.83] 21 Command Audit
mod command_audit;
pub use command_audit::*;

// [TPM2.0 1.83] 22 Integrity Collection (PCR)
mod pcr;
pub use pcr::*;

// [TPM2.0 1.83] 23 Enhanced Authorization (EA) Commands
mod enhanced_auth;
pub use enhanced_auth::*;

// [TPM2.0 1.83] 24 Hierarchy Commands
mod hierarchy;
pub use hierarchy::*;

// [TPM2.0 1.83] 25 Dictionary Attack Functions
mod dictionary_attack;
pub use dictionary_attack::*;

// [TPM2.0 1.83] 26 Miscellaneous Management Functions
mod miscellaneous;
pub use miscellaneous::*;

// [TPM2.0 1.83] 27 Field Upgrade
mod field_upgrade;
pub use field_upgrade::*;

// [TPM2.0 1.83] 28 Context Management
mod context;
pub use context::*;

// [TPM2.0 1.83] 29 Clocks and Timers, 33 Authenticated Countdown Timer
mod clock_timer;
pub use clock_timer::*;

// [TPM2.0 1.83] 30 Capability Commands
mod capability;
pub use capability::*;

// [TPM2.0 1.83] 31 Non-volatile Storage
mod nv_storage;
pub use nv_storage::*;

// [TPM2.0 1.83] 32 Attached Components
mod attached_components;
pub use attached_components::*;

// [TPM2.0 1.83] 34 Vendor Specific
mod vendor;
pub use vendor::*;

/// Trait for a TPM command transaction.
pub trait TpmCommand: Marshalable {
    /// The command code.
    const CMD_CODE: TpmCc;
    /// The command handles type.
    type Handles: Marshalable + Default;
    /// The response parameters type.
    type RespT: Marshalable;
    /// The response handles type.
    type RespHandles: Marshalable;
}
