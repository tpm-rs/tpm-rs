//! [TPM2.0 1.83] 17 Hash/HMAC/Event Sequences

/// [TPM2.0 1.83] 17.2 TPM2_HMAC_Start (Command)
pub struct HmacStartCmd {}

/// [TPM2.0 1.83] 17.3 TPM2_MAC_Start (Command)
pub struct MacStartCmd {}

/// [TPM2.0 1.83] 17.4 TPM2_HashSequenceStart (Command)
pub struct HashSequenceStartCmd {}

/// [TPM2.0 1.83] 17.5 TPM2_SequenceUpdate (Command)
pub struct SequenceUpdateCmd {}

/// [TPM2.0 1.83] 17.6 TPM2_SequenceComplete (Command)
pub struct SequenceCompleteCmd {}

/// [TPM2.0 1.83] 17.7 TPM2_EventSequenceComplete (Command)
pub struct EventSequenceCompleteCmd {}
