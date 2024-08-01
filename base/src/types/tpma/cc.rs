// =============================================================================
// USES
// =============================================================================

use super::{get_attribute_field, new_attribute_field, set_attribute_field};
use bitflags::bitflags;
use tpm2_rs_marshal::Marshal;

// =============================================================================
// TYPE
// =============================================================================

/// TpmaCc defines the attributes of a command (TPMA_CC).
/// See definition in Part 2: Structures, section 8.9.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmaCc(pub u32);
bitflags! {
    impl TpmaCc : u32 {
        /// Whether the command may write to NV.
        const NV  = 1 << 22;
        /// Whether the command could flush any number of loaded contexts.
        const EXTENSIVE = 1 << 23;
        /// Whether the conext associated with any transient handle in the command will be flushed when this command completes.
        const FLUSHED = 1 << 24;
        /// Wether there is a handle area in the response.
        const R_HANDLE = 1 << 28;
        /// Whether the command is vendor-specific.
        const V = 1 << 29;
        // See multi-bit fields below.
        const _ = !0;
    }
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl TpmaCc {
    /// Shift for the command index field.
    const COMMAND_INDEX_SHIFT: u32 = 0;
    /// Mask for the command index field.
    const COMMAND_INDEX_MASK: u32 = 0xFFFF;
    /// Shift for the command handles field.
    const C_HANDLES_SHIFT: u32 = 25;
    /// Mask for the command handles field.
    const C_HANDLES_MASK: u32 = 0x7 << TpmaCc::C_HANDLES_SHIFT;

    /// Creates a TpmaCc with the command index field set to the provided value.
    const fn command_index(index: u16) -> TpmaCc {
        TpmaCc(new_attribute_field(
            index as u32,
            Self::COMMAND_INDEX_MASK,
            Self::COMMAND_INDEX_SHIFT,
        ))
    }
    /// Creates a TpmaCc with the command handles field set to the provided value.
    const fn c_handles(count: u32) -> TpmaCc {
        TpmaCc(new_attribute_field(
            count,
            Self::C_HANDLES_MASK,
            Self::C_HANDLES_SHIFT,
        ))
    }

    /// Returns the command being selected.
    fn get_command_index(&self) -> u16 {
        get_attribute_field(self.0, Self::COMMAND_INDEX_MASK, Self::COMMAND_INDEX_SHIFT) as u16
    }
    /// Returns the number of handles in the handle area for this command.
    fn get_c_handles(&self) -> u32 {
        get_attribute_field(self.0, Self::C_HANDLES_MASK, Self::C_HANDLES_SHIFT)
    }

    /// Sets the command being selected.
    fn set_command_index(&mut self, index: u16) {
        self.0 = set_attribute_field(
            self.0,
            index as u32,
            Self::COMMAND_INDEX_MASK,
            Self::COMMAND_INDEX_SHIFT,
        );
    }
    /// Sets the number of handles in the handle area for this command.
    fn set_c_handles(&mut self, count: u32) {
        self.0 = set_attribute_field(self.0, count, Self::C_HANDLES_MASK, Self::C_HANDLES_SHIFT);
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attributes_field() {
        let mut cc = TpmaCc::NV | TpmaCc::FLUSHED | TpmaCc::command_index(0x8);
        assert_eq!(cc.get_command_index(), 0x8);
        cc.set_command_index(0xA0);
        assert_eq!(cc.get_command_index(), 0xA0);

        // Set a field to a value that is wider than the field.
        cc.set_c_handles(0xFFFFFFFF);
        assert_eq!(cc.get_c_handles(), 0x7, "Only the field bits should be set");
        assert_eq!(cc.get_command_index(), 0xA0);
        assert!(cc.contains(TpmaCc::NV));
        assert!((cc & TpmaCc::FLUSHED).0 != 0);
    }
}
