// =============================================================================
// USES
// =============================================================================

use bitflags::bitflags;
use tpm2_rs_marshal::Marshal;

// =============================================================================
// TYPE
// =============================================================================

/// TpmaLocality represents the locality attribute (TPMA_LOCALITY).
/// See definition in Part 2: Structures, section 8.5.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmaLocality(pub u8);
bitflags! {
    impl TpmaLocality : u8 {
        const LOC_ZERO = 1 << 0;
        const LOC_ONE = 1 << 1;
        const LOC_TWO = 1 << 2;
        const LOC_THREE = 1 << 3;
        const LOC_FOUR = 1 << 4;
        // If any other bits are set, an extended locality is indicated.
        const _ = !0;
    }
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl TpmaLocality {
    const EXTENDED_LOCALITY_MASK: u8 = 0xE0;
    /// Returns whether this attribute indicates an extended locality.
    fn is_extended(&self) -> bool {
        (self.0 & Self::EXTENDED_LOCALITY_MASK) != 0
    }
}
