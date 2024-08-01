// =============================================================================
// USES
// =============================================================================

use crate::types::{Tpm2bDigest, Tpm2bSensitive, Tpm2bSimple};
use core::mem::size_of;
use tpm2_rs_marshal::Marshalable;

// =============================================================================
// HELPER TYPES
// =============================================================================

// TODO: Not a fan of this name...
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct _PRIVATE {
    integrity_outer: Tpm2bDigest,
    integrity_inner: Tpm2bDigest,
    sensitive: Tpm2bSensitive,
}

// =============================================================================
// TYPE
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivate {
    size: u16,
    pub buffer: [u8; size_of::<_PRIVATE>()],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivate, buffer}
