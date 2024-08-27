#![forbid(unsafe_code)]

use core::mem::size_of;
use safe_discriminant::Discriminant;

use tpm2_rs_errors::*;
pub use tpm2_rs_marshalable_derive::Marshalable;

// This is a module that is exposed publicly, but isn't expected to be used.
// It's for the internal usage of having a prelude for the marshalalbe macro.
#[doc(hidden)]
pub mod __private {
    pub use tpm2_rs_errors::TpmRcError;
    pub use tpm2_rs_errors::TpmRcResult;
}

// The Marshalable trait defines the API for {un}marshaling TPM structs. It
// is implemented for primitive types. The marshal_derive::Marshalable macro
// will provide an implementation that calls try_{un}marshal for each of
// it's fields, but beware that this will not produce the correct output
// for types that have variable sized marshaling output based on their
// contents. Types can also provide their own implementation if needed.
//
// Enums with fields require a primitive representation and explicit selector
// values. These will be marshaled as the primitive selector followed by the
// selected variant.
//
// Array fields which should only {un}marshal a subset of their entries can
// use the length attribute to specify the field providing the number of
// entries that should be marshaled. See TpmlPcrSelection for an example.
pub trait Marshalable: Sized {
    // Unmarshals self from the prefix of `buffer`. Returns the unmarshalled self and number of bytes used.
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self>;

    // Marshals self into the prefix of `buffer`. Returns the number of bytes used.
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize>;
}

/// Defines the ability to marshal an enum by its variant data alone.
///
/// The separation of this trait from `Marshalable` is useful for cases where
/// an enum's data is not directly after the variant's selector. This is
/// something that can happen in some TPM types, so we need to be able to
/// support it (and it needs to be able to function cross-crates in order to
/// support vendors creating their own types, commands, etc).
///
/// # Notice
///
/// Today, you can get this trait simply by deriving the `Marshalable` trait.
/// However, in the future we will be separating this out into a different
/// derive proc-macro.
///
/// See: https://github.com/tpm-rs/tpm-rs/issues/84
pub trait MarshalableVariant: Sized + Discriminant {
    /// Tries to unmarshal into an enum with a specific selector's data.
    ///
    /// Because the way the data in `buffer` is interpreted changes depending on
    /// the variant we are unmarshaling, we have to be told explicitly which
    /// variant is being targeted.
    fn try_unmarshal_variant(selector: Self::Repr, buffer: &mut UnmarshalBuf) -> TpmRcResult<Self>;

    /// Only marshals the variant data for the enum.
    ///
    /// It is up to the caller to marshal the discriminant somewhere before this
    /// call so that they can recover it later.
    ///
    /// If the variant has no data, this returns `Ok(0)`.
    fn try_marshal_variant(&self, buffer: &mut [u8]) -> TpmRcResult<usize>;
}

pub struct UnmarshalBuf<'a> {
    buffer: &'a [u8],
}
impl<'a> UnmarshalBuf<'a> {
    pub fn new(buffer: &'a [u8]) -> UnmarshalBuf<'a> {
        UnmarshalBuf { buffer }
    }

    pub fn get(&mut self, len: usize) -> Option<&'a [u8]> {
        if len > self.buffer.len() {
            None
        } else {
            let (yours, mine) = self.buffer.split_at(len);
            self.buffer = mine;
            Some(yours)
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

// Helper to define Marshalable for primitive types with {to,from}_be_bytes methods.
// T is the primitive type.
macro_rules! impl_be_prim_marshalable {
    ($T:ty) => {
        impl Marshalable for $T {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
                let x = <[u8; size_of::<$T>()]>::try_unmarshal(buffer)?;
                Ok(Self::from_be_bytes(x))
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
                self.to_be_bytes().try_marshal(buffer)
            }
        }
    };
}
impl_be_prim_marshalable! {u8}
impl_be_prim_marshalable! {u16}
impl_be_prim_marshalable! {u32}
impl_be_prim_marshalable! {u64}
impl_be_prim_marshalable! {i8}
impl_be_prim_marshalable! {i16}
impl_be_prim_marshalable! {i32}
impl_be_prim_marshalable! {i64}

impl Marshalable for () {
    fn try_marshal(&self, _buffer: &mut [u8]) -> TpmRcResult<usize> {
        Ok(0)
    }
    fn try_unmarshal(_buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
        Ok(())
    }
}

impl<const M: usize> Marshalable for [u8; M] {
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
        if let Some(mine) = buffer.get(M) {
            let mut x = [0u8; M];
            x.copy_from_slice(mine);
            Ok(x)
        } else {
            Err(TpmRcError::Memory)
        }
    }

    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
        if buffer.len() >= self.len() {
            buffer[..self.len()].copy_from_slice(self);
            Ok(self.len())
        } else {
            Err(TpmRcError::Memory)
        }
    }
}

#[cfg(test)]
mod tests;
