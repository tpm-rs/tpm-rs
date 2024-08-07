#![forbid(unsafe_code)]

use core::mem::size_of;

use tpm2_rs_errors::*;
pub use tpm2_rs_marshalable_derive::Marshalable;

/// Exports needed for macro expansion
pub mod exports {
    pub use tpm2_rs_errors as errors;
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
pub trait Marshalable {
    // Unmarshals self from the prefix of `buffer`. Returns the unmarshalled self and number of bytes used.
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self>
    where
        Self: Sized;

    // Marshals self into the prefix of `buffer`. Returns the number of bytes used.
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize>;
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
