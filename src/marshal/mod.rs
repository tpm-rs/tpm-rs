//! Submodule defining traits used for Marshalling and Unmarshalling
//!
//! TODO: Elaberate the submodule documentation.
use crate::errors::{MarshalError, UnmarshalError};

// Expose marshal::limits submodule as part of the marshal submodule.
mod limits;
pub use limits::*;

/// A type that can be marshalled into a destination byte buffer
pub trait Marshal {
    fn marshal<'d, L: Limits>(&self, buf: &'d mut [u8]) -> Result<&'d mut [u8], MarshalError>;
    fn marshaled_size(&self) -> usize;
    fn marshaled_size_max<L: Limits>() -> usize;
}

/// A type that can be unmarshalled from a source byte buffer
pub trait Unmarshal<'s> {
    fn unmarshal<L: Limits>(&mut self, buf: &'s [u8]) -> Result<&'s [u8], UnmarshalError>;
}

/// A type that has a consistent size when marshalled
pub trait MarshalFixed: Marshal {
    const SIZE: usize;
    /// This type will always be `[u8; Self::SIZE]`. However, until the
    /// [`min_generic_const_args` feature](https://doc.rust-lang.org/nightly/unstable-book/language-features/min-generic-const-args.html#min_generic_const_args)
    /// is stabilized, we need this type to write the signature of
    /// [`MarshalFixed::marshal_fixed`] and [`UnmarshalFixed::unmarshal_fixed`].
    type Array;
    /// Infallible as we statically know the buffer is long enough
    fn marshal_fixed(&self, arr: &mut Self::Array);
}
// Blanket impl so a type only needs to implement `marshal_fixed()`.
impl<T: MarshalFixed<Array = [u8; N]>, const N: usize> Marshal for T {
    fn marshal<'d, L: Limits>(&self, buf: &'d mut [u8]) -> Result<&'d mut [u8], MarshalError> {
        let (arr, buf) = buf.split_first_chunk_mut().ok_or(MarshalError)?;
        self.marshal_fixed(arr);
        Ok(buf)
    }
    fn marshaled_size(&self) -> usize {
        Self::SIZE
    }
    fn marshaled_size_max<L: Limits>() -> usize {
        Self::SIZE
    }
}

/// Similar to [`MarshalFixed`] but for unmarshalling
///
/// This trait doesn't have a `'s` lifetime parameter like [`Unmarshal`], as
/// types with fixed [`SIZE`][`MarshalFixed::SIZE`] don't need to retain
/// references to the source buffer.
pub trait UnmarshalFixed: MarshalFixed + for<'s> Unmarshal<'s> + Sized {
    /// For fixed-size structures, we can just return the value.
    fn unmarshal_fixed<L: Limits>(arr: &Self::Array) -> Result<Self, UnmarshalError>;
}
// Blanket impl so a type only needs to implement `unmarshal_fixed()`.
impl<'s, T: UnmarshalFixed<Array = [u8; N]>, const N: usize> Unmarshal<'s> for T {
    fn unmarshal<L: Limits>(&mut self, mut buf: &'s [u8]) -> Result<&'s [u8], UnmarshalError> {
        *self = Self::unmarshal_fixed::<L>(pop_array(&mut buf)?)?;
        Ok(buf)
    }
}

pub(crate) fn pop_array<'s, const N: usize>(
    buf: &mut &'s [u8],
) -> Result<&'s [u8; N], UnmarshalError> {
    let arr;
    (arr, *buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
    Ok(arr)
}
