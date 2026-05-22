//! Submodule defining traits used for Marshalling and Unmarshalling

use crate::{
    TpmiAlgHash,
    errors::{MarshalError, UnmarshalError},
};
use core::convert::Infallible;

/// Allows an implementation to restrict which values it can [`Marshal`] and
/// [`Unmarshal`].
///
/// This trait enables different implementations to share the same core type
/// definitions while selectively supporting only a subset of variants. This
/// selection can be enforced either at compile time or at runtime.
///
/// This approach is important for two main reasons:
///
/// 1.  **ABI Stability**: It avoids the many compile-time `#define`s found in C
///     implementations. Those defines often alter structure layouts, leading to
///     API and ABI incompatibilities between libraries compiled with different
///     options.
///
/// 2.  **Code Size**: Restricting which algorithms and types the marshaling code
///     must support can significantly reduce the final binary size, which is
///     critical for constrained environments.
pub trait Limits: Copy {
    fn supports_hash(self, h: TpmiAlgHash) -> bool;

    fn max_digest_size(self) -> usize {
        for &h in TpmiAlgHash::BY_SIZE_DESC {
            if self.supports_hash(h) {
                return h.digest_size();
            }
        }
        0
    }
}

/// A type that can be marshalled into a destincation byte buffer
pub trait Marshal {
    fn marshal<'dst>(
        &self,
        limits: impl Limits,
        buf: &'dst mut [u8],
    ) -> Result<&'dst mut [u8], MarshalError>;
    fn marshaled_size(&self) -> usize;
    fn marshaled_size_max(limits: impl Limits) -> usize;
}

/// A type that can be unmarshalled from a source byte buffer
pub trait Unmarshal<'src> {
    fn unmarshal(
        &mut self,
        limits: impl Limits,
        buf: &'src [u8],
    ) -> Result<&'src [u8], UnmarshalError>;
}

/// A type that has a consistent size when marshalled
pub trait MarshalArray: Marshal {
    const SIZE: usize;
    /// This type will always be `[u8; Self::SIZE]`. However, until the
    /// [`min_generic_const_args` feature](https://doc.rust-lang.org/nightly/unstable-book/language-features/min-generic-const-args.html#min_generic_const_args)
    /// is stabilized, we need this type to write the signature of
    /// [`marshal_array`][MarshalArray::marshal_array].
    type Array;
    /// Infallible as we statically know the buffer is long enough
    fn marshal_array(&self, arr: &mut Self::Array);
}
// Blanket impl so a type only needs to implement `marshal_array()`.
impl<T: MarshalArray<Array = [u8; N]>, const N: usize> Marshal for T {
    #[inline(always)]
    fn marshal<'dst>(
        &self,
        _: impl Limits,
        buf: &'dst mut [u8],
    ) -> Result<&'dst mut [u8], MarshalError> {
        let (arr, buf) = buf.split_first_chunk_mut().ok_or(MarshalError)?;
        self.marshal_array(arr);
        Ok(buf)
    }
    #[inline(always)]
    fn marshaled_size(&self) -> usize {
        Self::SIZE
    }
    #[inline(always)]
    fn marshaled_size_max(_: impl Limits) -> usize {
        Self::SIZE
    }
}

/// Similar to [`MarshalArray`] but for unmarshalling
///
/// This trait doesn't have a `'src` lifetime parameter like [`Unmarshal`], as
/// types with fixed [`SIZE`][`MarshalArray::SIZE`] don't need to retain
/// references to the source buffer.
pub trait UnmarshalArray: Sized + MarshalArray + for<'src> Unmarshal<'src>
where
    UnmarshalError: From<Self::Error>,
{
    type Error;
    /// This can still fail if the source buffer has a bad value, but we know
    /// we have a buffer of the correct length.
    fn unmarshal_array(arr: &Self::Array) -> Result<Self, Self::Error>;
}
// Blanket impl so a type only needs to implement `unmarshal_array()`.
impl<'src, T: UnmarshalArray<Array = [u8; N]>, const N: usize> Unmarshal<'src> for T
where
    UnmarshalError: From<T::Error>,
{
    #[inline(always)]
    fn unmarshal(&mut self, _: impl Limits, buf: &'src [u8]) -> Result<&'src [u8], UnmarshalError> {
        let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
        *self = Self::unmarshal_array(arr)?;
        Ok(buf)
    }
}

/// Implement [`MarshalArray`] and [`UnmarshalArray`] for integer types
macro_rules! impl_ints { ($($T: ty),+) => { $(
    impl MarshalArray for $T {
        const SIZE: usize = size_of::<Self>();
        type Array = [u8; size_of::<Self>()];
        fn marshal_array(&self, arr: &mut [u8; Self::SIZE]) {
            *arr = self.to_be_bytes();
        }
    }
    impl UnmarshalArray for $T {
        type Error = Infallible;
        fn unmarshal_array(arr: &[u8; Self::SIZE]) -> Result<Self, Infallible> {
            Ok(Self::from_be_bytes(*arr))
        }
    }
)+ } }
impl_ints!(u8, u16, u32, u64, i8, i16, i32, i64);

impl<const N: usize> MarshalArray for [u8; N] {
    const SIZE: usize = N;
    type Array = [u8; N];
    #[inline(always)]
    fn marshal_array(&self, arr: &mut [u8; N]) {
        *arr = *self;
    }
}
