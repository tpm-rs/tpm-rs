//! Submodule defining traits used for Marshalling and Unmarshalling

use crate::{MarshalError, TpmiAlgHash, UnmarshalError};

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
pub trait MarshalFixed: Marshal {
    const SIZE: usize;
    /// This type will always be `[u8; Self::SIZE]`. However, until the
    /// [`min_generic_const_args` feature](https://doc.rust-lang.org/nightly/unstable-book/language-features/min-generic-const-args.html#min_generic_const_args)
    /// is stabilized, we need this type to write the signature of
    /// [`marshal_fixed`][MarshalFixed::marshal_fixed].
    type Array;
    /// Infallible as we statically know the buffer is long enough
    fn marshal_fixed(&self, arr: &mut Self::Array);
}
// Blanket impl so a type only needs to implement `marshal_fixed()`.
impl<T: MarshalFixed<Array = [u8; N]>, const N: usize> Marshal for T {
    #[inline(always)]
    fn marshal<'dst>(
        &self,
        _: impl Limits,
        buf: &'dst mut [u8],
    ) -> Result<&'dst mut [u8], MarshalError> {
        let (arr, buf) = buf.split_first_chunk_mut().ok_or(MarshalError)?;
        self.marshal_fixed(arr);
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

/// Similar to [`MarshalFixed`] but for unmarshalling
///
/// This trait doesn't have a `'src` lifetime parameter like [`Unmarshal`], as
/// types with fixed [`SIZE`][`MarshalFixed::SIZE`] don't need to retain
/// references to the source buffer.
pub trait UnmarshalFixed: MarshalFixed + for<'src> Unmarshal<'src> {
    /// This can still fail if the source buffer has a bad value, but we know
    /// we have a buffer of the correct length.
    fn unmarshal_fixed(&mut self, arr: &Self::Array) -> Result<(), UnmarshalError>;
    /// Helper function (nicer now that we don't need to return the unused buffer).
    #[inline(always)]
    fn unmarshal_value(arr: &Self::Array) -> Result<Self, UnmarshalError>
    where
        Self: Default,
    {
        let mut v = Self::default();
        v.unmarshal_fixed(arr)?;
        Ok(v)
    }
}
// Blanket impl so a type only needs to implement `unmarshal_fixed()`.
impl<'src, T: UnmarshalFixed<Array = [u8; N]>, const N: usize> Unmarshal<'src> for T {
    #[inline(always)]
    fn unmarshal(&mut self, _: impl Limits, buf: &'src [u8]) -> Result<&'src [u8], UnmarshalError> {
        let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
        self.unmarshal_fixed(arr)?;
        Ok(buf)
    }
}

/// Implement [`MarshalFixed`] and [`UnmarshalFixed`] for integer types
macro_rules! impl_ints { ($($T: ty),+) => { $(
    impl MarshalFixed for $T {
        const SIZE: usize = size_of::<Self>();
        type Array = [u8; size_of::<Self>()];
        fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
            *arr = self.to_be_bytes();
        }
    }
    impl UnmarshalFixed for $T {
        fn unmarshal_fixed(&mut self, arr: &[u8; Self::SIZE]) -> Result<(), UnmarshalError> {
            *self = Self::from_be_bytes(*arr);
            Ok(())
        }
    }
)+ } }
impl_ints!(u8, u16, u32, u64, i8, i16, i32, i64);

impl<const N: usize> MarshalFixed for [u8; N] {
    const SIZE: usize = N;
    type Array = [u8; N];
    #[inline(always)]
    fn marshal_fixed(&self, arr: &mut [u8; N]) {
        *arr = *self;
    }
}
impl<const N: usize> UnmarshalFixed for [u8; N] {
    #[inline(always)]
    fn unmarshal_fixed(&mut self, arr: &[u8; N]) -> Result<(), UnmarshalError> {
        *self = *arr;
        Ok(())
    }
}
