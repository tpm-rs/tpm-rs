//! Submodule defining traits used for Marshalling and Unmarshalling
use crate::{
    TpmiAlgHash,
    errors::{MarshalError, UnmarshalError},
};

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
pub trait Limits {
    const SUPPORTED_HASH_ALGS: &[TpmiAlgHash];
    const MAX_DIGEST_SIZE: usize = max_digest_size(Self::SUPPORTED_HASH_ALGS);
}
const fn max_digest_size(hash_algs: &[TpmiAlgHash]) -> usize {
    let mut max = 0;
    let mut i = 0;
    while i < hash_algs.len() {
        let hash_alg = hash_algs[i];
        if max < hash_alg.digest_size() {
            max = hash_alg.digest_size();
        }
        i += 1;
    }
    max
}

/// A type that can be marshalled into a destincation byte buffer
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
    /// [`marshal_fixed`][MarshalFixed::marshal_fixed].
    type Array;
    /// Infallible as we statically know the buffer is long enough
    fn marshal_fixed(&self, arr: &mut Self::Array);
}
// Blanket impl so a type only needs to implement `marshal_fixed()`.
impl<T: MarshalFixed<Array = [u8; N]>, const N: usize> Marshal for T {
    #[inline(always)]
    fn marshal<'d, L: Limits>(&self, buf: &'d mut [u8]) -> Result<&'d mut [u8], MarshalError> {
        let (arr, buf) = buf.split_first_chunk_mut().ok_or(MarshalError)?;
        self.marshal_fixed(arr);
        Ok(buf)
    }
    #[inline(always)]
    fn marshaled_size(&self) -> usize {
        Self::SIZE
    }
    #[inline(always)]
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
    fn unmarshal_value(arr: &Self::Array) -> Result<Self, UnmarshalError>;
    /// Helper function for unmarshalling a value into a reference.
    /// This is useful for implementing [Unmarshal::unmarshal].
    fn unmarshal_fixed(&mut self, arr: &Self::Array) -> Result<(), UnmarshalError> {
        *self = Self::unmarshal_value(arr)?;
        Ok(())
    }
}
// Blanket impl so a type only needs to implement `unmarshal_fixed()`.
impl<'s, T: UnmarshalFixed<Array = [u8; N]>, const N: usize> Unmarshal<'s> for T {
    #[inline(always)]
    fn unmarshal<L: Limits>(&mut self, mut buf: &'s [u8]) -> Result<&'s [u8], UnmarshalError> {
        self.unmarshal_fixed(pop_array(&mut buf)?)?;
        Ok(buf)
    }
}
#[inline(always)]
pub fn pop_array<'s, const N: usize>(buf: &mut &'s [u8]) -> Result<&'s [u8; N], UnmarshalError> {
    let arr;
    (arr, *buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
    Ok(arr)
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
        #[inline(always)]
        fn unmarshal_value(arr: &[u8; Self::SIZE]) -> Result<Self, UnmarshalError> {
            Ok(Self::from_be_bytes(*arr))
        }
    }
)+ } }
impl_ints!(u8, u16, u32, u64, i8, i16, i32, i64);

impl<const N: usize> MarshalFixed for &[u8; N] {
    const SIZE: usize = N;
    type Array = [u8; N];
    #[inline(always)]
    fn marshal_fixed(&self, arr: &mut [u8; N]) {
        *arr = **self;
    }
}
impl<'a, 's: 'a, const N: usize> Unmarshal<'s> for &'a [u8; N] {
    fn unmarshal<L: Limits>(&mut self, mut buf: &'s [u8]) -> Result<&'s [u8], UnmarshalError> {
        *self = pop_array(&mut buf)?;
        Ok(buf)
    }
}
