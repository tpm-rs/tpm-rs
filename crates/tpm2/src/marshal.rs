//! Marshalling and Unmarshalling traits
use core::fmt;

use crate::errors::UnmarshalError;

/// A type that can be marshalled into a destination byte buffer.
///
/// [`Self::MaxBuffer`] is always [`[u8; Self::MAX_SIZE]`](Self::MAX_SIZE),
/// so types should implement this trait like:
/// ```
/// # use tpm2::Marshal;
/// # const fn calculate_foo_max_size() -> usize { 42 }
/// struct Foo;
///
/// impl Marshal for Foo {
///     const MAX_SIZE: usize = calculate_foo_max_size();
///     type MaxBuffer = [u8; Self::MAX_SIZE];
///
///     fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
///         todo!()
///     }
/// }
/// ```
pub trait Marshal {
    /// The maximum possible size (in bytes) of this structure when encoded.
    const MAX_SIZE: usize;
    /// [`[u8; Self::MAX_SIZE]`](Self::MAX_SIZE)
    ///
    /// However, this has to be part of the trait definition until
    /// [`#![feature(min_generic_const_args)]`](https://doc.rust-lang.org/nightly/unstable-book/language-features/min-generic-const-args.html#min_generic_const_args)
    /// is finalized.
    type MaxBuffer;

    /// Marshals the structure into the provided array, which will always be
    /// `&mut`[`[u8; Self::MAX_SIZE]`](Self::MAX_SIZE).
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize;
}

/// A type that can be unmarshalled from a source byte buffer.
pub trait Unmarshal<'a> {
    /// Unmarshals the structure from the provided byte buffer, modifying the
    /// structure in-place.
    ///
    /// On success, returns the remaining, unused bytes from `src`.
    fn unmarshal_ref(&mut self, src: &'a [u8]) -> Result<&'a [u8], UnmarshalError>;

    /// Returns a value unmarshaled from `*src`.
    ///
    /// On success, `*src` will be the remaining, unused bytes. On failure,
    /// `*src` will be unmodified.
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError>
    where
        Self: Default,
    {
        let mut v = Self::default();
        *src = v.unmarshal_ref(src)?;
        Ok(v)
    }
}

/// A wrapper type for numeric values stored in big-endian byte order.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub(crate) struct BE<T>(pub(crate) T);

macro_rules! impl_unmarshal_ref {
    () => {
        #[inline(always)]
        fn unmarshal_ref(&mut self, mut src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
            *self = Unmarshal::unmarshal(&mut src)?;
            Ok(src)
        }
    };
}

impl<const N: usize> Marshal for [u8; N] {
    const MAX_SIZE: usize = N;
    type MaxBuffer = [u8; N];
    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; N]) -> usize {
        *dst = *self;
        N
    }
}

/// Unmarshals a reference to a fixed-size byte array `&'a [u8; N]` from `src`.
#[inline(always)]
pub(crate) fn unmarshal_array_ref<'a, const N: usize>(
    src: &mut &'a [u8],
) -> Result<&'a [u8; N], UnmarshalError> {
    let (arr, rest) = src.split_first_chunk().ok_or(UnmarshalError)?;
    *src = rest;
    Ok(arr)
}

impl<'a, const N: usize> Unmarshal<'a> for [u8; N] {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        unmarshal_array_ref(src).copied()
    }
    #[inline(always)]
    fn unmarshal_ref(&mut self, mut src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
        *self = *unmarshal_array_ref(&mut src)?;
        Ok(src)
    }
}
impl<'a, const N: usize> Unmarshal<'a> for &'a [u8; N] {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        unmarshal_array_ref(src)
    }
    #[inline(always)]
    fn unmarshal_ref(&mut self, mut src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
        *self = unmarshal_array_ref(&mut src)?;
        Ok(src)
    }
}

macro_rules! impl_ints { ($($T: ty),+) => { $(
    impl Marshal for $T {
        const MAX_SIZE: usize = size_of::<Self>();
        type MaxBuffer = [u8; Self::MAX_SIZE];

        #[inline(always)]
        fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
            self.to_be_bytes().marshal(dst)
        }
    }
    impl<'a> Unmarshal<'a> for $T {
        #[inline(always)]
        fn unmarshal(src: &mut &[u8]) -> Result<Self, UnmarshalError> {
            Unmarshal::unmarshal(src).map(Self::from_be_bytes)
        }
        impl_unmarshal_ref!();
    }

    impl BE<$T> {
        #[inline(always)]
        #[allow(dead_code)]
        pub const fn new(t: $T) -> Self {
            Self(t.to_be())
        }
        #[inline(always)]
        pub const fn get(self) -> $T {
            <$T>::from_be(self.0)
        }
    }
    impl Marshal for BE<$T> {
        const MAX_SIZE: usize = size_of::<Self>();
        type MaxBuffer = [u8; Self::MAX_SIZE];

        #[inline(always)]
        fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
            self.0.to_ne_bytes().marshal(dst)
        }
    }
    impl<'a> Unmarshal<'a> for BE<$T> {
        #[inline(always)]
        fn unmarshal(src: &mut &[u8]) -> Result<Self, UnmarshalError> {
            Ok(Self(<$T>::from_ne_bytes(Unmarshal::unmarshal(src)?)))
        }
        impl_unmarshal_ref!();
    }
    impl fmt::Debug for BE<$T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.get().fmt(f)
        }
    }
)+ } }
impl_ints!(u8, u16, u32, u64, i8, i16, i32, i64);
