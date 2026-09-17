//! Marshalling and Unmarshalling traits
use crate::errors::UnmarshalError;

/// A type that can be marshalled into a destination byte buffer.
pub trait Marshal: Sized {
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

pub(crate) fn marshal_helper<const N: usize>(
    t: &impl Marshal<MaxBuffer = [u8; N]>,
    dst: &mut [u8],
    count: usize,
) -> usize {
    count + t.marshal(dst[count..].first_chunk_mut().unwrap())
}

pub(crate) const fn max(vals: &[usize]) -> usize {
    let mut max_val = 0;
    let mut i = 0;
    while i < vals.len() {
        if vals[i] > max_val {
            max_val = vals[i];
        }
        i += 1;
    }
    max_val
}

/// A type that can be unmarshalled from a source byte buffer.
pub trait Unmarshal<'a>: Sized {
    /// Unmarshals the structure from the provided byte buffer, modifying the
    /// structure in-place.
    ///
    /// On success, returns the remaining, unused bytes from `src`.
    fn unmarshal_ref(&mut self, mut src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
        *self = Self::unmarshal(&mut src)?;
        Ok(src)
    }

    /// Returns a value unmarshaled from `*src`.
    ///
    /// On success, `*src` will be the remaining, unused bytes. On failure,
    /// `*src` will be in an unspecified state.
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError>;
}

impl<const N: usize> Marshal for [u8; N] {
    const MAX_SIZE: usize = N;
    type MaxBuffer = [u8; N];
    fn marshal(&self, dst: &mut [u8; N]) -> usize {
        *dst = *self;
        N
    }
}
impl<'a, const N: usize> Unmarshal<'a> for &'a [u8; N] {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (arr, rest) = src.split_first_chunk().ok_or(UnmarshalError)?;
        *src = rest;
        Ok(arr)
    }
}
impl<'a, const N: usize> Unmarshal<'a> for [u8; N] {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let arr: &'a [u8; N] = Unmarshal::unmarshal(src)?;
        Ok(*arr)
    }
}

macro_rules! impl_ints { ($($T: ty),+) => { $(
    impl Marshal for $T {
        const MAX_SIZE: usize = size_of::<Self>();
        type MaxBuffer = [u8; Self::MAX_SIZE];

        fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
            self.to_be_bytes().marshal(dst)
        }
    }
    impl<'a> Unmarshal<'a> for $T {
        fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
            Unmarshal::unmarshal(src).map(Self::from_be_bytes)
        }
    }
)+ } }
impl_ints!(u8, u16, u32, u64, i8, i16, i32, i64);

impl Marshal for bool {
    const MAX_SIZE: usize = u8::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for bool {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u8::unmarshal(src)?.try_into().map_err(|_| UnmarshalError)
    }
}

impl Marshal for () {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> Unmarshal<'a> for () {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max() {
        assert_eq!(max(&[]), 0);
        assert_eq!(max(&[5]), 5);
        assert_eq!(max(&[1, 5, 3, 9, 2]), 9);
        assert_eq!(max(&[10, 20, 30]), 30);
    }
}
