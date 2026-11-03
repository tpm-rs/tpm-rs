#![forbid(unsafe_code)]

//! `serde` support of the persisted types: the `Serialize`/`Deserialize` implementations of
//! [`Array`] (the sequence of its active elements), and helpers for fixed-size byte arrays of any
//! length (`serde` itself only implements its traits for arrays of up to 32 elements), for
//! `#[serde(with = "...")]`:
//!
//! - [`bytes`]: `[u8; N]` as a byte string (`serialize_bytes`).
//! - [`nested_bytes`]: `[[u8; M]; N]` as a tuple of `N` byte strings.
//!
//! Deserialization accepts a byte string or a sequence of `u8`, so that formats without a native
//! byte-string type (e.g. JSON, which writes bytes as an array of numbers) round-trip; the length
//! must match exactly.

use core::fmt;
use core::marker::PhantomData;

use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, SerializeTuple};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::types::Array;

/// Serialized as the sequence of the active elements `data[..len]` (`len` clamped to `N`).
impl<T: Serialize, const N: usize> Serialize for Array<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.as_slice().len()))?;
        for item in self.as_slice() {
            seq.serialize_element(item)?;
        }
        seq.end()
    }
}

/// Deserialized from a sequence of at most `N` elements; a longer sequence is an
/// `invalid_length` error.
impl<'de, T: Deserialize<'de> + Default + Copy, const N: usize> Deserialize<'de> for Array<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ArrayVisitor<T, const N: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de> + Default + Copy, const N: usize> Visitor<'de>
            for ArrayVisitor<T, N>
        {
            type Value = Array<T, N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a sequence of at most {N} elements")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut array = Array::new();
                while let Some(item) = seq.next_element()? {
                    if array.len == N {
                        return Err(A::Error::invalid_length(N + 1, &self));
                    }
                    array.data[array.len] = item;
                    array.len += 1;
                }
                Ok(array)
            }
        }

        deserializer.deserialize_seq(ArrayVisitor::<T, N>(PhantomData))
    }
}

/// Visitor of an exactly `N`-byte array from a byte string or a sequence of `u8`.
struct ByteArrayVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{N} bytes")
    }

    fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(i, &self))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            return Err(A::Error::invalid_length(N + 1, &self));
        }
        Ok(out)
    }
}

/// `[u8; N]` as a byte string.
pub mod bytes {
    use super::*;

    pub fn serialize<S: Serializer, const N: usize>(
        value: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        deserializer.deserialize_bytes(ByteArrayVisitor::<N>)
    }
}

/// An `[u8; M]` that serializes as a byte string (the elements of [`nested_bytes`]).
struct Bytes<const M: usize>([u8; M]);

impl<const M: usize> Serialize for Bytes<M> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const M: usize> Deserialize<'de> for Bytes<M> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_bytes(ByteArrayVisitor::<M>)
            .map(Bytes)
    }
}

/// `[[u8; M]; N]` as a tuple of `N` byte strings.
pub mod nested_bytes {
    use super::*;

    pub fn serialize<S: Serializer, const M: usize, const N: usize>(
        value: &[[u8; M]; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(N)?;
        for inner in value {
            tuple.serialize_element(&Bytes(*inner))?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const M: usize, const N: usize>(
        deserializer: D,
    ) -> Result<[[u8; M]; N], D::Error> {
        struct NestedVisitor<const M: usize, const N: usize>(PhantomData<[[u8; M]; N]>);

        impl<'de, const M: usize, const N: usize> Visitor<'de> for NestedVisitor<M, N> {
            type Value = [[u8; M]; N];

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{N} arrays of {M} bytes")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [[0u8; M]; N];
                for (i, inner) in out.iter_mut().enumerate() {
                    *inner = seq
                        .next_element::<Bytes<M>>()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?
                        .0;
                }
                if seq.next_element::<Bytes<M>>()?.is_some() {
                    return Err(A::Error::invalid_length(N + 1, &self));
                }
                Ok(out)
            }
        }

        deserializer.deserialize_tuple(N, NestedVisitor::<M, N>(PhantomData))
    }
}
