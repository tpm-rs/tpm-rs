#![forbid(unsafe_code)]

use core::mem::size_of;

use tpm2_rs_errors::*;
pub use tpm2_rs_marshal_derive::Marshal;

/// Exports needed for macro expansion
pub mod exports {
    pub use tpm2_rs_errors as errors;
}

// The Marshalable trait defines the API for {un}marshaling TPM structs. It
// is implemented for primitive types. The marshal_derive::Marshal macro
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
mod tests {
    use super::*;
    // Provide the tpm2_rs_marshal path to root to enable derive macro to work properly
    use crate as tpm2_rs_marshal;

    macro_rules! impl_test_scalar {
        ($T:ty, $I:expr, $V:expr) => {
            const SIZE_OF_TYPE: usize = size_of::<$T>();

            let mut too_small_buffer: [u8; SIZE_OF_TYPE - 1] = [$I; SIZE_OF_TYPE - 1];
            let same_size_buffer: [u8; SIZE_OF_TYPE] = [$I; SIZE_OF_TYPE];
            let larger_buffer: [u8; SIZE_OF_TYPE + 4] = [$I; SIZE_OF_TYPE + 4];

            let mut res: TpmRcResult<$T> =
                <$T>::try_unmarshal(&mut UnmarshalBuf::new(&too_small_buffer));
            assert!(res.is_err());

            res = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&same_size_buffer));
            assert_eq!(res.unwrap(), $V);

            res = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&larger_buffer));
            assert_eq!(res.unwrap(), $V);

            let marsh_value: $T = $V;
            let mut mres = marsh_value.try_marshal(&mut too_small_buffer);
            assert!(mres.is_err());

            let mut zero_same_size: [u8; SIZE_OF_TYPE] = [0; SIZE_OF_TYPE];
            let mut zero_larger: [u8; SIZE_OF_TYPE + 4] = [0; SIZE_OF_TYPE + 4];

            mres = marsh_value.try_marshal(&mut zero_same_size);
            assert_eq!(mres.unwrap(), SIZE_OF_TYPE);
            assert_eq!(zero_same_size, same_size_buffer);

            mres = marsh_value.try_marshal(&mut zero_larger);
            assert_eq!(mres.unwrap(), SIZE_OF_TYPE);
            assert!(zero_larger.starts_with(&same_size_buffer));
        };
    }

    #[test]
    fn test_try_unmarshal_u8() {
        impl_test_scalar! {u8, 0xFF, 0xFF}
    }

    #[test]
    fn test_try_unmarshal_i8() {
        impl_test_scalar! {i8, 0x7F, 0x7F}
    }

    #[test]
    fn test_try_unmarshal_u16() {
        impl_test_scalar! {u16, 0xFF, 0xFFFF}
    }

    #[test]
    fn test_try_unmarshal_i16() {
        impl_test_scalar! {i16, 0x7F, 0x7F7F}
    }

    #[test]
    fn test_try_unmarshal_u32() {
        impl_test_scalar! {u32, 0xFF, 0xFFFFFFFF}
    }

    #[test]
    fn test_try_unmarshal_i32() {
        impl_test_scalar! {i32, 0x7F, 0x7F7F7F7F}
    }

    #[test]
    fn test_try_unmarshal_u64() {
        impl_test_scalar! {u64, 0xFF, 0xFFFFFFFFFFFFFFFF}
    }

    #[test]
    fn test_try_unmarshal_i64() {
        impl_test_scalar! {i64, 0x7F, 0x7F7F7F7F7F7F7F7F}
    }

    #[derive(PartialEq, Marshal, Debug)]
    struct BasicFields {
        x: u32,
        y: u16,
        z: u8,
    }

    #[derive(PartialEq, Marshal, Debug)]
    struct NestedFields {
        one: BasicFields,
        two: u32,
        three: BasicFields,
    }
    #[test]
    fn test_derive_basic() {
        let begin = BasicFields { x: 10, y: 32, z: 4 };
        let mut buffer = [0u8; 8];
        assert!(begin.try_marshal(&mut buffer).is_ok());
        let middle = BasicFields::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert_eq!(middle.unwrap(), begin);
        let end = [0xFu8; 8];
        assert!(end.try_marshal(&mut buffer).is_ok());
        assert_eq!(buffer, end);
    }

    #[test]
    fn test_derive_nested() {
        let begin = NestedFields {
            one: BasicFields { x: 10, y: 32, z: 4 },
            two: 88,
            three: BasicFields { x: 11, y: 33, z: 5 },
        };
        let mut buffer = [0u8; 20];
        assert!(begin.try_marshal(&mut buffer).is_ok());
        let middle = NestedFields::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert!(middle.is_ok());
        assert_eq!(middle.unwrap(), begin);
        let end = [0xFu8; 20];
        assert!(end.try_marshal(&mut buffer).is_ok());
        assert_eq!(buffer, end);
    }

    #[test]
    fn test_derive_bounds() {
        let info = NestedFields {
            one: BasicFields { x: 10, y: 32, z: 4 },
            two: 88,
            three: BasicFields { x: 11, y: 33, z: 5 },
        };
        let mut buffer = [0u8; 20];
        assert!(info.try_marshal(&mut buffer).is_ok());

        // Too small returns error.
        let mut tiny_buffer = [0u8; 3];
        assert!(info.try_marshal(&mut tiny_buffer).is_err());
        // Too large is happy and prefix matches perfectly-sized buffer.
        let mut huge_buffer = [0u8; 64];
        assert!(info.try_marshal(&mut huge_buffer).is_ok());
        assert_eq!(huge_buffer[..buffer.len()], buffer);

        // We can also unmarshal from oversized buffer.
        let unmarshaled = NestedFields::try_unmarshal(&mut UnmarshalBuf::new(&huge_buffer));
        assert_eq!(unmarshaled.unwrap(), info);
    }

    #[derive(PartialEq, Debug, Marshal)]
    struct HasArray {
        count: u8,
        other: u32,
        #[length(count)]
        array: [u8; 128],
    }

    #[test]
    fn test_derive_custom_len() {
        let value = HasArray {
            count: 10,
            other: 0,
            array: [9u8; 128],
        };
        let mut buffer = [0u8; 256];
        let marshal = value.try_marshal(&mut buffer);
        assert_eq!(
            marshal.unwrap(),
            value.count as usize + size_of::<u32>() + size_of::<u8>()
        );

        let unmarshal = HasArray::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        let unmarsh_value = unmarshal.unwrap();
        // Marshaled fields match.
        assert_eq!(unmarsh_value.count, value.count);
        assert_eq!(unmarsh_value.other, value.other);
        assert_eq!(
            unmarsh_value.array[..value.count as usize],
            value.array[..value.count as usize]
        );
        // But the full structs don't, because the unmarshaled array bytes are different.
        assert_ne!(unmarsh_value, value);
    }

    #[derive(PartialEq, Debug, Marshal)]
    struct Nameless(u32, u16);

    #[test]
    fn test_derive_nameless_fields() {
        let value = Nameless(7777777, 61);
        let mut buffer = [0u8; 6];
        let marshal = value.try_marshal(&mut buffer);
        assert!(marshal.is_ok());
        let unmarshal = Nameless::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert_eq!(value, unmarshal.unwrap());
    }

    #[derive(PartialEq, Debug, Marshal)]
    struct HasPlainArrayField {
        a: u32,
        b: [u8; 10],
    }

    #[test]
    fn test_derive_array_field() {
        let value = HasPlainArrayField {
            a: 0x10101010,
            b: [3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
        };
        let mut buffer = [0u8; 16];
        let marshal = value.try_marshal(&mut buffer);
        assert!(marshal.is_ok());
        let unmarshal = HasPlainArrayField::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert_eq!(value, unmarshal.unwrap());
    }

    #[derive(PartialEq, Debug, Marshal)]
    struct HasUnitField {
        a: u8,
        b: (),
        c: u32,
    }

    #[test]
    fn test_derive_unit_struct() {
        let value = HasUnitField {
            a: 0x4,
            b: (),
            c: 0x12122121,
        };
        let mut buffer = [0u8; size_of::<u8>() + size_of::<u32>()];
        assert!(value.try_marshal(&mut buffer).is_ok());
        let unmarshal = HasUnitField::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert_eq!(value, unmarshal.unwrap())
    }
}
