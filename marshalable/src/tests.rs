// TODO potential bug in clippy? we need to have unit values for testing the
// behavior of marshaling on unit, but the I could not allow this warning for
// HasUnitField, possibly because of span bug, clippy suggested fix is syntax
// error possibly due to another bug, and placing the allow attribute on the
// struct or the let binding does not make the warning go aways
#![allow(clippy::let_unit_value)]

use super::*;

// Provide the tpm2_rs_marshal path to root to enable derive macro to work properly
use crate as tpm2_rs_marshalable;

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

#[derive(PartialEq, Marshalable, Debug)]
struct BasicFields {
    x: u32,
    y: u16,
    z: u8,
}

#[derive(PartialEq, Marshalable, Debug)]
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

#[derive(PartialEq, Debug, Marshalable)]
struct HasArray {
    count: u8,
    other: u32,
    #[marshalable(length=count)]
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

#[derive(PartialEq, Debug, Marshalable)]
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

#[derive(PartialEq, Debug, Marshalable)]
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

#[derive(PartialEq, Debug, Marshalable)]
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

#[repr(C, u8)]
#[derive(Copy, Clone, Debug, Discriminant, Marshalable, PartialEq)]
enum EnumWithVariantData {
    A(u8) = 1,
    B(u8) = 2,
    C(u64) = 3,
}

#[test]
fn test_derive_enum() -> Result<(), TpmRcError> {
    let original = EnumWithVariantData::B(0x42);
    assert_eq!(original.discriminant(), 2);

    let mut buffer = [0u8; size_of::<u8>()];
    assert_eq!(original.try_marshal_variant(&mut buffer), Ok(1));
    assert_eq!(&buffer, &[0x42]);
    let unmarshaled =
        EnumWithVariantData::try_unmarshal_variant(2, &mut UnmarshalBuf::new(&buffer))?;
    assert_eq!(unmarshaled.discriminant(), 2);
    assert_eq!(unmarshaled, original);

    Ok(())
}
