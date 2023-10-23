//! Aligned big-endian integer primitives.
//! 
//! The structs here are similar to those defined in `zerocopy::byteorder`,
//! but retain their alignment requirement, meaning reads are smaller.

use core::fmt;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

macro_rules! impl_big_endian_ints {
    ($($outer:ident => $inner:ty),* $(,)?) => {
        $(
            #[derive(Copy, Clone, Default, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
            #[repr(transparent)]
            #[doc = concat!("An aligned big-endian `", stringify!($inner), "`.")]
            pub struct $outer($inner);

            impl fmt::Debug for $outer {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.debug_tuple(stringify!($outer)).field(&self.get()).finish()
                }
            }

            impl $outer {
                pub const ZERO: Self = Self(0);

                #[doc = concat!(
                    "Constructs a big-endian `", stringify!(inner),
                    "` from native endian, performing a byte swap if needed.")]
                pub const fn new(val: $inner) -> $outer {
                    $outer(val.to_be())
                }

                #[doc = concat!(
                    "Retrieves the inner `", stringify!(inner),
                    "` as native endian, performing a byte swap if needed.")]
                pub const fn get(self) -> $inner {
                    <$inner>::from_be(self.0)
                }
            }

            impl From<$inner> for $outer {
                fn from(x: $inner) -> $outer {
                    $outer::new(x)
                }
            }

            impl From<$outer> for $inner {
                fn from(x: $outer) -> $inner {
                    x.get()
                }
            }
        )*
    };
}

impl_big_endian_ints!(
    U8 => u8,
    U16 => u16,
    U32 => u32,
    U64 => u64,
    I8 => i8,
    I16 => i16,
    I32 => i32,
    I64 => i64,
);