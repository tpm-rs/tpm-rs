//! [UnionSize] is a derivable trait that calculates the size of
//! `repr(C)` union part in a tagged or untagged enum.
//!
//! # Example
//! ```rust
//! use tpm2_rs_unionify::UnionSize;
//! #[derive(UnionSize)]
//! enum Foo {
//!     V1(u8),
//!     V2([u32; 128]),
//!     V3{
//!         buffer: [u8;32]
//!     },
//!     V4
//! }
//! assert_eq!(Foo::UNION_SIZE, 128*32/8);
//! ```

pub use tpm2_rs_unionify_derive::UnionSize;

pub trait UnionSize {
    /// The size (in bytes) of `repr(C)`-union-equivalent to the algebraic enum in question.
    const UNION_SIZE: usize;
}

#[cfg(test)]

mod test {
    #[test]
    fn test_unionify() {
        let t = trybuild::TestCases::new();
        t.pass("tests/pass/*.rs");
        t.compile_fail("tests/fail/*.rs")
    }
}
