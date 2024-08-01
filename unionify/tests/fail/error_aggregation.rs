use tpm2_rs_unionify::UnionSize;

#[derive(UnionSize)]
pub enum Foo {
    A { a1: u8, a2: u8 },
    B { b1: u64, b2: u64 },
    C { c1: u8, c2: u16 },
}

fn main() {}
