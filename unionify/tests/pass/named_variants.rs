use tpm2_rs_unionify::UnionSize;

#[derive(UnionSize)]
pub enum Foo {
    A { a: u8 },
    B { b: u64 },
}

fn main() {}
