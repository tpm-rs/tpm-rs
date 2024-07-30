use tpm2_rs_unionify::UnionSize;

#[derive(UnionSize)]
pub enum Foo {
    A { x: u8, y: u8 },
    B(u64),
}

fn main() {}
