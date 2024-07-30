use tpm2_rs_unionify::UnionSize;

#[derive(UnionSize)]
#[repr(u16)]
pub enum Foo {
    A(u8) = 10,
    B(u64),
}

fn main() {}
