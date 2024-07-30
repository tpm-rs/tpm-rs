use tpm2_rs_unionify::UnionSize;

#[derive(UnionSize)]
pub enum Foo {
    A,
    B,
}

fn main() {}
