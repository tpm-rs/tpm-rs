use tpm2_rs_unionify::UnionSize;

#[derive(UnionSize)]
pub enum Foo<T> {
    A(T),
    B(u64),
}

fn main() {}
