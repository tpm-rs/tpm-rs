use unionify::UnionSize;

///TODO support me
#[derive(UnionSize)]
pub enum Foo<const N: usize> {
    A([u32; N]),
    B(u64),
}

fn main() {}
