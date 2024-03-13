use unionify::UnionSize;

#[derive(UnionSize)]
pub enum Foo {
    A(u8),
    B(u64),
}

fn main() {}
