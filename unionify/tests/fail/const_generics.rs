use unionify::unionify;

///TODO support me
#[unionify(Bar)]
pub enum Foo<const N: usize> {
    A([u32; N]),
    B(u64),
}

fn main() {}
