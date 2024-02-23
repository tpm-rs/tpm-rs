use unionify::unionify;

#[unionify(Bar)]
pub enum Foo {
    A(u8, u8),
    B(u64),
}

fn main() {}
