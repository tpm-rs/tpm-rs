use unionify::unionify;

#[unionify(Bar)]
pub enum Foo {
    A { a: u8 },
    B(u64),
}

fn main() {}
