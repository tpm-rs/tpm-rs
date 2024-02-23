use unionify::unionify;

#[unionify(Bar)]
#[repr(u16)]
pub enum Foo {
    A(u8) = 10,
    B(u64),
}

fn main() {}
