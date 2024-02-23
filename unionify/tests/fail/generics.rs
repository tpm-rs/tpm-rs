use unionify::unionify;

#[unionify(Bar)]
pub enum Foo<T> {
    A(T),
    B(u64),
}

fn main() {}
