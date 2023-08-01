fn main() {
    println!("Hello, world!");

    let a = 1;
    let b = 2;
    let c = add(a, b);
    println!("{} + {} = {}", a, b, c);
}

fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(1, 2), 3);
    }
}