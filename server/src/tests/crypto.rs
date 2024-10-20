use crate::crypto::CryptoRandom;

/// Implements fake cryptographic operations to be used in unit testing.
pub struct FakeCrypto {
    counter: u8,
}

impl FakeCrypto {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
}

impl CryptoRandom for FakeCrypto {
    fn get_random_bytes(&mut self, buffer: &mut [u8]) {
        for i in buffer {
            self.counter = self.counter.wrapping_add(1);
            *i = self.counter;
        }
    }
}

#[test]
fn test_get_random_bytes() {
    let mut crypto = FakeCrypto::new();
    let mut buffer = [0; 10];

    crypto.get_random_bytes(&mut buffer);
    assert_eq!(buffer, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    crypto.get_random_bytes(&mut buffer);
    assert_eq!(buffer, [11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
}
