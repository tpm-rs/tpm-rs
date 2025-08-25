use core::{error::Error, fmt::Display};

use crate::platform::crypto::{
    drbg_helpers::{next_u32_via_fill, next_u64_via_fill},
    Drbg, DrbgError,
};

#[derive(Debug)]
pub struct FakeDrbgError;

impl Display for FakeDrbgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:#?}")
    }
}
impl Error for FakeDrbgError {}
/// Implements fake cryptographic operations to be used in unit testing.
pub struct FakeDrbg {
    counter: u8,
}

impl FakeDrbg {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
}

impl Drbg for FakeDrbg {
    type Entropy = [u8; 1];
    type Nonce = [u8; 0];
    fn instantiate(entropy_input: &[u8; 1], _: &Self::Nonce, _: &[u8]) -> Result<Self, DrbgError> {
        Ok(Self {
            counter: entropy_input[0],
        })
    }
    fn reseed(&mut self, entropy_input: &[u8; 1], _: &[u8]) -> Result<(), DrbgError> {
        self.counter += entropy_input[0];
        Ok(())
    }
    fn fill_bytes(&mut self, _: &[u8], buffer: &mut [u8]) -> Result<(), DrbgError> {
        for i in buffer {
            self.counter = self.counter.wrapping_add(1);
            *i = self.counter;
        }
        Ok(())
    }

    fn next_u32(&mut self, additional_input: &[u8]) -> Result<u32, DrbgError> {
        next_u32_via_fill(self, additional_input)
    }

    fn next_u64(&mut self, additional_input: &[u8]) -> Result<u64, DrbgError> {
        next_u64_via_fill(self, additional_input)
    }

    fn requires_reseeding(&mut self) -> bool {
        false
    }
}

#[test]
fn test_get_random_bytes() {
    let mut crypto = FakeDrbg::new();
    let mut buffer = [0; 10];

    crypto.fill_bytes(&[], &mut buffer).unwrap();
    assert_eq!(buffer, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    crypto.fill_bytes(&[], &mut buffer).unwrap();
    assert_eq!(buffer, [11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
}
