use crate::platform::crypto::EntropySource;

pub struct FakeEntropy;

impl EntropySource for FakeEntropy {
    fn fill_entropy(&mut self, dest: &mut [u8]) {
        for (idx, b) in dest.iter_mut().enumerate() {
            *b = (idx & 0xff) as u8;
        }
    }

    fn instantiate() -> Self {
        Self
    }
}
