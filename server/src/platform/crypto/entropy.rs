/// This trait wraps functionalities common to all entropy sources.
pub trait EntropySource {
    /// Create a new entropy source isnstance
    fn instantiate() -> Self;
    /// Fills `dest` with true random bytes.
    fn fill_entropy(&mut self, dest: &mut [u8]);
}
