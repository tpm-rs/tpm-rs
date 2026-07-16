use crate::Tpm2bDigest;

/// Random bytes returned by the RNG
#[doc(alias("GetRandom_Out"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct GetRandom<'a> {
    /// The generated random bytes.
    pub random_bytes: Tpm2bDigest<'a>,
}
