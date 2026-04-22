use crate::Tpm2bDigest;

/// Random bytes retuned by the RNG
#[doc(alias("GetRandom_Out"))]
#[derive(Clone, Copy, Debug)]
pub struct GetRandom<'a> {
    pub random_bytes: Tpm2bDigest<'a>,
}
