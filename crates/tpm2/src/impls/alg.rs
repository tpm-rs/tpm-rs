use crate::{Alg, Marshal, TpmiAlgHash, Unmarshal, errors::UnmarshalError};

impl Marshal for TpmiAlgHash {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmiAlgHash {
    fn unmarshal_ref(&mut self, mut src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
        *self = Alg::unmarshal(&mut src)?.try_into()?;
        Ok(src)
    }
}
