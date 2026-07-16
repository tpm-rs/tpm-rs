use crate::{Alg, BE, Marshal, Unmarshal, errors::UnmarshalError};

impl Marshal for Alg {
    const MAX_SIZE: usize = <BE<u16> as Marshal>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for Alg {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Unmarshal::unmarshal(src).map(Self)
    }
    impl_unmarshal_ref!();
}
