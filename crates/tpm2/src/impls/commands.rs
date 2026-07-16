use crate::{Command, Marshal, Tpm2bDigest, Unmarshal, commands::*, errors::UnmarshalError};

impl Command for GetRandom {
    type Response<'a> = responses::GetRandom<'a>;
}
impl Marshal for GetRandom {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        self.bytes_requested.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for GetRandom {
    fn unmarshal_ref(&mut self, src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
        self.bytes_requested.unmarshal_ref(src)
    }
}
impl<'a> Marshal for responses::GetRandom<'a> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; responses::GetRandom::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Tpm2bDigest::MAX_SIZE]) -> usize {
        self.random_bytes.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for responses::GetRandom<'a> {
    fn unmarshal_ref(&mut self, src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
        self.random_bytes.unmarshal_ref(src)
    }
}
