use crate::{
    Alg, Marshal, TpmiAlgHash, TpmtHa, Unmarshal, errors::UnmarshalError,
    marshal::unmarshal_array_ref,
};

impl<'a> Marshal for TpmtHa<'a> {
    const MAX_SIZE: usize = Alg::MAX_SIZE + TpmiAlgHash::MAX_DIGEST_SIZE;
    type MaxBuffer = [u8; TpmtHa::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtHa::MAX_SIZE]) -> usize {
        let hash_alg = Alg::from(self.hash_alg());
        let len = hash_alg.marshal((&mut dst[..Alg::MAX_SIZE]).try_into().unwrap());
        let digest = self.digest();
        dst[len..len + digest.len()].copy_from_slice(digest);
        len + digest.len()
    }
}

impl<'a> Unmarshal<'a> for TpmtHa<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let alg = TpmiAlgHash::unmarshal(src)?;
        match alg {
            TpmiAlgHash::Sha1 => Ok(TpmtHa::Sha1(unmarshal_array_ref(src)?)),
            TpmiAlgHash::Sha256 => Ok(TpmtHa::Sha256(unmarshal_array_ref(src)?)),
            TpmiAlgHash::Sha384 => Ok(TpmtHa::Sha384(unmarshal_array_ref(src)?)),
            TpmiAlgHash::Sha512 => Ok(TpmtHa::Sha512(unmarshal_array_ref(src)?)),
            _ => Err(UnmarshalError),
        }
    }
    impl_unmarshal_ref!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpmt_ha_marshal_unmarshal() {
        let digest_bytes = [0xAB; 32];
        let tpmt_ha = TpmtHa::Sha256(&digest_bytes);

        let mut buf = [0u8; TpmtHa::MAX_SIZE];
        let len = tpmt_ha.marshal(&mut buf);
        assert_eq!(len, 2 + 32);

        let mut slice = &buf[..len];
        let unmarshaled = TpmtHa::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshaled, tpmt_ha);
        assert!(slice.is_empty());
    }
}
