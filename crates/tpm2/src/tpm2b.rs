use crate::{Marshal, TpmiAlgHash, Unmarshal, errors::UnmarshalError};

/// A TPM 2.0 sized buffer wrapper holding up to `N` bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Tpm2b<'a, const N: usize>(&'a [u8]);

impl<'a, const N: usize> Tpm2b<'a, N> {
    pub const fn new(b: &'a [u8]) -> Option<Self> {
        if b.len() <= N { Some(Self(b)) } else { None }
    }
    pub const fn bytes(self) -> &'a [u8] {
        match self.0.split_at_checked(N) {
            Some((s, _)) => {
                debug_assert!(false, "Tpm2b inner data too long");
                s
            }
            None => self.0,
        }
    }
    #[inline(always)]
    pub(crate) const fn marshal_helper<const M: usize>(self, dst: &mut [u8; M]) -> usize {
        assert!(2 + N == M);
        let (s_dst, rest) = dst.split_first_chunk_mut::<2>().unwrap();

        let b = self.bytes();
        *s_dst = (b.len() as u16).to_be_bytes();
        let (b_dst, _) = rest.split_at_mut_checked(b.len()).unwrap();
        b_dst.copy_from_slice(b);
        2 + b.len()
    }
}

impl<'a, const N: usize> Unmarshal<'a> for Tpm2b<'a, N> {
    fn unmarshal_ref(&mut self, mut src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
        let size: usize = u16::unmarshal(&mut src)?.into();
        let (s, src) = src.split_at_checked(size).ok_or(UnmarshalError)?;
        *self = Self::new(s).ok_or(UnmarshalError)?;
        Ok(src)
    }
}

/// `TPM2B_DIGEST`
#[doc(alias("TPM2B_DIGEST"))]
pub type Tpm2bDigest<'a> = Tpm2b<'a, { TpmiAlgHash::MAX_DIGEST_SIZE }>;

/// Implement Marshal for the different [`Tpm2b`]` sizes.
macro_rules! impl_tpm2b_marshal { ($($N:expr),+) => { $(
    impl Marshal for Tpm2b<'_, { $N }> {
        const MAX_SIZE: usize = 2 + $N;
        type MaxBuffer = [u8; 2 + $N];

        fn marshal(&self, dst: &mut [u8; 2 + $N]) -> usize {
            self.marshal_helper(dst)
        }
    }
)+ }; }
impl_tpm2b_marshal!(TpmiAlgHash::MAX_DIGEST_SIZE);
