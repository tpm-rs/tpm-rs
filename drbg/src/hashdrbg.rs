use crate::{
    helpers::{slice_to_u896, truncate_from_start},
    HashDrbgProps,
};
use core::iter::once;
use crypto_bigint::{prelude::ArrayEncoding, U896};
pub use digest;
use digest::{generic_array::GenericArray, typenum::Unsigned, Digest, Output};

/// [HashDrbg] is a generic software-based construct for creating
/// a Hash DRBG compliant with
/// [NIST SP 800-90Ar1](http://dx.doi.org/10.6028/NIST.SP.800-90Ar1).
///
/// It is based on the specifications outlined in _10.1 DRBG Mechanisms Based
/// on Hash Functions_. This DRBG mechanism implementation uses the
/// highest security strength of available in the hash function. Thus
/// `requested_security_strength` parameter is omitted from arguments to
/// `instantiate` function as well as from the internal state.
///
/// ## Notes
///  `Hash` is expected to be cryptographically secure hash function.
///
pub struct HashDrbg<Hash: Digest + HashDrbgProps> {
    /// _10.1.1.1 1. a._ A value (V) of _seedlen_ bits that is updated during
    /// each call to the DRBG.
    pub(crate) v: GenericArray<u8, Hash::SeedLenBytes>,
    /// _10.1.1.1 1. b._ constant (C) of _seedlen_ bits that depends on the seed
    pub(crate) c: GenericArray<u8, Hash::SeedLenBytes>,
    /// _10.1.1.1 1. c._ A counter (reseed_counter) that indicates the number of
    /// requests for pseudorandom bits since new _entropy_input_ was obtained
    /// during instantiation or reseeding.
    pub(crate) reseed_counter: u64,
}

impl<Hash: Digest + HashDrbgProps> HashDrbg<Hash> {
    /// Generic hash function defined by `Hash` type
    fn hash(data: impl Iterator<Item = impl AsRef<[u8]>>) -> Output<Hash> {
        let mut hasher = Hash::new();
        for item in data {
            hasher.update(item);
        }
        hasher.finalize()
    }
    /// This is `Hash_df()` from _10.3.1_
    ///
    /// This function omits the number of bits to return, it always returns an array of
    /// the length [HashDrbgProps::SeedLenBytes]
    fn hash_df(data: &[&[u8]]) -> GenericArray<u8, Hash::SeedLenBytes> {
        let mut tmp = GenericArray::default();
        let mut counter: u8 = 1;
        let len = Hash::SeedLenBytes::USIZE / Hash::OutputSize::USIZE;
        let no_of_bits_to_return: &[u8] = &(Hash::SeedLenBytes::U32 * 8).to_be_bytes();
        for i in 0..len {
            let counter_byte: &[u8] = &[counter];
            let hashables = once(&counter_byte)
                .chain(once(&no_of_bits_to_return))
                .chain(data.iter());
            let out = Self::hash(hashables);
            tmp[i * Hash::OutputSize::USIZE..(i + 1) * Hash::OutputSize::USIZE]
                .copy_from_slice(&out);
            counter += 1;
        }
        let remainder = Hash::SeedLenBytes::USIZE % Hash::OutputSize::USIZE;
        // we may need to do the hashing on last time
        if remainder != 0 {
            let counter_byte: &[u8] = &[counter];
            let hashables = once(&counter_byte)
                .chain(once(&no_of_bits_to_return))
                .chain(data.iter());
            let out = Self::hash(hashables);
            tmp[len * Hash::OutputSize::USIZE..].copy_from_slice(&out[..remainder]);
        }
        tmp
    }
    /// This is the `Hash_DRBG_Instantiate_algorithm()` from _10.1.1.2_.
    ///
    /// Note that security strength is not used in the
    /// implementation so it is not passed here.
    pub fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        //TODO error handling
        let v = Self::hash_df(&[entropy_input, nonce, personalization_string]);
        let c = Self::hash_df(&[&[0], v.as_slice()]);
        Self {
            v,
            c,
            reseed_counter: 1,
        }
    }
    /// This is the `Hash_DRBG_Reseed_algorithm()` from _10.1.1.3_.
    pub fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        //TODO error handling
        self.v = Self::hash_df(&[&[0x1], self.v.as_slice(), entropy_input, additional_input]);
        self.c = Self::hash_df(&[&[0x0], self.v.as_slice()]);
        self.reseed_counter = 1;
    }
    /// This is the `Hash_DRBG_Generate_algorithm()` from _10.1.1.4_.
    pub fn generate(&mut self, additional_input: &[u8], out: &mut [u8]) {
        // TODO checks
        let p = U896::from_u64(2).shl(Hash::SeedLenBytes::USIZE * 8);
        let mut v = slice_to_u896(&self.v);
        if !additional_input.is_empty() {
            let w = Self::hash([&[0x2], self.v.as_slice(), additional_input].iter());
            // TODO U896 is to much for most of the drbgs
            // try to optimize later by using exactly U440 or U888
            let w = slice_to_u896(&w);
            v = v.add_mod(&w, &p);
            self.v = truncate_from_start(&v.to_be_byte_array());
        }
        self.hash_gen(out);
        let h = Self::hash([&[0x3], self.v.as_slice()].iter());
        let h = slice_to_u896(&h);
        let c = slice_to_u896(&self.c);
        let reseed_counter = U896::from_u64(self.reseed_counter);
        // we do V = (V + H + C + reseed_counter) mod 2^seedlen in multiple steps.
        let v = v.add_mod(&h, &p);
        let v = v.add_mod(&c, &p);
        let v = v.add_mod(&reseed_counter, &p);
        self.v = truncate_from_start(&v.to_be_byte_array());

        self.reseed_counter += 1;
    }
    /// This is the `Hashgen()` function from _10.1.1.4_.
    fn hash_gen(&self, out: &mut [u8]) {
        let m = out.len() / Hash::OutputSize::USIZE;
        let p = U896::from_u64(2).shl(Hash::SeedLenBytes::USIZE * 8);

        let mut data = self.v.clone();
        for i in 0..m {
            let w = Self::hash([&data].iter());
            out[i * Hash::OutputSize::USIZE..(i + 1) * Hash::OutputSize::USIZE].copy_from_slice(&w);
            let mut x = slice_to_u896(&data);
            x = x.add_mod(&U896::ONE, &p);
            data = truncate_from_start(&x.to_be_byte_array());
        }
        let remainder = out.len() % Hash::OutputSize::USIZE;
        // we may need to do the hashing on last time
        if remainder != 0 {
            let w = Self::hash([&data].iter());
            out[m * Hash::OutputSize::USIZE..].copy_from_slice(&w[..remainder]);
        }
    }
}

/*
impl<Hash: Digest + HashDrbgProps> Drbg for HashDrbg<Hash> {
    type Seed = [u8; 10];

    fn from_seed(seed: Self::Seed) -> Self {
        todo!()
    }

    fn reseed(&mut self, seed: Self::Seed) {
        todo!()
    }

    fn next_u32(&mut self) -> u32 {
        todo!()
    }

    fn next_u64(&mut self) -> u64 {
        todo!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        todo!()
    }
}
*/
