//! Tests for [`Hash`] (via [`HashStream`] and [`hash`]).

use tpm2::{
    TpmiAlgHash,
    crypto::{Hash, HashStream, hash},
};

use crate::{
    Caps, Check, expect_support,
    util::{HASHES, Hex, assert_bytes, pattern},
    vectors::hash as kat,
};

type HashVector = (&'static [u8], &'static [u8]);

/// Returns the `(message, digest)` pairs and the digest of one million `'a'`.
fn vectors(alg: TpmiAlgHash) -> (&'static [HashVector], &'static [u8]) {
    match alg {
        TpmiAlgHash::Sha1 => (kat::SHA1, &kat::SHA1_MILLION_A),
        TpmiAlgHash::Sha256 => (kat::SHA256, &kat::SHA256_MILLION_A),
        TpmiAlgHash::Sha384 => (kat::SHA384, &kat::SHA384_MILLION_A),
        TpmiAlgHash::Sha512 => (kat::SHA512, &kat::SHA512_MILLION_A),
        TpmiAlgHash::Sm3_256 => (kat::SM3_256, &kat::SM3_256_MILLION_A),
        TpmiAlgHash::Sha3_256 => (kat::SHA3_256, &kat::SHA3_256_MILLION_A),
        TpmiAlgHash::Sha3_384 => (kat::SHA3_384, &kat::SHA3_384_MILLION_A),
        TpmiAlgHash::Sha3_512 => (kat::SHA3_512, &kat::SHA3_512_MILLION_A),
    }
}

/// Starts a [`HashStream`] for `alg`, or returns `None` if `alg` is
/// (correctly) unsupported.
fn start<C: Hash>(c: &C, caps: &Caps, alg: TpmiAlgHash) -> Option<HashStream<C>> {
    expect_support(
        caps.hash.contains(&alg),
        format!("Hash {alg:?}"),
        HashStream::new(c, alg),
    )
}

/// Computes a one-shot digest.
fn digest<C: Hash>(c: &C, alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = hash(c, alg, data, &mut out).check(format!("hash {alg:?}"));
    assert_eq!(digest.hash_alg(), alg, "hash returned the wrong algorithm");
    digest.digest().to_vec()
}

fn kat<C: Hash>(c: &C, caps: &Caps, alg: TpmiAlgHash) {
    let Some(_) = start(c, caps, alg) else {
        return;
    };
    let (pairs, million_a) = vectors(alg);
    for (message, expected) in pairs {
        assert_bytes(
            &digest(c, alg, message),
            expected,
            format!("{alg:?}({})", Hex(message)),
        );
    }

    // One million 'a', in 1000-byte updates.
    let mut stream = HashStream::new(c, alg).check("HashStream::new");
    for _ in 0..1000 {
        stream.update(&[b'a'; 1000]).check("HashStream::update");
    }
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = stream.finalize(&mut out).check("HashStream::finalize");
    assert_eq!(digest.hash_alg(), alg);
    assert_bytes(digest.digest(), million_a, format!("{alg:?}(1M 'a')"));
}

macro_rules! kat_fns {
    ($($name:ident => $alg:ident),* $(,)?) => {$(
        #[doc = concat!("Known answers for ", stringify!($alg), " (empty, `\"abc\"`, 448-bit, and one million `'a'` messages).")]
        pub fn $name<C: Hash>(c: &C, caps: &Caps) {
            kat(c, caps, TpmiAlgHash::$alg);
        }
    )*};
}

kat_fns! {
    sha1_kat => Sha1,
    sha256_kat => Sha256,
    sha384_kat => Sha384,
    sha512_kat => Sha512,
    sm3_256_kat => Sm3_256,
    sha3_256_kat => Sha3_256,
    sha3_384_kat => Sha3_384,
    sha3_512_kat => Sha3_512,
}

/// Streaming input in chunks of any size (including empty updates) gives the
/// same digest as one-shot hashing, around block boundaries.
pub fn hash_streaming<C: Hash>(c: &C, caps: &Caps) {
    let data = pattern(1000, 1);
    for &alg in HASHES {
        if start(c, caps, alg).is_none() {
            continue;
        }
        let block = alg.block_size();
        for len in [
            0,
            1,
            block - 1,
            block,
            block + 1,
            2 * block,
            2 * block + 1,
            data.len(),
        ] {
            let data = &data[..len];
            let expected = digest(c, alg, data);
            for chunk in [1, 7, block - 1, block, block + 1] {
                let mut stream = HashStream::new(c, alg).check("HashStream::new");
                for part in data.chunks(chunk) {
                    stream.update(part).check("HashStream::update");
                    stream.update(&[]).check("HashStream::update (empty)");
                }
                let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
                let actual = stream.finalize(&mut out).check("HashStream::finalize");
                assert_bytes(
                    actual.digest(),
                    &expected,
                    format!("{alg:?} of {len} bytes in {chunk}-byte chunks"),
                );
            }
        }
    }
}
