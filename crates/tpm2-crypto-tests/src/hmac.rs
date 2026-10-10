//! Tests for [`Hmac`] (via [`HmacStream`] and [`hmac`]).

use tpm2::{
    TpmiAlgHash,
    crypto::{Hash, Hmac, HmacStream, hash, hmac},
};

use crate::{
    Caps, Check, expect_support,
    util::{HASHES, assert_bytes, pattern},
    vectors::hmac as kat,
};

fn vectors(alg: TpmiAlgHash) -> &'static [&'static [u8]] {
    match alg {
        TpmiAlgHash::Sha1 => kat::SHA1,
        TpmiAlgHash::Sha256 => kat::SHA256,
        TpmiAlgHash::Sha384 => kat::SHA384,
        TpmiAlgHash::Sha512 => kat::SHA512,
        TpmiAlgHash::Sm3_256 => kat::SM3_256,
        TpmiAlgHash::Sha3_256 => kat::SHA3_256,
        TpmiAlgHash::Sha3_384 => kat::SHA3_384,
        TpmiAlgHash::Sha3_512 => kat::SHA3_512,
    }
}

/// Returns `true` if HMAC with `alg` is supported (checking that it
/// correctly fails otherwise).
fn supported<C: Hmac>(c: &C, caps: &Caps, alg: TpmiAlgHash) -> bool {
    let result = HmacStream::new(c, alg, b"key");
    expect_support(caps.hmac.contains(&alg), format!("Hmac {alg:?}"), result).is_some()
}

/// Computes a one-shot MAC.
fn mac<C: Hmac>(c: &C, alg: TpmiAlgHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let tag = hmac(c, alg, key, data, &mut out).check(format!("hmac {alg:?}"));
    assert_eq!(tag.hash_alg(), alg, "hmac returned the wrong algorithm");
    tag.digest().to_vec()
}

fn kat<C: Hmac>(c: &C, caps: &Caps, alg: TpmiAlgHash) {
    if !supported(c, caps, alg) {
        return;
    }
    for (i, ((key, data), expected)) in kat::CASES.iter().zip(vectors(alg)).enumerate() {
        assert_bytes(
            &mac(c, alg, key, data),
            expected,
            format!("HMAC-{alg:?} case {i}"),
        );
    }
}

macro_rules! kat_fns {
    ($($name:ident => $alg:ident),* $(,)?) => {$(
        #[doc = concat!("Known answers for HMAC-", stringify!($alg), " (RFC 4231 test cases, and an empty key and message).")]
        pub fn $name<C: Hmac>(c: &C, caps: &Caps) {
            kat(c, caps, TpmiAlgHash::$alg);
        }
    )*};
}

kat_fns! {
    hmac_sha1_kat => Sha1,
    hmac_sha256_kat => Sha256,
    hmac_sha384_kat => Sha384,
    hmac_sha512_kat => Sha512,
    hmac_sm3_256_kat => Sm3_256,
    hmac_sha3_256_kat => Sha3_256,
    hmac_sha3_384_kat => Sha3_384,
    hmac_sha3_512_kat => Sha3_512,
}

/// Streaming input in chunks gives the same MAC as one-shot calculation, for
/// keys shorter than, equal to, and longer than the block size.
pub fn hmac_streaming<C: Hmac>(c: &C, caps: &Caps) {
    let data = pattern(1000, 2);
    for &alg in HASHES {
        if !supported(c, caps, alg) {
            continue;
        }
        let block = alg.block_size();
        for key_len in [0, 1, block - 1, block, block + 1, 2 * block + 3] {
            let key = pattern(key_len, 3);
            for len in [0, 1, block, 100, data.len()] {
                let data = &data[..len];
                let expected = mac(c, alg, &key, data);
                for chunk in [1, 7, block] {
                    let mut stream = HmacStream::new(c, alg, &key).check("HmacStream::new");
                    for part in data.chunks(chunk) {
                        stream.update(part).check("HmacStream::update");
                    }
                    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
                    let actual = stream.finalize(&mut out).check("HmacStream::finalize");
                    assert_bytes(
                        actual.digest(),
                        &expected,
                        format!(
                            "HMAC-{alg:?} ({key_len}-byte key, {len} bytes, {chunk}-byte chunks)"
                        ),
                    );
                }
            }
        }
    }
}

/// HMAC key handling (RFC 2104): keys longer than the block size are hashed
/// first, and shorter keys are padded with zeros.
pub fn hmac_key_handling<C: Hmac + Hash>(c: &C, caps: &Caps) {
    let data = b"HMAC key handling";
    for &alg in HASHES {
        if !supported(c, caps, alg) {
            continue;
        }
        let block = alg.block_size();
        // Zero padding: K and K || 0x00... (up to the block size) are equivalent.
        let key = pattern(block / 2, 4);
        let mut padded = key.clone();
        padded.resize(block, 0);
        assert_bytes(
            &mac(c, alg, &padded, data),
            &mac(c, alg, &key, data),
            format!("HMAC-{alg:?} with a zero-padded key"),
        );
        // Long keys: HMAC(K) == HMAC(H(K)) (needs the hash itself).
        if !caps.hash.contains(&alg) {
            continue;
        }
        let long_key = pattern(block + 1, 5);
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let hashed = hash(c, alg, &long_key, &mut out).check("hash");
        assert_bytes(
            &mac(c, alg, &long_key, data),
            &mac(c, alg, hashed.digest(), data),
            format!("HMAC-{alg:?} with a key longer than the block size"),
        );
    }
}
