//! Tests for [`Cmac`] (via [`CmacStream`] and [`cmac`]).

use tpm2::{
    AlgSym,
    crypto::{Cmac, CmacStream, SymmetricKey, cmac},
};

use crate::{
    Caps, Check, expect_support,
    symmetric::key,
    util::{CIPHERS, assert_bytes, pattern},
    vectors::cipher as kat,
};

/// Returns `true` if CMAC with `alg` is supported (checking that it correctly
/// fails otherwise).
fn supported<C: Cmac>(c: &C, caps: &Caps, alg: AlgSym) -> bool {
    let result = CmacStream::new(c, key(alg));
    expect_support(caps.cmac.contains(&alg), format!("Cmac {alg:?}"), result).is_some()
}

/// Computes a one-shot CMAC.
fn mac<C: Cmac>(c: &C, key: SymmetricKey<'_>, data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    cmac(c, key, data, &mut out).check(format!("cmac {:?}", key.alg()));
    out
}

fn kat<C: Cmac>(c: &C, caps: &Caps, alg: AlgSym, expected: &[[u8; 16]; 4]) {
    if !supported(c, caps, alg) {
        return;
    }
    for (len, expected) in kat::CMAC_LENS.iter().zip(expected) {
        assert_bytes(
            &mac(c, key(alg), &kat::PLAINTEXT[..*len]),
            expected,
            format!("CMAC-{alg:?} of {len} bytes"),
        );
    }
}

macro_rules! kat_fns {
    ($($name:ident => $alg:ident, $vectors:ident;)*) => {$(
        #[doc = concat!("Known answers for CMAC-", stringify!($alg), " (NIST SP 800-38B messages).")]
        pub fn $name<C: Cmac>(c: &C, caps: &Caps) {
            kat(c, caps, AlgSym::$alg, &kat::$vectors);
        }
    )*};
}

kat_fns! {
    cmac_aes128_kat => Aes128, CMAC_AES128;
    cmac_aes192_kat => Aes192, CMAC_AES192;
    cmac_aes256_kat => Aes256, CMAC_AES256;
    cmac_sm4_128_kat => Sm4_128, CMAC_SM4_128;
    cmac_camellia128_kat => Camellia128, CMAC_CAMELLIA128;
    cmac_camellia192_kat => Camellia192, CMAC_CAMELLIA192;
    cmac_camellia256_kat => Camellia256, CMAC_CAMELLIA256;
}

/// Streaming input in chunks gives the same MAC as one-shot calculation, for
/// messages around block boundaries.
pub fn cmac_streaming<C: Cmac>(c: &C, caps: &Caps) {
    let data = pattern(1000, 6);
    for &alg in CIPHERS {
        if !supported(c, caps, alg) {
            continue;
        }
        for len in (0..=49).chain([100, data.len()]) {
            let data = &data[..len];
            let expected = mac(c, key(alg), data);
            for chunk in [1, 15, 16, 17] {
                let mut stream = CmacStream::new(c, key(alg)).check("CmacStream::new");
                for part in data.chunks(chunk) {
                    stream.update(part).check("CmacStream::update");
                }
                let mut out = [0u8; 16];
                stream.finalize(&mut out).check("CmacStream::finalize");
                assert_bytes(
                    &out,
                    &expected,
                    format!("CMAC-{alg:?} of {len} bytes in {chunk}-byte chunks"),
                );
            }
        }
    }
}
