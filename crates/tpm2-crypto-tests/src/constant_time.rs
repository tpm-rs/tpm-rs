//! Tests for [`ConstantTimeEq`] (and [`digest_eq`]).

use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{ConstantTimeEq, digest_eq as tpm_digest_eq},
};

use crate::{
    Caps,
    util::{pattern, tpmt_ha},
};

fn check<C: ConstantTimeEq, const N: usize>(c: &C) {
    let a: [u8; N] = pattern(N, 7).try_into().expect("pattern length");
    assert!(
        c.constant_time_eq(&a, &a),
        "{N}-byte array differs from itself"
    );
    assert!(c.constant_time_eq(&a, &{ a }), "{N}-byte copies differ");
    let indices = [0, N / 2, N.saturating_sub(1)];
    for index in indices.into_iter().filter(|&i| i < N) {
        for bit in [0x01, 0x80] {
            let mut b = a;
            b[index] ^= bit;
            assert!(
                !c.constant_time_eq(&a, &b),
                "{N}-byte arrays differing at {index} are equal"
            );
        }
    }
}

/// Equal arrays compare equal and arrays differing in any position (first,
/// middle, last) don't, for several lengths (including zero).
pub fn constant_time_eq<C: ConstantTimeEq>(c: &C, _caps: &Caps) {
    check::<C, 0>(c);
    check::<C, 1>(c);
    check::<C, 16>(c);
    check::<C, 20>(c);
    check::<C, 32>(c);
    check::<C, 33>(c);
    check::<C, 64>(c);
}

/// Returns the first `alg.digest_size()` bytes of `data` as a digest.
fn ha(alg: TpmiAlgHash, data: &[u8]) -> TpmtHa<'_> {
    tpmt_ha(alg, &data[..alg.digest_size()])
}

/// [`digest_eq`](tpm_digest_eq) compares both the algorithm and the digest.
pub fn digest_eq<C: ConstantTimeEq>(c: &C, _caps: &Caps) {
    let bytes = pattern(64, 8);
    let other = pattern(64, 9);
    for alg in [TpmiAlgHash::Sha1, TpmiAlgHash::Sha256, TpmiAlgHash::Sha512] {
        assert!(
            tpm_digest_eq(c, ha(alg, &bytes), ha(alg, &bytes)),
            "{alg:?}: equal digests differ"
        );
        assert!(
            !tpm_digest_eq(c, ha(alg, &bytes), ha(alg, &other)),
            "{alg:?}: digests are equal"
        );
    }
    // Same bytes, different algorithms.
    let sha256 = ha(TpmiAlgHash::Sha256, &bytes);
    for alg in [
        TpmiAlgHash::Sha3_256,
        TpmiAlgHash::Sm3_256,
        TpmiAlgHash::Sha1,
    ] {
        assert!(
            !tpm_digest_eq(c, sha256, ha(alg, &bytes)),
            "Sha256 and {alg:?} digests are equal"
        );
    }
}
