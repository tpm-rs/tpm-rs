//! Tests for [`kdfa`] and [`kdfe`] with each backend's [`Hmac`] and [`Hash`].

use tpm2::{
    TpmiAlgHash,
    crypto::{Hash, Hmac, kdfa, kdfe},
};

use crate::{
    Caps, expect_support,
    util::{HASHES, assert_bytes},
    vectors::kdf::{self as kat, KdfKat},
};

fn kdfa_vectors(alg: TpmiAlgHash) -> &'static [KdfKat; 3] {
    match alg {
        TpmiAlgHash::Sha1 => &kat::KDFA_SHA1,
        TpmiAlgHash::Sha256 => &kat::KDFA_SHA256,
        TpmiAlgHash::Sha384 => &kat::KDFA_SHA384,
        TpmiAlgHash::Sha512 => &kat::KDFA_SHA512,
        TpmiAlgHash::Sm3_256 => &kat::KDFA_SM3_256,
        TpmiAlgHash::Sha3_256 => &kat::KDFA_SHA3_256,
        TpmiAlgHash::Sha3_384 => &kat::KDFA_SHA3_384,
        TpmiAlgHash::Sha3_512 => &kat::KDFA_SHA3_512,
    }
}

fn kdfe_vectors(alg: TpmiAlgHash) -> &'static [KdfKat; 3] {
    match alg {
        TpmiAlgHash::Sha1 => &kat::KDFE_SHA1,
        TpmiAlgHash::Sha256 => &kat::KDFE_SHA256,
        TpmiAlgHash::Sha384 => &kat::KDFE_SHA384,
        TpmiAlgHash::Sha512 => &kat::KDFE_SHA512,
        TpmiAlgHash::Sm3_256 => &kat::KDFE_SM3_256,
        TpmiAlgHash::Sha3_256 => &kat::KDFE_SHA3_256,
        TpmiAlgHash::Sha3_384 => &kat::KDFE_SHA3_384,
        TpmiAlgHash::Sha3_512 => &kat::KDFE_SHA3_512,
    }
}

/// KDFa known answers for every HMAC algorithm: multi-block output with a
/// partial final block, a short output, and empty inputs.
pub fn kdfa_kat<C: Hmac>(c: &C, caps: &Caps) {
    for &alg in HASHES {
        for (i, v) in kdfa_vectors(alg).iter().enumerate() {
            let mut out = vec![0u8; v.out.len()];
            let result = kdfa(c, alg, v.key, v.label, v.context_u, v.context_v, &mut out);
            if expect_support(caps.hmac.contains(&alg), format!("kdfa {alg:?}"), result).is_none() {
                break;
            }
            assert_bytes(&out, v.out, format!("kdfa {alg:?} vector {i}"));
        }
    }
}

/// KDFe known answers for every hash algorithm: multi-block output with a
/// partial final block, a short output, and empty inputs.
pub fn kdfe_kat<C: Hash>(c: &C, caps: &Caps) {
    for &alg in HASHES {
        for (i, v) in kdfe_vectors(alg).iter().enumerate() {
            let mut out = vec![0u8; v.out.len()];
            let result = kdfe(c, alg, v.key, v.label, v.context_u, v.context_v, &mut out);
            if expect_support(caps.hash.contains(&alg), format!("kdfe {alg:?}"), result).is_none() {
                break;
            }
            assert_bytes(&out, v.out, format!("kdfe {alg:?} vector {i}"));
        }
    }
}
