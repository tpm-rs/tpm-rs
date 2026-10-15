//! Checks the linked reference code against outputs of the C reference code (`mstpm20` at the
//! pinned commit, with the differential-testing profile), produced by a small C program that calls
//! the same functions (`DRBG_InstantiateSeeded()`, `DRBG_Generate()`, `CryptRsaGenerateKey()`,
//! `TpmEcc_GenPrivateScalar()`, `TpmEcc_SignEcdsa()`) with the inputs below. These guard the
//! Rust glue in `ffi.rs` (argument passing, state conversion, output layout).

use hex_literal::hex;
use tpm2::TpmEccCurve;

use super::RefRng;
use super::drbg::{fill, instantiate_seeded};
use super::{ecc, rsa};

/// `"Primary Object Creation"` including its terminating NUL (`PRIMARY_OBJECT_CREATION`).
const PRIMARY_OBJECT_CREATION: &[u8] = b"Primary Object Creation\0";

/// `n` bytes `start, start + 7, start + 14, ...` (the C program's `fill()`).
fn pattern(n: usize, start: u8) -> alloc::vec::Vec<u8> {
    (0..n).map(|i| start.wrapping_add((i * 7) as u8)).collect()
}

/// The next 16 bytes of the seeded DRBG `st`.
fn next16(st: &mut crate::DrbgState) -> [u8; 16] {
    let mut after = [0u8; 16];
    fill(&mut RefRng::seeded_only(), Some(st), &mut after).unwrap();
    after
}

#[test]
fn seeded_drbg_matches_c() {
    let (seed, name, add) = (pattern(32, 1), pattern(34, 100), pattern(5, 200));
    let mut st = instantiate_seeded(&seed, PRIMARY_OBJECT_CREATION, &name, &add).unwrap();
    let mut out = [0u8; 100];
    fill(&mut RefRng::seeded_only(), Some(&mut st), &mut out).unwrap();
    assert_eq!(
        out,
        hex!(
            "0abe824fe60a933d40ec1c357a0a410a26201984ec0914c3b6cbcbb6de047540"
            "0bf5ffd48611027de5dde15953fc50ce5678ec7130d45a535d9863b5f6ec337e"
            "159d20c37a5d1ea8ac67896690188486cdec03b21a97d5aab039c12aed4a69fe"
            "df48c786"
        )
    );
}

#[test]
fn rsa_2048_signing_key_matches_c() {
    let (seed, name) = (pattern(32, 1), pattern(34, 100));
    let mut st = instantiate_seeded(&seed, PRIMARY_OBJECT_CREATION, &name, &[]).unwrap();
    let (mut n, mut prime) = ([0u8; 256], [0u8; 128]);
    let e = rsa::generate_key(
        &mut RefRng::seeded_only(),
        Some(&mut st),
        2048,
        0,
        true,
        &mut n,
        &mut prime,
    )
    .unwrap();
    assert_eq!(e, 65537);
    assert_eq!(
        n,
        hex!(
            "c5c16b543f6e84d6380ccc080bda37aa3f3f0020810344e63a93a929209cc7ca"
            "0ddb7114fe22aeb9ab0acd27e9c92d67d88d9dffd3fda55adf6cc0840aed8e22"
            "fd8aedeb6765bd4d2cc8607564503a94a6929377211496bb04d7077b6efd7192"
            "e8ef417be604e8ab0804437caed4fde339a4a2adcb4c8e8d4058412e0faad537"
            "76a0882682d88c489dae05836181e5d0a4bc29355e87635e8b361ac762e0f624"
            "a5c74d6b25bea47e959c2a1d850f912a750ddf6368f3b134ed78376c615d176e"
            "c58b05327b67bb34a3e61630d007eea84a0fb531c782effcb03df5f38cac4436"
            "4cc0a108dfedd0ff1898890a780604e9b62625ce9f2e0fb589ba957cbafb189b"
        )
    );
    assert_eq!(
        prime,
        hex!(
            "d4e4dfe679c73d52ab5ccee7c67ddbbf51caf76710e49ea937e5e2340a2d8276"
            "b324e8ca28bf730f502a8a8fae57435c414481aa0043a28016933a8c583d68e0"
            "ccc3c2004a546f2cb1bb3ebe654e7ab416047e5f29075dcd20e899b4f1f50f39"
            "c743a10eb22c5a1ce5c9d3dd7ca255ab571308136298848f6fb279f43b413ea5"
        )
    );
    // The DRBG is left exactly where the C code left it.
    assert_eq!(next16(&mut st), hex!("f5715f2000d60cba19bf869ab57eda39"));
}

#[test]
fn rsa_1024_decryption_key_matches_c() {
    let (seed, name) = (pattern(32, 1), pattern(34, 100));
    let mut st = instantiate_seeded(&name, PRIMARY_OBJECT_CREATION, &seed, &[]).unwrap();
    let (mut n, mut prime) = ([0u8; 128], [0u8; 64]);
    rsa::generate_key(
        &mut RefRng::seeded_only(),
        Some(&mut st),
        1024,
        0,
        false,
        &mut n,
        &mut prime,
    )
    .unwrap();
    assert_eq!(
        n,
        hex!(
            "b45de0b1c8b3d69c4a413d4d2fe740e2552090188901f37cbfca640e9a43c8f7"
            "a09932355b977d445f8e96df7d64a0437469cc78aaba1d264900088b8475a893"
            "a62f9f8d7688a7229f122b59c9994e4df5297e19a79128da3bf772ff890fc9bf"
            "7a53375289e5509f82e155ab90ed4869cea12dc656750b79130b89e0e4cbd369"
        )
    );
    assert_eq!(
        prime,
        hex!(
            "f54de687f11787193bc04bf208a417b4d125b8045f430939b82e13b8d7a12551"
            "0d70af29e35abfd662551ba377fa7196969019242544e6e83b0c3e8567b481ad"
        )
    );
    assert_eq!(next16(&mut st), hex!("95c01c8e16b43c28ad3614cc44103066"));
}

#[test]
fn ecc_scalar_and_ecdsa_match_c() {
    let add = pattern(5, 200);
    let mut st = instantiate_seeded(&add, PRIMARY_OBJECT_CREATION, &[], &[]).unwrap();
    // A decryption key: `TpmEcc_GenPrivateScalar()` and the point multiplication only.
    let (mut d, mut q) = ([0u8; 32], [0u8; 64]);
    let len = ecc::generate_key(
        &mut RefRng::seeded_only(),
        Some(&mut st),
        TpmEccCurve::NistP256,
        false,
        &mut d,
        &mut q,
    )
    .unwrap();
    assert_eq!(len, 32);
    assert_eq!(
        d,
        hex!("e53dac0a1e82f8cc69fbc227cd8c202e7bd5f606e4a2452b618f9437c7aec1b1")
    );
    let digest = pattern(32, 9);
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    let len = ecc::sign_ecdsa(
        &mut RefRng::seeded_only(),
        Some(&mut st),
        TpmEccCurve::NistP256,
        &d,
        &digest,
        &mut r,
        &mut s,
    )
    .unwrap();
    assert_eq!(len, 32);
    assert_eq!(
        r,
        hex!("3edc22e67286fcb796db5632304f7212a5cc86effd26a2ea353cf256ff77e98d")
    );
    assert_eq!(
        s,
        hex!("52d0a3d97c0d99bf4b4dd9dc83b3bcd286173c857a0d639009af0243bb43d565")
    );
    assert_eq!(next16(&mut st), hex!("5a7a67d6dfd6db8fa133d47260e93507"));
}
