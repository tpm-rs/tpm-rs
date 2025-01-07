use crate::{
    bits_to_bytes,
    test::nist_parser::{Alg, RoundEntry, TestVector},
    HashDrbg, HashDrbgProps,
};
use digest::generic_array::GenericArray;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::fs::read_to_string;
use tpm2_rs_server::platform::crypto::Drbg;

/// Returns `true` if line is non-empty and is not a comment.
/// Comments are lines that start with a `#` symbol
fn line_filter(line: &str) -> bool {
    !(line.is_empty() || line.starts_with('#'))
}
fn test_round<Hash: HashDrbgProps>(e: &RoundEntry, out: &mut [u8], reseed: bool, pr: bool) {
    let entropy = GenericArray::from_slice(&e.entropy_input);
    let nonce = GenericArray::from_slice(&e.nonce);
    let mut drbg: HashDrbg<Hash> =
        HashDrbg::instantiate(entropy, nonce, &e.personalization_string).unwrap();
    assert_eq!(drbg.v.as_slice(), e.states[0].v.as_slice());
    assert_eq!(drbg.c.as_slice(), e.states[0].c.as_slice());
    assert_eq!(drbg.reseed_counter, e.states[0].reseed_counter);
    let i = if reseed {
        let entropy = GenericArray::from_slice(&e.entropy_input_reseed);
        drbg.reseed(entropy, &e.additional_input_reseed).unwrap();
        assert_eq!(drbg.v.as_slice(), e.states[1].v.as_slice());
        assert_eq!(drbg.c.as_slice(), e.states[1].c.as_slice());
        assert_eq!(drbg.reseed_counter, e.states[1].reseed_counter);

        1
    } else {
        0
    };
    if pr {
        let entropy = GenericArray::from_slice(&e.entropy_input_pr1);
        drbg.reseed(entropy, &e.additional_input1).unwrap();
        drbg.fill_bytes(&[], out).unwrap();
    } else {
        drbg.fill_bytes(&e.additional_input1, out).unwrap();
    }
    assert_eq!(drbg.v.as_slice(), e.states[i + 1].v.as_slice());
    assert_eq!(drbg.c.as_slice(), e.states[i + 1].c.as_slice());
    assert_eq!(drbg.reseed_counter, e.states[i + 1].reseed_counter);
    if pr {
        let entropy = GenericArray::from_slice(&e.entropy_input_pr2);
        drbg.reseed(entropy, &e.additional_input2).unwrap();
        drbg.fill_bytes(&[], out).unwrap();
    } else {
        drbg.fill_bytes(&e.additional_input2, out).unwrap();
    }
    assert_eq!(drbg.v.as_slice(), e.states[i + 2].v.as_slice());
    assert_eq!(drbg.c.as_slice(), e.states[i + 2].c.as_slice());
    assert_eq!(drbg.reseed_counter, e.states[i + 2].reseed_counter);
    assert_eq!(out, e.returned_bits);
}

fn test_rounds<Hash: HashDrbgProps>(vector: &TestVector, reseed: bool) {
    let mut out = vec![0; bits_to_bytes(vector.props.returned_bits_len)];
    for entry in &vector.entries {
        test_round::<Hash>(entry, &mut out, reseed, vector.props.prediction_resistance);
    }
}

fn test_vector(path: &str, reseed: bool) {
    let text = read_to_string(path).unwrap();
    let mut lines = text
        .split("\n")
        .map(|line| line.trim())
        .filter(|line| line_filter(line))
        .peekable();
    let vectors = TestVector::parse(&mut lines, reseed);
    for vector in vectors {
        match vector.props.alg {
            Alg::Sha1 => test_rounds::<Sha1>(&vector, reseed),
            Alg::Sha224 => test_rounds::<Sha224>(&vector, reseed),
            Alg::Sha256 => test_rounds::<Sha256>(&vector, reseed),
            Alg::Sha384 => test_rounds::<Sha384>(&vector, reseed),
            Alg::Sha512 => test_rounds::<Sha512>(&vector, reseed),
            Alg::Sha512_224 => test_rounds::<Sha512_224>(&vector, reseed),
            Alg::Sha512_256 => test_rounds::<Sha512_256>(&vector, reseed),
        }
    }
}

#[test]
fn test_hash_drbg_no_reseed() {
    test_vector("./vectors/no_reseed/Hash_DRBG.txt", false);
}

#[test]
fn test_hash_drbg_pr_false() {
    test_vector("./vectors/pr_false/Hash_DRBG.txt", true);
}

#[test]
fn test_hash_drbg_pr_true() {
    test_vector("./vectors/pr_true/Hash_DRBG.txt", false);
}
