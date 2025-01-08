//! This is ad-hoc parser for the txt test vectors coming from [CAVP Testing:
//! Random Number Generators](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Random-Number-Generators).
//! This parser is rigid like a dense block of concrete. Its sole purpose in
//! existence is to take the text vectors provided by nist and convert them
//! to an in-memory data structure.
//!
//! Tests vectors are pulled from [DRBG Test
//! Vectors](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip)
//! Warning: According to NIST CAVP Testing: Random Number page: use of these vectors does not take the place of validation obtained
//! through the Automated Cryptographic Algorithm Validation Program (CAVP).
//!
//! Getting access to Cryptographic Algorithm Validation Program is quite the process and is described here:
//! https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/how-to-access-acvts

use core::{error::Error, iter::Peekable, panic, str::FromStr};

/// parse something on the form of `k = v`
fn parse_kv(line: &str) -> (&str, &str) {
    let parts: Vec<&str> = line.split('=').map(|item| item.trim()).collect();
    if parts.len() != 2 {
        panic!("Invalid line format");
    }
    (parts[0], parts[1])
}

fn hex_to_vec_u8(hex: &str) -> Vec<u8> {
    if hex.len() % 2 != 0 {
        panic!("Hex string must have an even length");
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => panic!("Invalid hex character in '{}'", byte_str),
        }
    }
    bytes
}

fn parse_kv_from_str<'a, Err: Error, F: FromStr<Err = Err>>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> F {
    let line = lines
        .next()
        .unwrap_or_else(|| panic!("Expected `{key} = number`, but found end of file."));
    let (entry_key, entry_val) = parse_kv(line);
    assert_eq!(entry_key, key);
    entry_val.parse().unwrap()
}

fn parse_hex<'a>(lines: &mut impl Iterator<Item = &'a str>, key: &str) -> Vec<u8> {
    let line = lines
        .next()
        .unwrap_or_else(|| panic!("Expected `{key} = number`, but found end of file."));
    let (entry_key, entry_val) = parse_kv(line);
    assert_eq!(entry_key, key);
    hex_to_vec_u8(entry_val)
}

pub struct State {
    pub v: Vec<u8>,
    pub c: Vec<u8>,
    pub reseed_counter: u64,
}

impl State {
    fn parse<'a>(lines: &mut impl Iterator<Item = &'a str>) -> State {
        let v = parse_hex(lines, "V");
        let c = parse_hex(lines, "C");
        let reseed_counter = parse_kv_from_str(lines, "reseed counter");
        State {
            v,
            c,
            reseed_counter,
        }
    }
}
pub struct RoundEntry {
    pub entropy_input: Vec<u8>,
    pub nonce: Vec<u8>,
    pub personalization_string: Vec<u8>,
    pub entropy_input_reseed: Vec<u8>,
    pub additional_input_reseed: Vec<u8>,
    pub additional_input1: Vec<u8>,
    pub entropy_input_pr1: Vec<u8>,
    pub additional_input2: Vec<u8>,
    pub entropy_input_pr2: Vec<u8>,
    pub states: Vec<State>,
    pub returned_bits: Vec<u8>,
}

impl RoundEntry {
    /// It may be the case that entries are done, and we are back to parse properties.
    /// In that case we return `None`
    fn parse_count<'a>(lines: &mut Peekable<impl Iterator<Item = &'a str>>) -> Option<()> {
        let line = lines.peek()?;
        if line.starts_with('[') {
            return None;
        }
        let (entry_key, entry_val) = parse_kv(line);
        assert_eq!(entry_key, "COUNT");
        let _: usize = entry_val.parse().unwrap();
        lines.next();
        Some(())
    }
    fn expect_line<'a>(lines: &mut impl Iterator<Item = &'a str>, line: &str) {
        let line_input = lines
            .next()
            .unwrap_or_else(|| panic!("Expected `{line}`, but found end of file."));
        assert_eq!(line_input, line);
    }
    fn parse_one<'a>(
        lines: &mut Peekable<impl Iterator<Item = &'a str>>,
        props: &TestVectorProps,
        reseed: bool,
    ) -> Option<RoundEntry> {
        let mut states = Vec::new();
        Self::parse_count(lines)?;
        let entropy_input = parse_hex(lines, "EntropyInput");
        assert_eq!(entropy_input.len() * 8, props.entropy_input_len);
        let nonce = parse_hex(lines, "Nonce");
        assert_eq!(nonce.len() * 8, props.nonce_len);
        let personalization_string = parse_hex(lines, "PersonalizationString");
        assert_eq!(
            personalization_string.len() * 8,
            props.personalization_string_len
        );
        Self::expect_line(lines, "** INSTANTIATE:");
        states.push(State::parse(lines));
        let entropy_input_reseed;
        let additional_input_reseed;
        if reseed {
            entropy_input_reseed = parse_hex(lines, "EntropyInputReseed");
            assert_eq!(entropy_input_reseed.len() * 8, props.entropy_input_len);
            additional_input_reseed = parse_hex(lines, "AdditionalInputReseed");
            Self::expect_line(lines, "** RESEED:");
            states.push(State::parse(lines));
        } else {
            entropy_input_reseed = Vec::new();
            additional_input_reseed = Vec::new();
        }
        let additional_input1 = parse_hex(lines, "AdditionalInput");
        assert_eq!(additional_input1.len() * 8, props.additional_input_len);
        let entropy_input_pr1;
        if props.prediction_resistance {
            entropy_input_pr1 = parse_hex(lines, "EntropyInputPR");
            assert_eq!(entropy_input_pr1.len() * 8, props.entropy_input_len);
        } else {
            entropy_input_pr1 = Vec::new()
        };
        Self::expect_line(lines, "** GENERATE (FIRST CALL):");
        states.push(State::parse(lines));
        let additional_input2 = parse_hex(lines, "AdditionalInput");
        let entropy_input_pr2;
        if props.prediction_resistance {
            entropy_input_pr2 = parse_hex(lines, "EntropyInputPR");
            assert_eq!(entropy_input_pr2.len() * 8, props.entropy_input_len);
        } else {
            entropy_input_pr2 = Vec::new()
        };
        assert_eq!(additional_input2.len() * 8, props.additional_input_len);
        let returned_bits = parse_hex(lines, "ReturnedBits");
        assert_eq!(returned_bits.len() * 8, props.returned_bits_len);
        Self::expect_line(lines, "** GENERATE (SECOND CALL):");
        states.push(State::parse(lines));
        Some(RoundEntry {
            entropy_input,
            nonce,
            personalization_string,
            entropy_input_reseed,
            additional_input_reseed,
            additional_input1,
            entropy_input_pr1,
            additional_input2,
            entropy_input_pr2,
            states,
            returned_bits,
        })
    }
    fn parse<'a>(
        lines: &mut Peekable<impl Iterator<Item = &'a str>>,
        props: &TestVectorProps,
        reseed: bool,
    ) -> Vec<RoundEntry> {
        let mut entries = Vec::new();
        while let Some(entry) = RoundEntry::parse_one(lines, props, reseed) {
            entries.push(entry);
        }
        entries
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Alg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
}

impl Alg {
    /// parses one of the approved hash functions:
    fn parse<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Option<Alg> {
        let alg_line = lines.next()?;
        let alg = match alg_line {
            "[SHA-1]" => Alg::Sha1,
            "[SHA-224]" => Alg::Sha224,
            "[SHA-256]" => Alg::Sha256,
            "[SHA-384]" => Alg::Sha384,
            "[SHA-512]" => Alg::Sha512,
            "[SHA-512/224]" => Alg::Sha512_224,
            "[SHA-512/256]" => Alg::Sha512_256,
            _ => panic!("Unsupported DRBG algorithm `{alg_line}`"),
        };
        Some(alg)
    }
}

pub struct TestVectorProps {
    pub alg: Alg,
    pub prediction_resistance: bool,
    pub entropy_input_len: usize,
    /// in bits
    pub nonce_len: usize,
    /// in bits
    pub personalization_string_len: usize,
    /// in bits
    pub additional_input_len: usize,
    /// in bits
    pub returned_bits_len: usize,
}

impl TestVectorProps {
    /// parse something on the form of [k = v]
    fn parse_square_bracket_kv(line: &str) -> (&str, &str) {
        if !(line.starts_with('[') && line.ends_with(']')) {
            panic!("Expected a line that stars and ends with [ ], instead foud, {line}");
        }
        let line = &line[1..line.len() - 1];
        parse_kv(line)
    }

    fn parse_prediction_resistance<'a>(lines: &mut impl Iterator<Item = &'a str>) -> bool {
        let line = lines
            .next()
            .expect("Expected `[PredictionResistance = True/False]`, but found end of file.");
        let (key, val) = Self::parse_square_bracket_kv(line);
        assert_eq!(key, "PredictionResistance");
        match val {
            "True" => true,
            "False" => false,
            _ => panic!("Expected `True/False`, but found `{line}`"),
        }
    }
    fn parse_square_bracket_number<'a>(
        lines: &mut impl Iterator<Item = &'a str>,
        key: &str,
    ) -> usize {
        let line = lines
            .next()
            .unwrap_or_else(|| panic!("Expected `[{key} = number]`, but found end of file."));
        let (entry_key, entry_val) = Self::parse_square_bracket_kv(line);
        assert_eq!(entry_key, key);
        entry_val.parse().unwrap()
    }
    /// attempts to parse one full test vector, will panic if it fails to parse
    /// will return None if there is nothing left to parse
    fn parse<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Option<TestVectorProps> {
        let alg = Alg::parse(lines)?;
        let prediction_resistance = Self::parse_prediction_resistance(lines);
        let entropy_input_len = Self::parse_square_bracket_number(lines, "EntropyInputLen");
        let nonce_len = Self::parse_square_bracket_number(lines, "NonceLen");
        let personalization_string_len =
            Self::parse_square_bracket_number(lines, "PersonalizationStringLen");
        let additional_input_len = Self::parse_square_bracket_number(lines, "AdditionalInputLen");
        let returned_bits_len = Self::parse_square_bracket_number(lines, "ReturnedBitsLen");
        Some(TestVectorProps {
            alg,
            prediction_resistance,
            entropy_input_len,
            nonce_len,
            personalization_string_len,
            additional_input_len,
            returned_bits_len,
        })
    }
}

pub struct TestVector {
    pub props: TestVectorProps,
    pub entries: Vec<RoundEntry>,
}

impl TestVector {
    pub fn parse<'a>(
        lines: &mut Peekable<impl Iterator<Item = &'a str>>,
        reseed: bool,
    ) -> Vec<TestVector> {
        let mut vectors = Vec::new();
        while let Some(props) = TestVectorProps::parse(lines) {
            let entries = RoundEntry::parse(lines, &props, reseed);
            let vector = TestVector { props, entries };
            vectors.push(vector);
        }
        vectors
    }
}
