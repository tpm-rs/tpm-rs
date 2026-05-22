//! Unit tests for the base crate (uses std)
extern crate std;
use std::vec::Vec;

use crate::platform::TpmContextDeps;

use super::tpmctx::*;
use drbg::FakeDrbg;
use entropy::FakeEntropy;
use hex_literal::hex;

pub mod drbg;
pub mod entropy;

/// Contains all of the test dependencies to create a [`TpmContext`] for unit testing
struct TestDeps;

impl TpmContextDeps for TestDeps {
    type Drbg = FakeDrbg;
    type EntropySource = FakeEntropy;
    type Request = [u8];
    type Response = [u8];
}

#[test]
fn get_random_in_place() {
    let mut tpm: TpmContext<TestDeps> = TpmContext::new().unwrap();

    let request = hex!(
        "8001" // tag
        "0000000c" // size
        "0000017B" // command code
        "000c" // requested random bytes
    );
    let expected_response = &hex!(
        "8001" // session
        "00000016" // size
        "00000000" // successful response
        "0102030405060708090a0b0c" // random bytes
    );

    let mut response = request.to_vec();
    response.resize(256, 0xFF);
    let size = tpm.execute_command_in_place(&mut response, request.len());
    assert_eq!(&response[..size], expected_response);
}

#[test]
fn get_random_separate() {
    let mut tpm: TpmContext<TestDeps> = TpmContext::new().unwrap();

    let request = hex!(
        "8001" // tag
        "0000000c" // size
        "0000017B" // command code
        "000c" // requested random bytes
    );
    let expected_response = hex!(
        "8001" // session
        "00000016" // size
        "00000000" // successful response
        "0102030405060708090a0b0c" // random bytes
    );

    let mut response = Vec::new();
    response.resize(256, 0xFF);
    let size = tpm.execute_command_separate(&request, &mut response);
    assert_eq!(&response[..size], expected_response);
}
