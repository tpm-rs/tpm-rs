//! Unit tests for the base crate (uses std)
extern crate std;
use std::vec::Vec;

use crate::platform::TpmContextDeps;

use super::TpmContext;
use drbg::FakeDrbg;
use entropy::FakeEntropy;

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

    // tag (8001), size (0000000c), command code (0000017b), requested bytes (000c)
    let request = b"\
        \x80\x01\
        \x00\x00\x00\x0c\
        \x00\x00\x01\x7b\
        \x00\x0c";
    // tag (8001), size (00000016), rc (00000000), random bytes (01..=0c)
    let expected_response = b"\
        \x80\x01\
        \x00\x00\x00\x16\
        \x00\x00\x00\x00\
        \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";

    let mut response = request.to_vec();
    response.resize(256, 0xFF);
    let size = tpm.execute_command_in_place(&mut response, request.len());
    assert_eq!(&response[..size], expected_response);
}

#[test]
fn get_random_separate() {
    let mut tpm: TpmContext<TestDeps> = TpmContext::new().unwrap();

    // tag (8001), size (0000000c), command code (0000017b), requested bytes (000c)
    let request = b"\
        \x80\x01\
        \x00\x00\x00\x0c\
        \x00\x00\x01\x7b\
        \x00\x0c";
    // tag (8001), size (00000016), rc (00000000), random bytes (01..=0c)
    let expected_response = b"\
        \x80\x01\
        \x00\x00\x00\x16\
        \x00\x00\x00\x00\
        \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";

    let mut response = Vec::new();
    response.resize(256, 0xFF);
    let size = tpm.execute_command_separate(request, &mut response);
    assert_eq!(&response[..size], expected_response);
}
