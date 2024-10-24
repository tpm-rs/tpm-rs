use crate::platform::TpmContextDeps;

use super::tpmctx::*;
use crypto::FakeCrypto;
use hex_literal::hex;

pub mod crypto;

/// Contains all of the test dependencies to create a [`TpmContext`] for unit testing
struct TestDeps {
    crypto: FakeCrypto,
}

impl TpmContextDeps for TestDeps {
    type Crypto = FakeCrypto;
    type Request = [u8];
    type Response = [u8];
}

impl TestDeps {
    pub fn new() -> Self {
        Self {
            crypto: FakeCrypto::new(),
        }
    }

    pub fn tpm(&mut self) -> TpmContext<Self> {
        TpmContext::new(&mut self.crypto)
    }
}

#[test]
fn get_random_in_place() {
    let mut test_deps = TestDeps::new();
    let mut tpm = test_deps.tpm();

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
    let mut test_deps = TestDeps::new();
    let mut tpm = test_deps.tpm();

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
