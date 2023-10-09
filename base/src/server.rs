use crate::{
    crypto::{Crypto, CryptoEngine, DigestType},
    errors::{TpmError, TpmResult},
    storage::{FileId, PartitionId, Storage},
};


/// Specifies all of the dependent types needed to create a `Server` instance.
pub trait ServerDeps {
    type Crypto: Crypto;
    type Storage: Storage;
}

/// Internal state of Tpm Server
enum ServerState {
    Uninitialized,
    Initialized,
}


/// TPM `Server` that processes incoming requests according to TPM 2.0 spec.
pub struct Server<'a, Deps: ServerDeps> {
    crypto_engine: CryptoEngine<Deps::Crypto>,
    storage: &'a mut Deps::Storage,
    state: ServerState,
}

impl<'a, Deps: ServerDeps> Server<'a, Deps> {
    /// Creates a new `Server` with the specified dependencies.
    pub fn new(storage: &'a mut Deps::Storage) -> Self {
        Self {
            crypto_engine: CryptoEngine::new(),
            state: ServerState::Uninitialized,
            storage,
        }
    }

    /// Processes a TPM request and fills out the response.
    pub fn process_tpm_request(&mut self, request: &[u8], response: &mut [u8]) {
        // "Parse" the request here and determine what should be done.
        if request.len() > 0 {
            if let Err(e) = self.perform_sha256_hash_twice(request, response) {
                if let Some(output) = response.get_mut(0..4) {
                    output.copy_from_slice(&u32::from(e).to_be_bytes());
                }
            } else {
                let _ = self
                    .storage
                    .write_all(PartitionId::PCR, FileId(123), &response);
            }
        }
    }

    fn perform_sha256_hash_twice(&self, input: &[u8], output: &mut [u8]) -> TpmResult<usize> {
        let mut hash_op = self.crypto_engine.start_hash(DigestType::SHA2_256)?;
        hash_op.update(input)?;
        let size = hash_op.finish(output)?;
        let hash1 = output.get(..size).ok_or(TpmError::TPM2_RC_SIZE)?;

        let mut hash_op = self.crypto_engine.start_hash(DigestType::SHA2_256)?;
        hash_op.update(hash1)?;
        hash_op.finish(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testing::FakeCrypto;
    use crate::storage::testing::FakeStorage;

    struct TestDeps {
        storage: FakeStorage,
    }

    impl ServerDeps for TestDeps {
        type Crypto = FakeCrypto;
        type Storage = FakeStorage;
    }

    impl TestDeps {
        pub fn new() -> Self {
            Self {
                storage: FakeStorage::new(),
            }
        }

        pub fn new_engine(&mut self) -> Server<Self> {
            Server::new(&mut self.storage)
        }
    }

    #[test]
    fn verify_hash_twice() {
        let mut deps = TestDeps::new();
        let mut server = deps.new_engine();

        let request = [12; 50];
        let mut response = [0; 32];
        server.process_tpm_request(&request, &mut response);
        let expected = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12, 12, 12, 12, 12, 12, 12,
            12, 12, 12, 12, 12, 12,
        ];

        assert_eq!(response, expected, "Hash twice reponse is correct");

        // Ensure that the filesystem was written to with the correct values
        assert_eq!(deps.storage.file_count(), 1);
        assert_eq!(
            &deps
                .storage
                .file_contents(PartitionId::PCR, FileId(123))
                .expect("File present")[..],
            &expected[..],
            "File contents match"
        );
    }
}
