use crate::helpers::slice_to_hex_string;
use getrandom::getrandom;
use std::process::exit;
use tpm2_rs_server::platform::crypto::EntropySource;
use tracing::{error, instrument, trace};

pub struct SystemEntropySource;

impl SystemEntropySource {
    /// This method is guaranteed to fill `dest`
    /// with high quality entropy, or it crashes if it fails to do so
    #[instrument(skip_all)]
    fn fill_entropy(dest: &mut [u8]) {
        if let Err(e) = getrandom(dest) {
            error!("fill_entropy failed with error: {e}");
            exit(-1);
        } else {
            trace!("entropy = {}", slice_to_hex_string(dest));
        }
    }
}

impl EntropySource for SystemEntropySource {
    fn fill_entropy(&mut self, dest: &mut [u8]) {
        Self::fill_entropy(dest);
    }

    fn instantiate() -> Self {
        Self
    }
}
