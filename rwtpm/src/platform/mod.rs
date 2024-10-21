mod entropy;

use entropy::SystemEntropySource;
use tpm2_rs_drbg::{sha2::Sha512, HashDrbg};
use tpm2_rs_server::platform::TpmContextDeps;

pub struct SwDeps;

impl TpmContextDeps for SwDeps {
    type Drbg = HashDrbg<Sha512>;
    type EntropySource = SystemEntropySource;
    type Request = [u8];
    type Response = [u8];
}
