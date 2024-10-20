use crate::{
    platform::{
        crypto::{Drbg, EntropySource},
        TpmContextDeps,
    },
    ServerError,
};

pub struct Crypto<Deps: TpmContextDeps> {
    pub drbg: Deps::Drbg,
    pub entropy: Deps::EntropySource,
}

impl<Deps: TpmContextDeps> Crypto<Deps> {
    pub fn new() -> Result<Self, ServerError<Deps>> {
        let mut entropy_source: <Deps as TpmContextDeps>::EntropySource =
            Deps::EntropySource::instantiate();
        let mut entropy_input = <Deps::Drbg as Drbg>::Entropy::default();
        let mut nonce = <Deps::Drbg as Drbg>::Nonce::default();
        entropy_source.fill_entropy(entropy_input.as_mut());
        entropy_source.fill_entropy(nonce.as_mut());
        let drbg =
            Deps::Drbg::instantiate(&entropy_input, &nonce, &[]).map_err(ServerError::Drbg)?;
        Ok(Self {
            drbg,
            entropy: entropy_source,
        })
    }
}
