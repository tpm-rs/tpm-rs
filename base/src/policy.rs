use core::marker::PhantomData;

use crate::{
    errors::{TpmError, TpmResult},
    hash::Hasher,
    TPM2AlgID, TpmiAlgHash, TpmtHa, TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE,
    TPM2_SHA384_DIGEST_SIZE, TPM2_SHA512_DIGEST_SIZE, TPM2_SM3_256_DIGEST_SIZE,
};

/// PolicyCalculator represents a TPM 2.0 policy that needs to be calculated
/// synthetically (i.e., without a TPM).
pub struct PolicyCalculator<H: Hasher> {
    pub alg: TpmiAlgHash,
    pub hash_state: TpmtHa,
    phantom_data: PhantomData<H>,
}

impl<H: Hasher> PolicyCalculator<H> {
    /// Creates a fresh policy using the given hash algorithm.
    pub fn new(alg: TpmiAlgHash) -> TpmResult<Self> {
        let hash_alg_id = alg.0.get();
        let hash_state = TpmtHa::new(TPM2AlgID(hash_alg_id))?;

        Ok(PolicyCalculator {
            alg,
            hash_state,
            phantom_data: PhantomData,
        })
    }

    /// Resets the internal state of the policy hash to all 0x0.
    pub fn reset(&mut self) {
        self.hash_state = match self.hash_state {
            TpmtHa::Sha1(_) => TpmtHa::Sha1([0u8; TPM2_SHA1_DIGEST_SIZE]),
            TpmtHa::Sha256(_) => TpmtHa::Sha256([0u8; TPM2_SHA256_DIGEST_SIZE]),
            TpmtHa::Sha384(_) => TpmtHa::Sha384([0u8; TPM2_SHA384_DIGEST_SIZE]),
            TpmtHa::Sha512(_) => TpmtHa::Sha512([0u8; TPM2_SHA512_DIGEST_SIZE]),
            TpmtHa::Sm3_256(_) => TpmtHa::Sm3_256([0u8; TPM2_SM3_256_DIGEST_SIZE]),
        };
    }

    /// Updates the internal state of the policy hash by appending the
    /// current state with the given contents, and updating the new state
    /// to the hash of that.
    pub fn update(&mut self, bytes: &[u8]) -> TpmResult<()> {
        let mut hasher = H::new()?;
        self.hash_state = match self.hash_state {
            TpmtHa::Sha1(state) => {
                hasher.update(&[&state, bytes].concat())?;
                let digest = hasher.finish()?;
                TpmtHa::Sha1(
                    digest.bytes()[..TPM2_SHA1_DIGEST_SIZE]
                        .try_into()
                        .map_err(|_| TpmError::TPM2_RC_SIZE)?,
                )
            }
            TpmtHa::Sha256(state) => {
                hasher.update(&[&state, bytes].concat())?;
                let digest = hasher.finish()?;
                TpmtHa::Sha256(
                    digest.bytes()[..TPM2_SHA256_DIGEST_SIZE]
                        .try_into()
                        .map_err(|_| TpmError::TPM2_RC_SIZE)?,
                )
            }
            TpmtHa::Sha384(state) => {
                hasher.update(&[&state, bytes].concat())?;
                let digest = hasher.finish()?;
                TpmtHa::Sha384(
                    digest.bytes()[..TPM2_SHA384_DIGEST_SIZE]
                        .try_into()
                        .map_err(|_| TpmError::TPM2_RC_SIZE)?,
                )
            }
            TpmtHa::Sha512(state) => {
                hasher.update(&[&state, bytes].concat())?;
                let digest = hasher.finish()?;
                TpmtHa::Sha512(
                    digest.bytes()[..TPM2_SHA512_DIGEST_SIZE]
                        .try_into()
                        .map_err(|_| TpmError::TPM2_RC_SIZE)?,
                )
            }
            TpmtHa::Sm3_256(state) => {
                hasher.update(&[&state, bytes].concat())?;
                let digest = hasher.finish()?;
                TpmtHa::Sm3_256(
                    digest.bytes()[..TPM2_SM3_256_DIGEST_SIZE]
                        .try_into()
                        .map_err(|_| TpmError::TPM2_RC_SIZE)?,
                )
            }
        };
        Ok(())
    }

    /// Returns the current state of the policy hash.
    pub fn get_hash(&mut self) -> TpmtHa {
        self.hash_state
    }
}
