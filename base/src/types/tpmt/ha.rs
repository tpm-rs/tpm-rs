// =============================================================================
// USES
// =============================================================================

use crate::{
    constants::{
        TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE, TPM2_SHA384_DIGEST_SIZE,
        TPM2_SHA512_DIGEST_SIZE, TPM2_SHA_DIGEST_SIZE, TPM2_SM3_256_DIGEST_SIZE,
    },
    types::TPM2AlgID,
};
use tpm2_rs_marshal::Marshal;
use tpm2_rs_unionify::UnionSize;

// =============================================================================
// TYPES
// =============================================================================

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal, UnionSize)]
pub enum TpmtHa {
    Sha1([u8; TPM2_SHA_DIGEST_SIZE as usize]) = TPM2AlgID::SHA1.0,
    Sha256([u8; TPM2_SHA256_DIGEST_SIZE as usize]) = TPM2AlgID::SHA256.0,
    Sha384([u8; TPM2_SHA384_DIGEST_SIZE as usize]) = TPM2AlgID::SHA384.0,
    Sha512([u8; TPM2_SHA512_DIGEST_SIZE as usize]) = TPM2AlgID::SHA512.0,
    Sm3_256([u8; TPM2_SM3_256_DIGEST_SIZE as usize]) = TPM2AlgID::SM3256.0,
}

// =============================================================================
// TRAITS
// =============================================================================

// TODO: This seems bad. Why is this here?
impl Default for TpmtHa {
    fn default() -> Self {
        TpmtHa::Sha1([0; TPM2_SHA1_DIGEST_SIZE as usize])
    }
}
