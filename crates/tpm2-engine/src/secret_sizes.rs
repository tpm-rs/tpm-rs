//! Sizes of TPM-generated secrets that depend on the implementation profile.
//!
//! They follow the TCG reference implementation's profile: 64-byte Primary Seeds and hierarchy
//! proofs (`PRIMARY_SEED_SIZE`, `PROOF_SIZE`). Since these values are drawn from the DRBG, their
//! sizes also determine every later random value.

/// Size of the Primary Seeds (EPS, SPS, PPS) and of the null hierarchy's seed
/// (`PRIMARY_SEED_SIZE`).
pub(crate) const PRIMARY_SEED_SIZE: usize = 64;

/// Size of the hierarchy proofs (phProof, shProof, ehProof, nullProof) (`PROOF_SIZE`).
pub(crate) const PROOF_SIZE: usize = 64;
