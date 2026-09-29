//! # TPM 2.0 Command Execution Engine
//!
//! <div class="warning">
//! This code is unstable and there are no guarantees of stability at this time.
//! </div>
//!
//! This crate implements the core execution engine and individual command handlers for a TPM 2.0 device.
//! The implementation is split into a central coordinating engine ([TpmEngine](engine.rs)) and modular command handlers
//! (found under the [handler](handler/mod.rs) module) to maintain safety, clear security boundaries, and modularity.
//!
//! ## Architectural Decomposition
//!
//! The responsibility for handling TPM command requests and formatting response payloads is cleanly separated
//! between the [TpmEngine](engine.rs) and the [handler](handler/mod.rs) modules:
//!
//! ### 1. [TpmEngine](engine.rs) (Outer Security and Session Envelope)
//!
//! The engine owns the physical resources, global TPM state ([GlobalState](engine.rs)), and manages the session lifecycle.
//! It acts as a shield around command execution, handling:
//! - **Request Parsing (Outer Frame)**: Unmarshals the command tag, size, and command code.
//!   - **Session Verification & Integrity**: Verifies authentication sessions and HMACs for incoming requests.
//!   - **Parameter Decryption**: Decrypts request parameters using session keys before the handler executes.
//! - **Post-Execution Security Envelope**:
//!   - **Parameter Encryption**: Encrypts response parameters if required by the active session.
//!   - **HMAC / Integrity Computation**: Computes HMACs over response parameters and generates final session nonces.
//!   - **Response Assembly**: Packs the handles, response parameters, and sessions into the final output buffer.
//!
//! By handling these tasks centrally, the engine ensures that security-sensitive properties (like session encryption and
//! cryptographic integrity verification) are consistently applied and cannot be bypassed or misconfigured by individual handlers.
//!
//! ### 2. [handler](handler/mod.rs) (Command-Specific Payload Logic)
//!
//! Handlers are specialized modules that implement the actual business logic of specific TPM commands (e.g., PCR read/write,
//! key creation, cryptographic operations).
//! - **Encapsulated Scope**: Handlers operate on "shadow requests" that have session headers and wrappers already stripped.
//!   They do not have direct, unconstrained access to raw session management or crypto parameter wrapping.
//! - **Inner Payload Operations**: Handlers parse command-specific fields (like key sizes, public templates, data to hash),
//!   execute the core algorithm, and write command-specific output fields to the response.
//! - **State Mutators**: Handlers mutate the TPM state (like PCR values, volatile key slots, and NV memory) through
//!   API methods provided by [TpmEngine](engine.rs). These
//!   methods limit what command implementations can do and encapsulate error checking (e.g., out of range indices)
//!
//! Some handlers perform command-specific cryptographic operations directly on user-provided data payloads:
//! - **Symmetric/Asymmetric Encryption**: [encrypt_decrypt.rs](handler/encrypt_decrypt.rs) (symmetric AES/SM4), [crypt_ops.rs](handler/crypt_ops.rs) (asymmetric RSA encryption and decryption).
//! - **Integrity / MAC Creation**: [crypt_ops.rs](handler/crypt_ops.rs) (computes HMAC).
//! - **Signature Verification**: [crypt_ops.rs](handler/crypt_ops.rs) (validates signatures).
//! - **Key Migration & Importing**: [duplicate.rs](handler/duplicate.rs) (encrypts objects for duplicate migration), [import.rs](handler/import.rs) (decrypts imported objects).

#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)] // rustc >= 1.90.0 (1159e78c4 2025-09-14)

#[cfg(test)]
extern crate alloc;

mod error;
pub mod handler;
pub mod hash_state;
pub mod owned;
pub mod storage;
#[cfg(test)]
pub mod test_support;
pub mod timer;
mod util;

mod engine;
mod req_resp;
pub use engine::{
    ActiveSequence, DRBG_MAGIC, DrbgState, GlobalState, MAX_ACTIVE_SEQUENCES, MAX_LOADED_OBJECTS,
    MAX_LOADED_SESSIONS, MAX_SEQUENCE_BUFFER, SequenceType, TpmEngine, command_handles_count,
    command_returns_handle, get_command_attribute, handle_requires_auth,
};
pub use error::InternalError;
pub use hash_state::StreamingHashState;
pub use storage::translator::{Ibmswtpm2StateDto, TpmStateTranslator};

pub use tpm2::platform::TpmPlatform;

pub mod pcr {
    pub use tpm2::platform::PcrState;
}
