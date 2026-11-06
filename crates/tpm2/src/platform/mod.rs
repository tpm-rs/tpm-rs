//! TPM 2.0 Platform Abstraction Layer
//!
//! The `tpm-rs` library is designed to run across diverse operational environments—ranging
//! from resource-constrained bare-metal embedded firmware (utilizing custom hardware accelerators)
//! to user-space host applications running on a desktop operating system (e.g., Linux, Windows).
//!
//! The `platform` module encapsulates all external dependencies and hardware interfaces (such as
//! cryptography, clocks, non-volatile storage, and physical presence controls) into a clean set
//! of traits. This isolation keeps the core library's state machine, wire-format serialization,
//! and command processing logic completely independent of the execution environment.
//!
//! ### Submodules
//!
//! - [`storage`]: Low-level non-volatile memory (NV) access.
//! - [`timer`]: Monotonic clock/timer interface.
//! - [`pcr`]: Structure containing platform configuration register banks.
//! - [`firmware`]: Firmware secrets (Firmware Secret, Firmware SVN Secrets) of the
//!   firmware-limited and SVN-limited hierarchies, and the reference platform's dummy ones.
//! - [`secure_channel`]: Secure channel (SPDM) information of the TPM's secure transport layer.
//!
//! The `Platform` trait that combines these components for the TPM engine is defined by
//! `tpm2-engine`; every platform crate implements it with its own platform type.

pub mod firmware;
pub mod pcr;
pub mod secure_channel;
pub mod storage;
pub mod timer;

pub use firmware::FirmwareSecretUnavailable;
pub use pcr::PcrState;
pub use secure_channel::{SecureChannel, SimulatedSecureChannel, SpdmSession};
pub use storage::{NvStorage, StorageError};
pub use timer::TpmTimer;
