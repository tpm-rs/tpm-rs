//! TPM 2.0 Structures and Specification Types
//!
//! This module groups all data structures, unions, interfaces, lists, buffers,
//! and attribute definitions defined in "Part 2: Structures" of the TPM 2.0 Specification.
//!
//! Internally, the types are partitioned into submodules according to their
//! naming prefixes in the specification:
//!
//! - `tpma`: Attribute types (`TPMA_` prefix). Typically represented using
//!   the `bitflags` macro (e.g., [`TpmaLocality`], [`TpmaNv`]).
//! - `tpmi`: Interface types (`TPMI_` prefix). Constrained subsets of larger types
//!   (e.g., algorithm or handle subsets) that implement `TryFrom` validation
//!   (e.g., [`TpmiAlgHash`], [`TpmiAlgKdf`]).
//! - `tpmt`: Template/Tagged Union types (`TPMT_` prefix). Modeled directly as Rust
//!   enums carrying data variants (e.g., [`TpmtPublic`], [`TpmtSensitive`], [`TpmtHa`]).
//! - `tpms`: Structure types (`TPMS_` prefix). Plain-old-data structs representing
//!   fixed parameter bundles (e.g., [`TpmsClockInfo`], [`TpmsPcrSelect`], [`TpmsPcrSelection`]).
//! - `tpml`: List types (`TPML_` prefix). Counted arrays containing lists of handles,
//!   digests, or algorithms (e.g., [`TpmlPcrSelection`], [`TpmlDigest`]).
//! - `tpm2b`: Buffer types (`TPM2B_` prefix). Size-prefixed byte array wraps
//!   commonly used for marshalling variables and keys (e.g., [`Tpm2bDigest`], [`Tpm2bData`]).
//! - `tpmu`: Union types (`TPMU_` prefix). Raw unions that are not encapsulated
//!   inside tagged enum templates (e.g., [`TpmuAttest`], [`TpmuSensitiveComposite`]).
//!
//! We also have `headers`, which exports [`CommandHeader`] and [`ResponseHeader`].
//!
//! All types are re-exported flatly from this module, making them accessible
//! at`tpm2::*`.

mod headers;
mod tpm2b;
mod tpma;
mod tpmi;
mod tpml;
mod tpms;
mod tpmt;
mod tpmu;

pub use headers::*;
pub use tpm2b::*;
pub use tpma::*;
pub use tpmi::*;
pub use tpml::*;
pub use tpms::*;
pub use tpmt::*;
pub use tpmu::*;
