//! Platform abstractions for [`Engine`](crate::Engine).

use tpm2::crypto::Crypto;

/// In-memory NV Index storage.
///
/// Placeholder with no required operations yet; methods will be added
/// alongside the NV commands.
pub trait IndexData: Default {}

/// In-memory storage for objects made persistent by `TPM2_EvictControl`.
///
/// Placeholder with no required operations yet; methods will be added
/// alongside `TPM2_EvictControl`.
pub trait EvictData: Default {}

/// Platform-specific dependencies for [`Engine`](crate::Engine).
///
/// A platform selects its cryptography backend and non-volatile storage layout
/// via associated types so the engine is statically dispatched with no heap
/// allocation or trait objects.
pub trait Platform {
    /// Cryptography backend implementing [`Crypto`].
    type Crypto: Crypto;

    /// NV Index data, stored in [`Nv::index`](crate::state::Nv::index).
    type IndexData: IndexData;

    /// Persistent object data, stored in [`Nv::evict`](crate::state::Nv::evict).
    type EvictData: EvictData;
}
