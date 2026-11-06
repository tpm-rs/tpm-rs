//! NV storage of the engine.
//!
//! The TPM keeps everything it stores in NV in an [`IndexState`]: the platform-specific
//! structure holding the NV Indices, the persistent objects and the engine's internal records
//! ([`nv`]), each addressed by its handle, plus a small reserved header
//! ([`manager::RESERVED_SIZE`] octets) for the persistent counters. It lives in the TPM state
//! ([`crate::Nv::index`]); its type is chosen by the platform ([`crate::Platform::IndexState`]).
//!
//! Every byte-addressable NV medium ([`NvStorage`]) is an [`IndexState`]: the storage manager
//! ([`manager`]) keeps the items in a fixed table of contents followed by their packed
//! payloads.

pub mod manager;
pub mod nv;
pub mod nv_capacity;
pub mod ram_storage_mock;
pub mod types;

use manager::MAX_ITEMS;
use types::{Handle, ItemMetadata};

/// Structure holding the NV data of the TPM: the `Handle -> [u8]` mapping of the NV Indices,
/// persistent objects and internal records (the "items"), and the reserved header.
///
/// The items are created with [`IndexState::define_space`] (with a fixed size, which
/// [`IndexState::resize_item`] changes), read and written at an offset with
/// [`IndexState::read_item`] and [`IndexState::write_item`], and removed with
/// [`IndexState::undefine_space`]. Every write is durable when it returns (a platform that
/// keeps the data in RAM syncs it to external storage in [`crate::Platform::store_nv`]).
///
/// Every [`NvStorage`] medium implements it with the layout of the storage manager
/// ([`manager`]); a platform can implement it directly for another representation.
pub trait IndexState {
    /// The total size of the NV memory in octets (the reserved header, the table of contents
    /// and the item payloads of the storage manager's layout).
    fn nv_capacity(&self) -> usize;

    /// Reads `buf.len()` octets of the reserved header at `offset`.
    fn read_reserved(&self, offset: usize, buf: &mut [u8]) -> Result<(), StorageError>;

    /// Writes `data` to the reserved header at `offset`.
    fn write_reserved(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageError>;

    /// The metadata of every defined item, in storage order, followed by unused (`in_use ==
    /// 0`) entries.
    fn items(&self) -> Result<[ItemMetadata; MAX_ITEMS], StorageError>;

    /// Defines the item `handle` with `size` octets and the storage `attributes`. Fails with
    /// [`StorageError::AccessDenied`] if it exists and with [`StorageError::OutOfBounds`] if
    /// there is no room.
    fn define_space(
        &mut self,
        handle: Handle,
        size: u16,
        attributes: u32,
    ) -> Result<(), StorageError>;

    /// Removes the item `handle` ([`StorageError::AccessDenied`] if it does not exist).
    fn undefine_space(&mut self, handle: Handle) -> Result<(), StorageError>;

    /// Changes the size of the item `handle` to `new_size` octets, keeping its first
    /// `min(old, new)` octets.
    fn resize_item(&mut self, handle: Handle, new_size: u16) -> Result<(), StorageError>;

    /// Writes `data` to the item `handle` at `offset` (`write_idx`).
    fn write_item(&mut self, handle: Handle, offset: u16, data: &[u8]) -> Result<(), StorageError>;

    /// Reads `buf.len()` octets of the item `handle` at `offset` (`read_idx`).
    fn read_item(&self, handle: Handle, offset: u16, buf: &mut [u8]) -> Result<(), StorageError>;

    /// The metadata of the item `handle` ([`StorageError::AccessDenied`] if it does not exist).
    fn get_metadata(&self, handle: Handle) -> Result<ItemMetadata, StorageError>;
}

pub use tpm2::platform::{NvStorage, StorageError};
