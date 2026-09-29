pub mod manager;
pub mod ram_storage_mock;
pub mod transcoder;
pub mod translator;
pub mod types;

use types::{Handle, ItemMetadata};

/// Generic interface defining logical TPM items (Persistent Objects, NV Indices)
pub trait Tpm2Storage {
    fn define_space(
        &mut self,
        handle: Handle,
        size: u16,
        attributes: u32,
    ) -> Result<(), StorageError>;
    fn undefine_space(&mut self, handle: Handle) -> Result<(), StorageError>;
    fn resize_item(&mut self, handle: Handle, new_size: u16) -> Result<(), StorageError>;
    fn write_item(&mut self, handle: Handle, offset: u16, data: &[u8]) -> Result<(), StorageError>;
    fn read_item(&self, handle: Handle, offset: u16, buf: &mut [u8]) -> Result<(), StorageError>;
    fn get_metadata(&self, handle: Handle) -> Result<ItemMetadata, StorageError>;
}

pub use tpm2::platform::{NvStorage, StorageError};
