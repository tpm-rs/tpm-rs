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

/// Defines specific error conditions that can occur during storage and NV media operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StorageError {
    /// Caused when the requested operation addresses memory outside the physical boundaries
    /// of the NV indices or medium capacity.
    OutOfBounds,

    /// Represents a failure originating from the physical storage hardware, such as
    /// a damaged component, failed I/O bus transaction, flash wear-out, or interrupted power.
    HardwareError,

    /// Indicates that the caller lacks physical or logical permissions to access the medium.
    AccessDenied,
}

/// Defines operations for Non-Volatile (NV) State Storage.
pub trait NvStorage {
    /// Return the total capacity of the storage in bytes.
    fn capacity(&self) -> usize;

    /// Read `length` bytes at `offset` into `buffer`.
    ///
    /// # Errors
    /// * `StorageError::OutOfBounds` - Returned if `offset + buffer.len()` exceeds the max `capacity()` of the storage medium.
    /// * `StorageError::HardwareError` - Returned if the underlying medium fails to fulfill the read operation due to physical, I/O, or bus faults.
    /// * `StorageError::AccessDenied` - Returned if the hardware is in a locked or protected state preventing read access.
    fn read_nv(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, StorageError>;

    /// Write `buffer` to storage starting at `offset`.
    ///
    /// # Errors
    /// * `StorageError::OutOfBounds` - Returned if `offset + buffer.len()` exceeds the bounds of the `capacity()`.
    /// * `StorageError::HardwareError` - Returned if the physical write transaction fails, or if the medium has degraded (e.g., flash wear out).
    /// * `StorageError::AccessDenied` - Returned if the physical NV block is write-locked (such as hardware write-protect enabled).
    fn write_nv(&mut self, offset: usize, buffer: &[u8]) -> Result<usize, StorageError>;

    /// Trigger an atomic commit or flush of changes in the storage backend.
    ///
    /// # Errors
    /// * `StorageError::HardwareError` - Returned if a power-fail or system-level fault interrupts the atomic commit process.
    fn flush(&mut self) -> Result<(), StorageError>;
}
