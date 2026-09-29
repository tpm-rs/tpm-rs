use super::{NvStorage, StorageError};

/// An in-memory storage implementation for testing or simple environments.
/// Using a generic const N to define the RAM block size without alloc.
pub struct RamStorageMock<const N: usize> {
    data: [u8; N],
    pub dirty: bool,
}

impl<const N: usize> RamStorageMock<N> {
    /// Create a newly initialized RAM storage block with zeros.
    pub const fn new() -> Self {
        Self {
            data: [0; N],
            dirty: false,
        }
    }

    /// Exposes the inner array reference.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Exposes the mutable inner array reference.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> NvStorage for RamStorageMock<N> {
    fn capacity(&self) -> usize {
        N
    }

    fn read_nv(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, StorageError> {
        if offset + buffer.len() > N {
            return Err(StorageError::OutOfBounds);
        }
        buffer.copy_from_slice(&self.data[offset..offset + buffer.len()]);
        Ok(buffer.len())
    }

    fn write_nv(&mut self, offset: usize, buffer: &[u8]) -> Result<usize, StorageError> {
        if offset + buffer.len() > N {
            return Err(StorageError::OutOfBounds);
        }
        self.data[offset..offset + buffer.len()].copy_from_slice(buffer);
        self.dirty = true;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        Ok(()) // NOOP for RAM
    }
}

impl<const N: usize> Default for RamStorageMock<N> {
    fn default() -> Self {
        Self::new()
    }
}
