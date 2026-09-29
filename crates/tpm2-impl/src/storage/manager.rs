use super::types::{Handle, ItemMetadata};
use super::{NvStorage, StorageError, Tpm2Storage};

/// The maximum number of persistent objects or NV indices that can be stored simultaneously.
/// This is a custom storage limitation.
pub const MAX_ITEMS: usize = 64;
/// Serialized byte size of the Table of Contents (TOC) index tracking NV storage items.
/// Calculated as MAX_ITEMS * ItemMetadata::SIZE. Custom storage design property.
pub const TOC_SIZE: usize = MAX_ITEMS * ItemMetadata::SIZE;
/// Byte space reserved at the beginning of NV storage for metadata/TOC structures.
/// Custom storage design property.
pub const RESERVED_SIZE: usize = 128;

/// A simple block storage manager that operates without dynamic allocation.
/// It uses a fixed-size Table of Contents (TOC) at the start of the storage space
/// and maintains the data payloads in the same order as they appear in the TOC,
/// tightly packed (contiguous).
pub struct StorageManager<'a> {
    storage: &'a mut dyn NvStorage,
}

impl<'a> StorageManager<'a> {
    pub fn new(storage: &'a mut dyn NvStorage) -> Self {
        Self { storage }
    }

    /// Read the entire TOC into a fixed-size array
    pub fn read_toc(&self) -> Result<[ItemMetadata; MAX_ITEMS], StorageError> {
        let mut toc = [ItemMetadata::empty(); MAX_ITEMS];
        let mut buf = [0u8; ItemMetadata::SIZE];
        for (i, item) in toc.iter_mut().enumerate() {
            self.storage
                .read_nv(RESERVED_SIZE + i * ItemMetadata::SIZE, &mut buf)?;
            *item = ItemMetadata::from_bytes(&buf);
        }
        Ok(toc)
    }

    /// Helper to find the index and data offset of a handle in the contiguous TOC/payload layout.
    fn find_item(
        &self,
        handle: Handle,
        toc: &[ItemMetadata; MAX_ITEMS],
    ) -> Option<(usize, usize, ItemMetadata)> {
        let mut offset = RESERVED_SIZE + TOC_SIZE;
        for (i, item) in toc.iter().enumerate() {
            if item.in_use == 0 {
                break; // Because we keep TOC contiguous
            }
            if item.handle == handle {
                return Some((i, offset, *item));
            }
            offset += item.data_size as usize;
        }
        None
    }

    /// Calculate total bytes currently used (TOC + all data items)
    fn total_used_bytes(&self, toc: &[ItemMetadata; MAX_ITEMS]) -> usize {
        let mut total = RESERVED_SIZE + TOC_SIZE;
        for item in toc.iter() {
            if item.in_use == 0 {
                break;
            }
            total += item.data_size as usize;
        }
        total
    }

    /// Commit the TOC back to storage
    fn write_toc(&mut self, toc: &[ItemMetadata; MAX_ITEMS]) -> Result<(), StorageError> {
        for (i, item) in toc.iter().enumerate() {
            self.storage
                .write_nv(RESERVED_SIZE + i * ItemMetadata::SIZE, &item.to_bytes())?;
        }
        // Force flush
        self.storage.flush()
    }
}

impl<'a> Tpm2Storage for StorageManager<'a> {
    fn define_space(
        &mut self,
        handle: Handle,
        size: u16,
        attributes: u32,
    ) -> Result<(), StorageError> {
        let mut toc = self.read_toc()?;

        if self.find_item(handle, &toc).is_some() {
            return Err(StorageError::AccessDenied); // Item already exists
        }

        let mut free_idx = None;
        for (i, item) in toc.iter().enumerate() {
            if item.in_use == 0 {
                free_idx = Some(i);
                break;
            }
        }

        let free_idx = free_idx.ok_or(StorageError::OutOfBounds)?; // No room in TOC

        let current_usage = self.total_used_bytes(&toc);
        if current_usage + (size as usize) > self.storage.capacity() {
            return Err(StorageError::OutOfBounds); // No room in physical storage
        }

        toc[free_idx] = ItemMetadata {
            handle,
            data_size: size,
            attributes,
            in_use: 1,
        };

        self.write_toc(&toc)
    }

    fn undefine_space(&mut self, handle: Handle) -> Result<(), StorageError> {
        let mut toc = self.read_toc()?;
        let (idx, offset, item) = self
            .find_item(handle, &toc)
            .ok_or(StorageError::AccessDenied)?;

        let size = item.data_size as usize;
        let total_used = self.total_used_bytes(&toc);
        let end_of_data = total_used;

        // Shift data down (compaction) to overwrite the removed item
        // Because we are no_std and might not have a big enough buffer for the whole shift at once,
        // we shift in chunks.
        let mut shift_src = offset + size;
        let mut shift_dst = offset;
        let mut chunk = [0u8; 64];

        while shift_src < end_of_data {
            let bytes_to_copy = core::cmp::min(64, end_of_data - shift_src);
            self.storage
                .read_nv(shift_src, &mut chunk[..bytes_to_copy])?;
            self.storage.write_nv(shift_dst, &chunk[..bytes_to_copy])?;
            shift_src += bytes_to_copy;
            shift_dst += bytes_to_copy;
        }

        // Shift TOC down
        for i in idx..(MAX_ITEMS - 1) {
            toc[i] = toc[i + 1];
        }
        toc[MAX_ITEMS - 1] = ItemMetadata::empty();

        self.write_toc(&toc)
    }

    fn resize_item(&mut self, handle: Handle, new_size: u16) -> Result<(), StorageError> {
        let mut toc = self.read_toc()?;
        let (idx, offset, item) = self
            .find_item(handle, &toc)
            .ok_or(StorageError::AccessDenied)?;

        let old_size = item.data_size as usize;
        let new_size_usize = new_size as usize;
        if old_size == new_size_usize {
            return Ok(());
        }

        let total_used = self.total_used_bytes(&toc);
        let end_of_data = total_used;

        if new_size_usize > old_size {
            let diff = new_size_usize - old_size;
            if end_of_data + diff > self.storage.capacity() {
                return Err(StorageError::OutOfBounds);
            }
            let mut shift_src = end_of_data;
            let mut chunk = [0u8; 64];
            while shift_src > offset + old_size {
                let bytes_to_copy = core::cmp::min(64, shift_src - (offset + old_size));
                shift_src -= bytes_to_copy;
                self.storage
                    .read_nv(shift_src, &mut chunk[..bytes_to_copy])?;
                self.storage
                    .write_nv(shift_src + diff, &chunk[..bytes_to_copy])?;
            }
        } else {
            let _diff = old_size - new_size_usize;
            let mut shift_src = offset + old_size;
            let mut shift_dst = offset + new_size_usize;
            let mut chunk = [0u8; 64];
            while shift_src < end_of_data {
                let bytes_to_copy = core::cmp::min(64, end_of_data - shift_src);
                self.storage
                    .read_nv(shift_src, &mut chunk[..bytes_to_copy])?;
                self.storage.write_nv(shift_dst, &chunk[..bytes_to_copy])?;
                shift_src += bytes_to_copy;
                shift_dst += bytes_to_copy;
            }
        }

        toc[idx].data_size = new_size;
        self.write_toc(&toc)
    }

    fn write_item(
        &mut self,
        handle: Handle,
        item_offset: u16,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let toc = self.read_toc()?;
        let (_, base_offset, item) = self
            .find_item(handle, &toc)
            .ok_or(StorageError::AccessDenied)?;

        if item_offset as usize + data.len() > item.data_size as usize {
            return Err(StorageError::OutOfBounds);
        }

        self.storage
            .write_nv(base_offset + item_offset as usize, data)?;
        self.storage.flush()
    }

    fn read_item(
        &self,
        handle: Handle,
        item_offset: u16,
        buf: &mut [u8],
    ) -> Result<(), StorageError> {
        let toc = self.read_toc()?;
        let (_, base_offset, item) = self
            .find_item(handle, &toc)
            .ok_or(StorageError::AccessDenied)?;

        if item_offset as usize + buf.len() > item.data_size as usize {
            return Err(StorageError::OutOfBounds);
        }

        self.storage
            .read_nv(base_offset + item_offset as usize, buf)?;
        Ok(())
    }

    fn get_metadata(&self, handle: Handle) -> Result<ItemMetadata, StorageError> {
        let toc = self.read_toc()?;
        let (_, _, item) = self
            .find_item(handle, &toc)
            .ok_or(StorageError::AccessDenied)?;
        Ok(item)
    }
}
