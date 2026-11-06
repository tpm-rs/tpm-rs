use super::types::{Handle, ItemMetadata};
use super::{IndexState, NvStorage, StorageError};

/// The maximum number of items (NV Indices, persistent objects and the engine's internal
/// records) that can be stored simultaneously: a custom storage limitation, sized so that the
/// table never fills up before the NV space accounting (`TPM_RC_NV_SPACE`,
/// [`super::nv_capacity`]) does. The smallest entry that accounting admits is an orderly Index,
/// whose data is in RAM: `sizeof(UINT32) + sizeof(NV_INDEX)` octets of the reference's dynamic
/// area (`NV_USER_DYNAMIC..NV_USER_DYNAMIC_END`). So the table holds as many of them as fit
/// (rounded up), plus the four internal records ([`super::nv`]).
pub const MAX_ITEMS: usize = {
    use super::nv_capacity::{
        NV_USER_DYNAMIC, NV_USER_DYNAMIC_END, SIZEOF_NV_INDEX, SIZEOF_UINT32,
    };
    let smallest = (SIZEOF_UINT32 + SIZEOF_NV_INDEX) as usize;
    let dynamic = (NV_USER_DYNAMIC_END - NV_USER_DYNAMIC) as usize;
    dynamic.div_ceil(smallest) + INTERNAL_RECORDS
};
/// The number of internal records of the engine ([`super::nv::is_internal_record`]).
const INTERNAL_RECORDS: usize = 4;
/// Serialized byte size of the Table of Contents (TOC) index tracking NV storage items.
/// Calculated as MAX_ITEMS * ItemMetadata::SIZE. Custom storage design property.
pub const TOC_SIZE: usize = MAX_ITEMS * ItemMetadata::SIZE;
/// Byte space reserved at the beginning of NV storage for metadata/TOC structures.
/// Custom storage design property.
pub const RESERVED_SIZE: usize = 128;

/// The storage manager: the layout in which every byte-addressable NV medium ([`NvStorage`])
/// holds an [`IndexState`], without dynamic allocation.
///
/// The medium starts with the reserved header ([`RESERVED_SIZE`] octets), followed by a
/// fixed-size Table of Contents (TOC, [`TOC_SIZE`] octets: [`MAX_ITEMS`] [`ItemMetadata`]
/// entries, the used ones first) and the item payloads, in the order of their TOC entries,
/// tightly packed (contiguous).
impl<S: NvStorage + ?Sized> IndexState for S {
    fn nv_capacity(&self) -> usize {
        self.capacity()
    }

    fn read_reserved(&self, offset: usize, buf: &mut [u8]) -> Result<(), StorageError> {
        if offset + buf.len() > RESERVED_SIZE {
            return Err(StorageError::OutOfBounds);
        }
        self.read_nv(offset, buf).map(|_| ())
    }

    fn write_reserved(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageError> {
        if offset + data.len() > RESERVED_SIZE {
            return Err(StorageError::OutOfBounds);
        }
        self.write_nv(offset, data).map(|_| ())
    }

    fn items(&self) -> Result<[ItemMetadata; MAX_ITEMS], StorageError> {
        read_toc(self)
    }

    fn define_space(
        &mut self,
        handle: Handle,
        size: u16,
        attributes: u32,
    ) -> Result<(), StorageError> {
        let mut toc = read_toc(self)?;

        if find_item(handle, &toc).is_some() {
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

        let current_usage = total_used_bytes(&toc);
        if current_usage + (size as usize) > self.capacity() {
            return Err(StorageError::OutOfBounds); // No room in physical storage
        }

        toc[free_idx] = ItemMetadata {
            handle,
            data_size: size,
            attributes,
            in_use: 1,
        };

        write_toc(self, &toc)
    }

    fn undefine_space(&mut self, handle: Handle) -> Result<(), StorageError> {
        let mut toc = read_toc(self)?;
        let (idx, offset, item) = find_item(handle, &toc).ok_or(StorageError::AccessDenied)?;

        let size = item.data_size as usize;
        let total_used = total_used_bytes(&toc);
        let end_of_data = total_used;

        // Shift data down (compaction) to overwrite the removed item
        // Because we are no_std and might not have a big enough buffer for the whole shift at once,
        // we shift in chunks.
        let mut shift_src = offset + size;
        let mut shift_dst = offset;
        let mut chunk = [0u8; 64];

        while shift_src < end_of_data {
            let bytes_to_copy = core::cmp::min(64, end_of_data - shift_src);
            self.read_nv(shift_src, &mut chunk[..bytes_to_copy])?;
            self.write_nv(shift_dst, &chunk[..bytes_to_copy])?;
            shift_src += bytes_to_copy;
            shift_dst += bytes_to_copy;
        }

        // Shift TOC down
        for i in idx..(MAX_ITEMS - 1) {
            toc[i] = toc[i + 1];
        }
        toc[MAX_ITEMS - 1] = ItemMetadata::empty();

        write_toc(self, &toc)
    }

    fn resize_item(&mut self, handle: Handle, new_size: u16) -> Result<(), StorageError> {
        let mut toc = read_toc(self)?;
        let (idx, offset, item) = find_item(handle, &toc).ok_or(StorageError::AccessDenied)?;

        let old_size = item.data_size as usize;
        let new_size_usize = new_size as usize;
        if old_size == new_size_usize {
            return Ok(());
        }

        let total_used = total_used_bytes(&toc);
        let end_of_data = total_used;

        if new_size_usize > old_size {
            let diff = new_size_usize - old_size;
            if end_of_data + diff > self.capacity() {
                return Err(StorageError::OutOfBounds);
            }
            let mut shift_src = end_of_data;
            let mut chunk = [0u8; 64];
            while shift_src > offset + old_size {
                let bytes_to_copy = core::cmp::min(64, shift_src - (offset + old_size));
                shift_src -= bytes_to_copy;
                self.read_nv(shift_src, &mut chunk[..bytes_to_copy])?;
                self.write_nv(shift_src + diff, &chunk[..bytes_to_copy])?;
            }
        } else {
            let mut shift_src = offset + old_size;
            let mut shift_dst = offset + new_size_usize;
            let mut chunk = [0u8; 64];
            while shift_src < end_of_data {
                let bytes_to_copy = core::cmp::min(64, end_of_data - shift_src);
                self.read_nv(shift_src, &mut chunk[..bytes_to_copy])?;
                self.write_nv(shift_dst, &chunk[..bytes_to_copy])?;
                shift_src += bytes_to_copy;
                shift_dst += bytes_to_copy;
            }
        }

        toc[idx].data_size = new_size;
        write_toc(self, &toc)
    }

    fn write_item(
        &mut self,
        handle: Handle,
        item_offset: u16,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let toc = read_toc(self)?;
        let (_, base_offset, item) = find_item(handle, &toc).ok_or(StorageError::AccessDenied)?;

        if item_offset as usize + data.len() > item.data_size as usize {
            return Err(StorageError::OutOfBounds);
        }

        self.write_nv(base_offset + item_offset as usize, data)?;
        self.flush()
    }

    fn read_item(
        &self,
        handle: Handle,
        item_offset: u16,
        buf: &mut [u8],
    ) -> Result<(), StorageError> {
        let toc = read_toc(self)?;
        let (_, base_offset, item) = find_item(handle, &toc).ok_or(StorageError::AccessDenied)?;

        if item_offset as usize + buf.len() > item.data_size as usize {
            return Err(StorageError::OutOfBounds);
        }

        self.read_nv(base_offset + item_offset as usize, buf)?;
        Ok(())
    }

    fn get_metadata(&self, handle: Handle) -> Result<ItemMetadata, StorageError> {
        let toc = read_toc(self)?;
        let (_, _, item) = find_item(handle, &toc).ok_or(StorageError::AccessDenied)?;
        Ok(item)
    }

    fn erase(&mut self) -> Result<(), StorageError> {
        let zero_block = [0u8; 128];
        let cap = self.capacity();
        let mut pos = 0;
        while pos < cap {
            let len = (cap - pos).min(zero_block.len());
            self.write_nv(pos, &zero_block[..len])?;
            pos += len;
        }
        self.flush()
    }
}

/// Reads the entire TOC into a fixed-size array.
fn read_toc<S: NvStorage + ?Sized>(storage: &S) -> Result<[ItemMetadata; MAX_ITEMS], StorageError> {
    let mut toc = [ItemMetadata::empty(); MAX_ITEMS];
    let mut buf = [0u8; ItemMetadata::SIZE];
    for (i, item) in toc.iter_mut().enumerate() {
        storage.read_nv(RESERVED_SIZE + i * ItemMetadata::SIZE, &mut buf)?;
        *item = ItemMetadata::from_bytes(&buf);
    }
    Ok(toc)
}

/// Finds the TOC index, the data offset and the metadata of `handle` in the contiguous
/// TOC/payload layout.
fn find_item(
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

/// The total number of octets in use (the reserved header, the TOC and all item payloads).
fn total_used_bytes(toc: &[ItemMetadata; MAX_ITEMS]) -> usize {
    let mut total = RESERVED_SIZE + TOC_SIZE;
    for item in toc.iter() {
        if item.in_use == 0 {
            break;
        }
        total += item.data_size as usize;
    }
    total
}

/// Commits the TOC back to storage (and flushes it).
fn write_toc<S: NvStorage + ?Sized>(
    storage: &mut S,
    toc: &[ItemMetadata; MAX_ITEMS],
) -> Result<(), StorageError> {
    for (i, item) in toc.iter().enumerate() {
        storage.write_nv(RESERVED_SIZE + i * ItemMetadata::SIZE, &item.to_bytes())?;
    }
    // Force flush
    storage.flush()
}
