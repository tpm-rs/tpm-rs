#![forbid(unsafe_code)]

//! The orderly-Index RAM and its NV copy (`s_indexOrderlyRam` and `NV_INDEX_RAM_DATA` of the C
//! references, `NVDynamic.c`/`NvDynamic.c`).
//!
//! The references keep the data and the attributes of the NV Indices with `TPMA_NV_ORDERLY` in a
//! RAM area of `RAM_INDEX_SPACE` octets (one `NV_RAM_HEADER { size, handle, attributes }` and
//! the data per Index, in the order of their definition) and write that area to its NV copy
//! only at certain points (`NvUpdateIndexOrderlyData()`): when the command that changed it set
//! `g_updateNV` to `UT_ORDERLY` (an orderly Index was defined or deleted, an orderly counter was
//! written for the first time or rolled over its low `ORDERLY_BITS`), at `TPM2_Shutdown` (of
//! either type), and at manufacture. Every `TPM2_Startup` reloads the RAM area from the NV copy
//! (`NvEntityStartup()`), so after a power loss without `TPM2_Shutdown` the orderly Indices
//! revert to the state of the last save (Part 1, "NV Index Orderly Attribute": "the TPM may
//! not update the NV memory for the data ... until the TPM receives TPM2_Shutdown()").
//!
//! tpm-rs keeps the current data and attributes of every orderly Index in its NV Index item, the
//! counterpart of the RAM area: nothing can read them between a power loss and the next
//! `TPM2_Startup`, which reloads them, so their surviving the power loss cannot be observed. The
//! NV copy is the internal record [`ORDERLY_RAM_HANDLE`]: the image of the RAM area in the
//! references' layout ([`ram_image`], native little-endian `NV_RAM_HEADER` fields, as in their
//! NV memory). [`save`] is `NvUpdateIndexOrderlyData()`, [`restore`] the reload of
//! `NvEntityStartup()`.

use crate::storage::nv::ORDERLY_RAM_HANDLE;
use crate::storage::nv_capacity::{SIZEOF_NV_RAM_HEADER, parse_index_record};
use crate::storage::{IndexState, StorageError};
use tpm2::TpmaNv;

/// `RAM_INDEX_SPACE`: the size of the orderly-Index RAM area and of its NV copy.
pub const RAM_INDEX_SPACE: usize = crate::storage::nv_capacity::RAM_INDEX_SPACE as usize;
/// `sizeof(NV_RAM_HEADER)`.
const RAM_HEADER: usize = SIZEOF_NV_RAM_HEADER as usize;

/// An image of the orderly-Index RAM area (`s_indexOrderlyRam`).
pub type RamImage = [u8; RAM_INDEX_SPACE];

/// The layout of an NV Index item (`TPM2B_AUTH || TPM2B_NV_PUBLIC || data`): the offset of the
/// `TPMA_NV` attributes and of the data, the attributes and the data size, parsed from the
/// start of the item.
struct IndexLayout {
    attributes_at: usize,
    data_at: usize,
    attributes: u32,
    data_size: u16,
}

/// The longest item prefix [`index_layout`] reads: `TPM2B_AUTH` (2 + 64) and `TPM2B_NV_PUBLIC`
/// (2 + 4 + 2 + 4 + 2 + 64 + 2).
const MAX_HEADER: usize = 66 + 80;

/// Parses the layout of the NV Index item `handle` of `storage`.
fn index_layout(
    storage: &(impl IndexState + ?Sized),
    handle: u32,
) -> Result<IndexLayout, StorageError> {
    let meta = storage.get_metadata(handle)?;
    let mut header = [0u8; MAX_HEADER];
    let len = usize::from(meta.data_size).min(MAX_HEADER);
    storage.read_item(handle, 0, &mut header[..len])?;
    let header = &header[..len];
    let (attributes, data_size) = parse_index_record(header).ok_or(StorageError::HardwareError)?;
    let auth_size = usize::from(u16::from_be_bytes([header[0], header[1]]));
    let public_at = 2 + auth_size;
    let public_size = header
        .get(public_at..public_at + 2)
        .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        .ok_or(StorageError::HardwareError)?;
    Ok(IndexLayout {
        // TPMS_NV_PUBLIC: nvIndex (4), nameAlg (2), attributes (4), ...
        attributes_at: public_at + 2 + 6,
        data_at: public_at + 2 + public_size,
        attributes,
        data_size,
    })
}

/// The entries of the RAM image `image` (`NvRamNext()`): the handle, the attributes and the data
/// of every orderly Index, up to the first entry whose `size` is 0 or that does not fit.
pub fn entries(image: &RamImage) -> impl Iterator<Item = (u32, u32, &[u8])> {
    let le32 =
        |at: usize| u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]]);
    let mut at = 0usize;
    core::iter::from_fn(move || {
        if at + RAM_HEADER > RAM_INDEX_SPACE {
            return None;
        }
        let size = le32(at) as usize;
        if size < RAM_HEADER || at + size > RAM_INDEX_SPACE {
            return None;
        }
        let entry = (
            le32(at + 4),
            le32(at + 8),
            &image[at + RAM_HEADER..at + size],
        );
        at += size;
        Some(entry)
    })
}

/// The image of the orderly-Index RAM area of the NV Indices of `storage`: their current
/// attributes and data, in item (definition) order, followed by zeros (`NvAddRAM()`,
/// `NvDeleteRAM()`).
pub fn ram_image(storage: &(impl IndexState + ?Sized)) -> Result<RamImage, StorageError> {
    let mut image = [0u8; RAM_INDEX_SPACE];
    let mut at = 0usize;
    for item in storage.items()?.iter().take_while(|item| item.in_use != 0) {
        if item.handle >> 24 != tpm2::TpmHt::NVIndex as u32 {
            continue;
        }
        let layout = index_layout(storage, item.handle)?;
        if layout.attributes & TpmaNv::ORDERLY.0 == 0 {
            continue;
        }
        let size = RAM_HEADER + usize::from(layout.data_size);
        let entry = image
            .get_mut(at..at + size)
            .ok_or(StorageError::OutOfBounds)?;
        entry[..4].copy_from_slice(&(size as u32).to_le_bytes());
        entry[4..8].copy_from_slice(&item.handle.to_le_bytes());
        entry[8..12].copy_from_slice(&layout.attributes.to_le_bytes());
        storage.read_item(item.handle, layout.data_at as u16, &mut entry[RAM_HEADER..])?;
        at += size;
    }
    Ok(image)
}

/// The NV copy of the orderly-Index RAM area (`NV_INDEX_RAM_DATA`), or `None` if it was never
/// saved.
pub fn saved_image(storage: &(impl IndexState + ?Sized)) -> Option<RamImage> {
    let meta = storage.get_metadata(ORDERLY_RAM_HANDLE).ok()?;
    if usize::from(meta.data_size) != RAM_INDEX_SPACE {
        return None;
    }
    let mut image = [0u8; RAM_INDEX_SPACE];
    storage.read_item(ORDERLY_RAM_HANDLE, 0, &mut image).ok()?;
    Some(image)
}

/// Replaces the NV copy of the orderly-Index RAM area with `image`.
pub fn write_saved_image(
    storage: &mut (impl IndexState + ?Sized),
    image: &RamImage,
) -> Result<(), StorageError> {
    match storage.get_metadata(ORDERLY_RAM_HANDLE) {
        Ok(meta) if usize::from(meta.data_size) == RAM_INDEX_SPACE => {}
        Ok(_) => {
            storage.undefine_space(ORDERLY_RAM_HANDLE)?;
            storage.define_space(ORDERLY_RAM_HANDLE, RAM_INDEX_SPACE as u16, 0)?;
        }
        Err(_) => storage.define_space(ORDERLY_RAM_HANDLE, RAM_INDEX_SPACE as u16, 0)?,
    }
    storage.write_item(ORDERLY_RAM_HANDLE, 0, image)
}

/// `NvUpdateIndexOrderlyData()`: writes the orderly-Index RAM area to its NV copy.
pub fn save(storage: &mut (impl IndexState + ?Sized)) -> Result<(), StorageError> {
    let image = ram_image(storage)?;
    write_saved_image(storage, &image)
}

/// The reload of the orderly-Index RAM area from its NV copy at `TPM2_Startup`
/// (`NvRead(s_indexOrderlyRam, NV_INDEX_RAM_DATA, ...)` in `NvEntityStartup()`): the attributes
/// and the data of every orderly Index revert to those of the last [`save`]. Without an NV copy
/// (NV written before tpm-rs kept one), nothing changes.
pub fn restore(storage: &mut (impl IndexState + ?Sized)) -> Result<(), StorageError> {
    let Some(image) = saved_image(storage) else {
        return Ok(());
    };
    for (handle, attributes, data) in entries(&image) {
        // Every orderly Index has an entry: the NV copy is saved whenever one is defined or
        // deleted. An entry without its Index (not written by tpm-rs) is skipped.
        let Ok(layout) = index_layout(storage, handle) else {
            continue;
        };
        if layout.attributes & TpmaNv::ORDERLY.0 == 0 || usize::from(layout.data_size) != data.len()
        {
            continue;
        }
        storage.write_item(
            handle,
            layout.attributes_at as u16,
            &attributes.to_be_bytes(),
        )?;
        storage.write_item(handle, layout.data_at as u16, data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ram_storage_mock;

    type RamStorageMock = ram_storage_mock::RamStorageMock<16384>;

    /// Defines the NV Index `handle` with an empty authValue, `attributes` and `data`.
    fn define(storage: &mut RamStorageMock, handle: u32, attributes: u32, data: &[u8]) {
        let mut item = [0u8; 2 + 2 + 14 + 32];
        // TPM2B_AUTH (empty), TPM2B_NV_PUBLIC { nvIndex, nameAlg, attributes, authPolicy (empty),
        // dataSize }.
        let mut at = 2;
        item[at..at + 2].copy_from_slice(&14u16.to_be_bytes());
        at += 2;
        item[at..at + 4].copy_from_slice(&handle.to_be_bytes());
        item[at + 4..at + 6].copy_from_slice(&0x000Bu16.to_be_bytes());
        item[at + 6..at + 10].copy_from_slice(&attributes.to_be_bytes());
        item[at + 12..at + 14].copy_from_slice(&(data.len() as u16).to_be_bytes());
        at += 14;
        item[at..at + data.len()].copy_from_slice(data);
        let len = at + data.len();
        storage.define_space(handle, len as u16, 0).unwrap();
        storage.write_item(handle, 0, &item[..len]).unwrap();
    }

    fn data_of(storage: &RamStorageMock, handle: u32) -> ([u8; 8], u32) {
        let layout = index_layout(storage, handle).unwrap();
        let mut data = [0u8; 8];
        storage
            .read_item(
                handle,
                layout.data_at as u16,
                &mut data[..usize::from(layout.data_size)],
            )
            .unwrap();
        (data, layout.attributes)
    }

    #[test]
    fn save_and_restore_revert_orderly_indices_only() {
        let mut storage = RamStorageMock::new();
        let orderly = TpmaNv::ORDERLY.0 | TpmaNv::AUTHWRITE.0 | TpmaNv::AUTHREAD.0;
        define(&mut storage, 0x0100_0001, orderly, &[1; 8]);
        define(&mut storage, 0x0100_0002, TpmaNv::AUTHWRITE.0, &[2; 4]);
        define(&mut storage, 0x0100_0003, orderly, &[3; 2]);
        save(&mut storage).unwrap();

        let image = saved_image(&storage).unwrap();
        let listed: [(u32, u32, usize); 2] = {
            let mut it = entries(&image).map(|(h, a, d)| (h, a, d.len()));
            [it.next().unwrap(), it.next().unwrap()]
        };
        assert_eq!(
            listed,
            [(0x0100_0001, orderly, 8), (0x0100_0003, orderly, 2)]
        );
        assert_eq!(entries(&image).count(), 2);
        assert_eq!(u32::from_le_bytes(image[..4].try_into().unwrap()), 12 + 8);
        assert!(image[12 + 8 + 12 + 2..].iter().all(|&b| b == 0));

        // Change the data and the attributes of every Index ("in RAM"), then restore.
        let written = orderly | TpmaNv::WRITTEN.0;
        for handle in [0x0100_0001, 0x0100_0002, 0x0100_0003] {
            let layout = index_layout(&storage, handle).unwrap();
            let attributes = layout.attributes | TpmaNv::WRITTEN.0;
            storage
                .write_item(
                    handle,
                    layout.attributes_at as u16,
                    &attributes.to_be_bytes(),
                )
                .unwrap();
            storage
                .write_item(handle, layout.data_at as u16, &[9; 2])
                .unwrap();
        }
        assert_eq!(data_of(&storage, 0x0100_0001).1, written);
        restore(&mut storage).unwrap();
        assert_eq!(data_of(&storage, 0x0100_0001), ([1; 8], orderly));
        assert_eq!(
            data_of(&storage, 0x0100_0003),
            ([3, 3, 0, 0, 0, 0, 0, 0], orderly)
        );
        // An ordinary Index keeps its changes.
        assert_eq!(
            data_of(&storage, 0x0100_0002),
            (
                [9, 9, 2, 2, 0, 0, 0, 0],
                TpmaNv::AUTHWRITE.0 | TpmaNv::WRITTEN.0
            )
        );
    }

    #[test]
    fn restore_without_a_saved_copy_changes_nothing() {
        let mut storage = RamStorageMock::new();
        define(&mut storage, 0x0100_0001, TpmaNv::ORDERLY.0, &[1; 8]);
        restore(&mut storage).unwrap();
        assert_eq!(data_of(&storage, 0x0100_0001), ([1; 8], TpmaNv::ORDERLY.0));
        assert!(saved_image(&storage).is_none());
    }
}
