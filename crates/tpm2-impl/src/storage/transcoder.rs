//! Bidirectional NVRAM transcoder bridging the `ibmswtpm2` monolithic 16 KB
//! memory image (`s_NV`) and `tpm-rs`'s Table of Contents (`StorageManager`) layout.
//!
//! # Architectural Context
//! In `ibmswtpm2`, non-volatile memory
//! is represented as a single contiguous 16,384-byte buffer (`s_NV`) divided into:
//! - Fixed-offset C structs:
//!   - `NV_PERSISTENT_DATA` (`gp`, offset `0..792`)
//!   - `NV_STATE_RESET_DATA` (`gr`, offset `792..1104`)
//!   - `NV_STATE_CLEAR_DATA` (`gc`, offset `1104..2876`)
//!   - `NV_ORDERLY_DATA` (`go`, offset `2876..2972`)
//!   - `NV_INDEX_RAM_DATA` (`s_indexOrderlyRam`, offset `2972..3484`)
//! - Dynamic linked list (`NV_USER_DYNAMIC`, offset `3484..16384`) storing
//!   persistent objects (`0x81xxxxxx`) and dynamic NV indices (`0x01xxxxxx`).
//!
//! By contrast, `tpm-rs` uses a 128-byte reserved header (`0..128`), a 64-entry
//! Table of Contents (`128..832`), and contiguous payloads including a virtual
//! handle `0x00FFFFFF` (`HIERARCHY_AUTH_HANDLE`) for hierarchy state.
//!
//! This module provides lossless bidirectional translation between both formats.

use super::manager::{RESERVED_SIZE, StorageManager};
use super::{NvStorage, StorageError, Tpm2Storage};

/// Total byte size of the monolithic `ibmswtpm2` NVRAM image (`s_NV`).
pub const NV_MEMORY_SIZE: usize = 16384;

/// Offset of `PERSISTENT_DATA gp` in `s_NV` (size: 792 bytes).
pub const NV_PERSISTENT_DATA_OFFSET: usize = 0;
/// Offset of `STATE_RESET_DATA gr` in `s_NV` (size: 312 bytes).
pub const NV_STATE_RESET_DATA_OFFSET: usize = 792;
/// Offset of `STATE_CLEAR_DATA gc` in `s_NV` (size: 1772 bytes).
pub const NV_STATE_CLEAR_DATA_OFFSET: usize = 1104;
/// Offset of `ORDERLY_DATA go` in `s_NV` (size: 96 bytes).
pub const NV_ORDERLY_DATA_OFFSET: usize = 2876;
/// Offset of orderly NV index RAM backing store (`s_indexOrderlyRam`, size: 512 bytes).
pub const NV_INDEX_RAM_DATA_OFFSET: usize = 2972;
/// Offset of the dynamic linked-list region for NV indices and evict objects.
pub const NV_USER_DYNAMIC_OFFSET: usize = 3484;

/// Virtual handle used by `tpm-rs` to store persistent hierarchy authorizations and seeds.
pub const HIERARCHY_AUTH_HANDLE: u32 = 0x00FFFFFF;

/// Size of a fixed-width `TPM2B` buffer slot (`u16` length + 64-byte payload) in `s_NV`.
const FIXED_TPM2B_SIZE: usize = 66;

/// Header of each linked-list node in `s_NV` dynamic space (`size`, `handle`, `attributes`).
const DYNAMIC_NODE_HEADER_SIZE: usize = 12;

/// Helper to write a variable-length `TPM2B` slice (2-byte big-endian size + bytes) into a fixed 66-byte slot.
fn write_fixed_tpm2b(dst: &mut [u8], src_slice: &mut &[u8]) {
    if src_slice.len() < 2 {
        return;
    }
    let len = u16::from_be_bytes([src_slice[0], src_slice[1]]) as usize;
    let clamped_len = core::cmp::min(len, 64);
    if src_slice.len() < 2 + len {
        return;
    }
    dst[0..2].copy_from_slice(&(clamped_len as u16).to_be_bytes());
    dst[2..2 + clamped_len].copy_from_slice(&src_slice[2..2 + clamped_len]);
    *src_slice = &src_slice[2 + len..];
}

/// Helper to append a fixed 66-byte `TPM2B` slot from `s_NV` into a marshalled buffer slice.
fn marshal_from_fixed_tpm2b(src: &[u8], dst: &mut [u8], offset: &mut usize) {
    let len = u16::from_be_bytes([src[0], src[1]]) as usize;
    let clamped_len = core::cmp::min(len, 64);
    if *offset + 2 + clamped_len <= dst.len() {
        dst[*offset..*offset + 2].copy_from_slice(&(clamped_len as u16).to_be_bytes());
        *offset += 2;
        dst[*offset..*offset + clamped_len].copy_from_slice(&src[2..2 + clamped_len]);
        *offset += clamped_len;
    }
}

/// Forward Migration Transcoder: translates an `ibmswtpm2` monolithic 16 KB `s_NV` buffer
/// into `tpm-rs` `StorageManager` format (reserved header + TOC + `0x00FFFFFF` + dynamic items).
pub fn transcode_s_nv_to_storage(
    s_nv: &[u8; NV_MEMORY_SIZE],
    storage: &mut dyn NvStorage,
) -> Result<(), StorageError> {
    // 1. Clear reserved header and TOC region in destination storage.
    let zero_block = [0u8; 128];
    storage.write_nv(0, &zero_block)?;
    for i in 0..6 {
        storage.write_nv(RESERVED_SIZE + i * 128, &zero_block)?;
    }

    // 2. Transcode fixed scalar fields from `gp` and `go` into `tpm-rs` reserved header (0..128).
    // gp: total_reset_count (offset 732..740), reset_count (740..744), failed_tries (744..748),
    //     orderly_state (748..750), time_epoch (750..758)
    storage.write_nv(0, &s_nv[740..744])?; // reset_count (u32)
    storage.write_nv(4, &s_nv[748..750])?; // orderly_state (u16)
    storage.write_nv(8, &s_nv[732..736])?; // total_reset_count low 32 bits (u32)
    storage.write_nv(24, &s_nv[750..758])?; // time_epoch (u64)
    storage.write_nv(32, &s_nv[744..748])?; // failed_tries (u32)

    // go: drbg_state (offset 2876..2952), self_heal_timer (2952..2960), lockout_timer (2960..2968)
    storage.write_nv(
        36,
        &s_nv[NV_ORDERLY_DATA_OFFSET..NV_ORDERLY_DATA_OFFSET + 76],
    )?;
    storage.write_nv(
        112,
        &s_nv[NV_ORDERLY_DATA_OFFSET + 76..NV_ORDERLY_DATA_OFFSET + 92],
    )?;

    // 3. Construct the `0x00FFFFFF` (HIERARCHY_AUTH_HANDLE) payload from `gp`, `gr`, and `gc`.
    let mut auth_buf = [0u8; 1152];
    let mut offset = 0usize;

    // Auths (owner, endorsement, platform, lockout)
    marshal_from_fixed_tpm2b(
        &s_nv[204..204 + FIXED_TPM2B_SIZE],
        &mut auth_buf,
        &mut offset,
    );
    marshal_from_fixed_tpm2b(
        &s_nv[270..270 + FIXED_TPM2B_SIZE],
        &mut auth_buf,
        &mut offset,
    );
    marshal_from_fixed_tpm2b(
        &s_nv[NV_STATE_CLEAR_DATA_OFFSET + 72..NV_STATE_CLEAR_DATA_OFFSET + 72 + FIXED_TPM2B_SIZE],
        &mut auth_buf,
        &mut offset,
    );
    marshal_from_fixed_tpm2b(
        &s_nv[336..336 + FIXED_TPM2B_SIZE],
        &mut auth_buf,
        &mut offset,
    );

    // Policies (owner, endorsement, platform, lockout)
    marshal_from_fixed_tpm2b(&s_nv[6..6 + FIXED_TPM2B_SIZE], &mut auth_buf, &mut offset);
    marshal_from_fixed_tpm2b(&s_nv[72..72 + FIXED_TPM2B_SIZE], &mut auth_buf, &mut offset);
    marshal_from_fixed_tpm2b(
        &s_nv[NV_STATE_CLEAR_DATA_OFFSET + 6..NV_STATE_CLEAR_DATA_OFFSET + 6 + FIXED_TPM2B_SIZE],
        &mut auth_buf,
        &mut offset,
    );
    marshal_from_fixed_tpm2b(
        &s_nv[138..138 + FIXED_TPM2B_SIZE],
        &mut auth_buf,
        &mut offset,
    );

    // Algorithms (owner, endorsement, platform, lockout)
    auth_buf[offset..offset + 2].copy_from_slice(&s_nv[0..2]);
    offset += 2;
    auth_buf[offset..offset + 2].copy_from_slice(&s_nv[2..4]);
    offset += 2;
    auth_buf[offset..offset + 2]
        .copy_from_slice(&s_nv[NV_STATE_CLEAR_DATA_OFFSET + 4..NV_STATE_CLEAR_DATA_OFFSET + 6]);
    offset += 2;
    auth_buf[offset..offset + 2].copy_from_slice(&s_nv[4..6]);
    offset += 2;

    // 405-byte tail: sh_enable, eh_enable, ph_enable_nv, magic 0xAA, seeds, proofs, clear_count
    auth_buf[offset] = s_nv[NV_STATE_CLEAR_DATA_OFFSET];
    offset += 1;
    auth_buf[offset] = s_nv[NV_STATE_CLEAR_DATA_OFFSET + 1];
    offset += 1;
    auth_buf[offset] = s_nv[NV_STATE_CLEAR_DATA_OFFSET + 2];
    offset += 1;
    auth_buf[offset] = 0xAA;
    offset += 1;

    // sp_seed (gp offset 402..468)
    auth_buf[offset..offset + FIXED_TPM2B_SIZE].copy_from_slice(&s_nv[402..402 + FIXED_TPM2B_SIZE]);
    offset += FIXED_TPM2B_SIZE;
    // sh_proof (gp offset 600..666)
    auth_buf[offset..offset + FIXED_TPM2B_SIZE].copy_from_slice(&s_nv[600..600 + FIXED_TPM2B_SIZE]);
    offset += FIXED_TPM2B_SIZE;
    // eh_proof (gp offset 666..732)
    auth_buf[offset..offset + FIXED_TPM2B_SIZE].copy_from_slice(&s_nv[666..666 + FIXED_TPM2B_SIZE]);
    offset += FIXED_TPM2B_SIZE;
    // clear_count (gc offset 1242..1246)
    auth_buf[offset..offset + 4]
        .copy_from_slice(&s_nv[NV_STATE_CLEAR_DATA_OFFSET + 138..NV_STATE_CLEAR_DATA_OFFSET + 142]);
    offset += 4;
    // pp_seed (gp offset 468..534)
    auth_buf[offset..offset + FIXED_TPM2B_SIZE].copy_from_slice(&s_nv[468..468 + FIXED_TPM2B_SIZE]);
    offset += FIXED_TPM2B_SIZE;
    // ph_proof (gr offset 792..858)
    auth_buf[offset..offset + FIXED_TPM2B_SIZE].copy_from_slice(
        &s_nv[NV_STATE_RESET_DATA_OFFSET..NV_STATE_RESET_DATA_OFFSET + FIXED_TPM2B_SIZE],
    );
    offset += FIXED_TPM2B_SIZE;
    // ep_seed (gp offset 534..600)
    auth_buf[offset..offset + FIXED_TPM2B_SIZE].copy_from_slice(&s_nv[534..534 + FIXED_TPM2B_SIZE]);
    offset += FIXED_TPM2B_SIZE;

    // PCR policy alg & digest (gc offset 1246..1314) and PCR auth value (gc offset 1314..1380)
    let pcr_alg_bytes = &s_nv[NV_STATE_CLEAR_DATA_OFFSET + 142..NV_STATE_CLEAR_DATA_OFFSET + 144];
    if pcr_alg_bytes == [0, 0] {
        auth_buf[offset..offset + 2].copy_from_slice(&0x0010u16.to_be_bytes());
    } else {
        auth_buf[offset..offset + 2].copy_from_slice(pcr_alg_bytes);
    }
    offset += 2;
    marshal_from_fixed_tpm2b(
        &s_nv
            [NV_STATE_CLEAR_DATA_OFFSET + 144..NV_STATE_CLEAR_DATA_OFFSET + 144 + FIXED_TPM2B_SIZE],
        &mut auth_buf,
        &mut offset,
    );
    marshal_from_fixed_tpm2b(
        &s_nv
            [NV_STATE_CLEAR_DATA_OFFSET + 210..NV_STATE_CLEAR_DATA_OFFSET + 210 + FIXED_TPM2B_SIZE],
        &mut auth_buf,
        &mut offset,
    );

    let mut storage_mgr = StorageManager::new(storage);
    let _ = storage_mgr.undefine_space(HIERARCHY_AUTH_HANDLE);
    storage_mgr.define_space(HIERARCHY_AUTH_HANDLE, 1152, 0)?;
    storage_mgr.write_item(HIERARCHY_AUTH_HANDLE, 0, &auth_buf[..offset])?;

    // 4. Walk the dynamic linked list in `s_NV` and populate TOC entries in `StorageManager`.
    let mut cursor = NV_USER_DYNAMIC_OFFSET;
    while cursor + DYNAMIC_NODE_HEADER_SIZE <= NV_MEMORY_SIZE {
        let entry_size = u32::from_be_bytes([
            s_nv[cursor],
            s_nv[cursor + 1],
            s_nv[cursor + 2],
            s_nv[cursor + 3],
        ]) as usize;
        if entry_size == 0 || entry_size < DYNAMIC_NODE_HEADER_SIZE {
            break;
        }
        if cursor + entry_size > NV_MEMORY_SIZE {
            break;
        }
        let handle = u32::from_be_bytes([
            s_nv[cursor + 4],
            s_nv[cursor + 5],
            s_nv[cursor + 6],
            s_nv[cursor + 7],
        ]);
        let attributes = u32::from_be_bytes([
            s_nv[cursor + 8],
            s_nv[cursor + 9],
            s_nv[cursor + 10],
            s_nv[cursor + 11],
        ]);
        let payload_len = entry_size - DYNAMIC_NODE_HEADER_SIZE;
        let payload = &s_nv[cursor + DYNAMIC_NODE_HEADER_SIZE..cursor + entry_size];

        if handle != HIERARCHY_AUTH_HANDLE {
            let _ = storage_mgr.undefine_space(handle);
            storage_mgr.define_space(handle, payload_len as u16, attributes)?;
            storage_mgr.write_item(handle, 0, payload)?;
        }
        cursor += entry_size;
    }

    if cursor + 12 <= NV_MEMORY_SIZE
        && u32::from_be_bytes([
            s_nv[cursor],
            s_nv[cursor + 1],
            s_nv[cursor + 2],
            s_nv[cursor + 3],
        ]) == 0
    {
        storage.write_nv(16, &s_nv[cursor + 4..cursor + 12])?; // max_counter (u64)
    }

    Ok(())
}

/// Rollback Migration Transcoder: translates `tpm-rs` `StorageManager` storage
/// into an `ibmswtpm2` monolithic 16 KB `s_NV` image.
pub fn transcode_storage_to_s_nv(
    storage: &mut dyn NvStorage,
    s_nv: &mut [u8; NV_MEMORY_SIZE],
) -> Result<(), StorageError> {
    // 1. Zero-initialize the target 16 KB `s_NV` buffer.
    s_nv.fill(0);

    // 2. Read reserved header (0..128) from `tpm-rs` storage and populate `gp` & `go`.
    let mut hdr = [0u8; RESERVED_SIZE];
    storage.read_nv(0, &mut hdr)?;

    // reset_count (0..4) -> gp offset 740..744
    s_nv[740..744].copy_from_slice(&hdr[0..4]);
    // total_reset_count (8..12) -> gp offset 732..736
    s_nv[732..736].copy_from_slice(&hdr[8..12]);
    // orderly_state (4..6) -> gp offset 748..750
    s_nv[748..750].copy_from_slice(&hdr[4..6]);
    // time_epoch (24..32) -> gp offset 750..758
    s_nv[750..758].copy_from_slice(&hdr[24..32]);
    // failed_tries (32..36) -> gp offset 744..748
    s_nv[744..748].copy_from_slice(&hdr[32..36]);

    // drbg_state (36..112) -> go offset 2876..2952
    s_nv[NV_ORDERLY_DATA_OFFSET..NV_ORDERLY_DATA_OFFSET + 76].copy_from_slice(&hdr[36..112]);
    // self_heal_timer & lockout_timer (112..128) -> go offset 2952..2968
    s_nv[NV_ORDERLY_DATA_OFFSET + 76..NV_ORDERLY_DATA_OFFSET + 92].copy_from_slice(&hdr[112..128]);

    // 3. Unpack `0x00FFFFFF` (HIERARCHY_AUTH_HANDLE) from `StorageManager` into `gp`, `gr`, and `gc`.
    let storage_mgr = StorageManager::new(storage);
    let mut auth_buf = [0u8; 1152];
    if let Ok(meta) = storage_mgr.get_metadata(HIERARCHY_AUTH_HANDLE) {
        let read_len = core::cmp::min(meta.data_size as usize, 1152);
        if storage_mgr
            .read_item(HIERARCHY_AUTH_HANDLE, 0, &mut auth_buf[..read_len])
            .is_ok()
        {
            let mut slice = &auth_buf[..read_len];
            // Auths: owner, endorsement, platform, lockout
            write_fixed_tpm2b(&mut s_nv[204..204 + FIXED_TPM2B_SIZE], &mut slice);
            write_fixed_tpm2b(&mut s_nv[270..270 + FIXED_TPM2B_SIZE], &mut slice);
            write_fixed_tpm2b(
                &mut s_nv[NV_STATE_CLEAR_DATA_OFFSET + 72
                    ..NV_STATE_CLEAR_DATA_OFFSET + 72 + FIXED_TPM2B_SIZE],
                &mut slice,
            );
            write_fixed_tpm2b(&mut s_nv[336..336 + FIXED_TPM2B_SIZE], &mut slice);

            // Policies: owner, endorsement, platform, lockout
            write_fixed_tpm2b(&mut s_nv[6..6 + FIXED_TPM2B_SIZE], &mut slice);
            write_fixed_tpm2b(&mut s_nv[72..72 + FIXED_TPM2B_SIZE], &mut slice);
            write_fixed_tpm2b(
                &mut s_nv[NV_STATE_CLEAR_DATA_OFFSET + 6
                    ..NV_STATE_CLEAR_DATA_OFFSET + 6 + FIXED_TPM2B_SIZE],
                &mut slice,
            );
            write_fixed_tpm2b(&mut s_nv[138..138 + FIXED_TPM2B_SIZE], &mut slice);

            // Algorithms: owner, endorsement, platform, lockout (2 bytes each)
            if slice.len() >= 8 {
                s_nv[0..2].copy_from_slice(&slice[0..2]);
                s_nv[2..4].copy_from_slice(&slice[2..4]);
                s_nv[NV_STATE_CLEAR_DATA_OFFSET + 4..NV_STATE_CLEAR_DATA_OFFSET + 6]
                    .copy_from_slice(&slice[4..6]);
                s_nv[4..6].copy_from_slice(&slice[6..8]);
                slice = &slice[8..];
            }

            // 405-byte tail: sh_enable, eh_enable, ph_enable_nv, magic 0xAA, seeds, proofs, clear_count
            if slice.len() >= 405 && slice[3] == 0xAA {
                s_nv[NV_STATE_CLEAR_DATA_OFFSET] = slice[0];
                s_nv[NV_STATE_CLEAR_DATA_OFFSET + 1] = slice[1];
                s_nv[NV_STATE_CLEAR_DATA_OFFSET + 2] = slice[2];
                slice = &slice[4..];

                // sp_seed -> gp offset 402..468
                s_nv[402..402 + FIXED_TPM2B_SIZE].copy_from_slice(&slice[0..FIXED_TPM2B_SIZE]);
                slice = &slice[FIXED_TPM2B_SIZE..];
                // sh_proof -> gp offset 600..666
                s_nv[600..600 + FIXED_TPM2B_SIZE].copy_from_slice(&slice[0..FIXED_TPM2B_SIZE]);
                slice = &slice[FIXED_TPM2B_SIZE..];
                // eh_proof -> gp offset 666..732
                s_nv[666..666 + FIXED_TPM2B_SIZE].copy_from_slice(&slice[0..FIXED_TPM2B_SIZE]);
                slice = &slice[FIXED_TPM2B_SIZE..];
                // clear_count -> gc offset 1242..1246
                s_nv[NV_STATE_CLEAR_DATA_OFFSET + 138..NV_STATE_CLEAR_DATA_OFFSET + 142]
                    .copy_from_slice(&slice[0..4]);
                slice = &slice[4..];
                // pp_seed -> gp offset 468..534
                s_nv[468..468 + FIXED_TPM2B_SIZE].copy_from_slice(&slice[0..FIXED_TPM2B_SIZE]);
                slice = &slice[FIXED_TPM2B_SIZE..];
                // ph_proof -> gr offset 792..858
                s_nv[NV_STATE_RESET_DATA_OFFSET..NV_STATE_RESET_DATA_OFFSET + FIXED_TPM2B_SIZE]
                    .copy_from_slice(&slice[0..FIXED_TPM2B_SIZE]);
                slice = &slice[FIXED_TPM2B_SIZE..];
                // ep_seed -> gp offset 534..600
                s_nv[534..534 + FIXED_TPM2B_SIZE].copy_from_slice(&slice[0..FIXED_TPM2B_SIZE]);
                slice = &slice[FIXED_TPM2B_SIZE..];

                if slice.len() >= 2 {
                    s_nv[NV_STATE_CLEAR_DATA_OFFSET + 142..NV_STATE_CLEAR_DATA_OFFSET + 144]
                        .copy_from_slice(&slice[0..2]);
                    slice = &slice[2..];
                    write_fixed_tpm2b(
                        &mut s_nv[NV_STATE_CLEAR_DATA_OFFSET + 144
                            ..NV_STATE_CLEAR_DATA_OFFSET + 144 + FIXED_TPM2B_SIZE],
                        &mut slice,
                    );
                    write_fixed_tpm2b(
                        &mut s_nv[NV_STATE_CLEAR_DATA_OFFSET + 210
                            ..NV_STATE_CLEAR_DATA_OFFSET + 210 + FIXED_TPM2B_SIZE],
                        &mut slice,
                    );
                }
            }
        }
    }

    // 4. Walk TOC entries in `StorageManager` and write linked-list nodes starting at `NV_USER_DYNAMIC_OFFSET`.
    let toc = storage_mgr.read_toc()?;
    let mut cursor = NV_USER_DYNAMIC_OFFSET;

    for item in toc.iter() {
        if item.in_use == 0 {
            break;
        }
        if item.handle == HIERARCHY_AUTH_HANDLE {
            continue;
        }
        let payload_len = item.data_size as usize;
        let entry_size = DYNAMIC_NODE_HEADER_SIZE + payload_len;
        // Require at least 12 trailing bytes for the end-of-list marker (4B) + max_counter (8B).
        if cursor + entry_size + 12 > NV_MEMORY_SIZE {
            return Err(StorageError::OutOfBounds);
        }

        s_nv[cursor..cursor + 4].copy_from_slice(&(entry_size as u32).to_be_bytes());
        s_nv[cursor + 4..cursor + 8].copy_from_slice(&item.handle.to_be_bytes());
        s_nv[cursor + 8..cursor + 12].copy_from_slice(&item.attributes.to_be_bytes());

        storage_mgr.read_item(
            item.handle,
            0,
            &mut s_nv[cursor + DYNAMIC_NODE_HEADER_SIZE..cursor + entry_size],
        )?;
        cursor += entry_size;
    }

    // Write end-of-list marker (size = 0) and trailing max_counter (8B) at cursor.
    if cursor + 12 <= NV_MEMORY_SIZE {
        s_nv[cursor..cursor + 4].copy_from_slice(&0u32.to_be_bytes());
        s_nv[cursor + 4..cursor + 12].copy_from_slice(&hdr[16..24]);
    }

    Ok(())
}
