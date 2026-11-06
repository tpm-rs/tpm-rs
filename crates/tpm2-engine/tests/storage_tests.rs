use tpm2_engine::storage::ram_storage_mock::RamStorageMock;
use tpm2_engine::storage::{IndexState, NvStorage, StorageError};

// =========================================================================
// Tests from src/storage/ram_storage_mock.rs
// =========================================================================

#[test]
fn test_ram_storage() {
    let mut storage = RamStorageMock::<128>::new();
    let write_buf = b"hello tpm2";
    storage.write_nv(10, write_buf).unwrap();

    let mut read_buf = [0u8; 10];
    storage.read_nv(10, &mut read_buf).unwrap();
    assert_eq!(&read_buf, write_buf);

    // Out of bounds
    assert!(storage.read_nv(120, &mut [0u8; 20]).is_err());
    assert!(storage.write_nv(120, &[0u8; 20]).is_err());
}

// =========================================================================
// Tests from src/storage/manager.rs
// =========================================================================

#[test]
fn test_manager_define_write_read() {
    // Room for the table of contents (`MAX_ITEMS` entries) and the items.
    let mut ram = RamStorageMock::<4096>::new();
    let manager = &mut ram;

    // Define a 64 byte NV index
    manager.define_space(0x01500000, 64, 0).unwrap();

    let msg = b"TPM test message";
    manager.write_item(0x01500000, 0, msg).unwrap();

    let mut out = [0u8; 16];
    manager.read_item(0x01500000, 0, &mut out).unwrap();
    assert_eq!(&out, msg);

    let meta = manager.get_metadata(0x01500000).unwrap();
    assert_eq!(meta.data_size, 64);
    assert_eq!(meta.attributes, 0);
}

#[test]
fn test_manager_compaction() {
    // Room for the table of contents (`MAX_ITEMS` entries) and the items.
    let mut ram = RamStorageMock::<4096>::new();
    let manager = &mut ram;

    manager.define_space(0x81000001, 10, 0).unwrap(); // Persistent Key 1
    manager.define_space(0x81000002, 20, 0).unwrap(); // Persistent Key 2
    manager.define_space(0x81000003, 10, 0).unwrap(); // Persistent Key 3

    manager.write_item(0x81000001, 0, &[1; 10]).unwrap();
    manager.write_item(0x81000002, 0, &[2; 20]).unwrap();
    manager.write_item(0x81000003, 0, &[3; 10]).unwrap();

    // Remove the middle one
    manager.undefine_space(0x81000002).unwrap();

    // Ensure key 3 shifted correctly and is still readable
    let mut out = [0u8; 10];
    manager.read_item(0x81000003, 0, &mut out).unwrap();
    assert_eq!(&out, &[3; 10]);

    // Key 2 should be gone
    assert_eq!(
        manager.read_item(0x81000002, 0, &mut out),
        Err(StorageError::AccessDenied)
    );
}
