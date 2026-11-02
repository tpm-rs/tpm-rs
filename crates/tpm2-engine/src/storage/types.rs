/// Type aliases for clarity
pub type Handle = u32;

/// A TPM handle category is usually identified by its highest byte.
/// Under TPM 2.0:
/// NV Indices start with 0x01
/// Persistent Objects start with 0x81
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HandleType {
    NvIndex,
    PersistentObject,
    Unknown,
}

impl From<u32> for HandleType {
    fn from(handle: u32) -> Self {
        match handle >> 24 {
            0x01 => HandleType::NvIndex,
            0x81 => HandleType::PersistentObject,
            _ => HandleType::Unknown,
        }
    }
}

/// Simple alloc-free fixed representation of metadata for an NV index or persistent object
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)] // Ensure predictable memory layout
pub struct ItemMetadata {
    pub handle: Handle,
    pub data_size: u16,
    pub attributes: u32,
    pub in_use: u8,
}

impl ItemMetadata {
    /// Serialized byte size of the [ItemMetadata] struct (handle: 4, data_size: 2, attributes: 4, in_use: 1 = 11 bytes).
    /// This is an implementation-specific value for the storage manager.
    pub const SIZE: usize = 11;

    pub const fn empty() -> Self {
        Self {
            handle: 0,
            data_size: 0,
            attributes: 0,
            in_use: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.handle.to_be_bytes());
        buf[4..6].copy_from_slice(&self.data_size.to_be_bytes());
        buf[6..10].copy_from_slice(&self.attributes.to_be_bytes());
        buf[10] = self.in_use;
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut handle_bytes = [0u8; 4];
        handle_bytes.copy_from_slice(&buf[0..4]);

        let mut size_bytes = [0u8; 2];
        size_bytes.copy_from_slice(&buf[4..6]);

        let mut attr_bytes = [0u8; 4];
        attr_bytes.copy_from_slice(&buf[6..10]);

        Self {
            handle: u32::from_be_bytes(handle_bytes),
            data_size: u16::from_be_bytes(size_bytes),
            attributes: u32::from_be_bytes(attr_bytes),
            in_use: buf[10],
        }
    }
}
