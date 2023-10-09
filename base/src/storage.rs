use crate::errors::TpmResult;

/// Cheap-to-copy handle that represents a partition within a storage system.
#[derive(Eq, PartialEq, Hash)]
pub struct PartitionId(pub usize);
/// Cheap-to-copy handle that represents a file within a storage system.
#[derive(Eq, PartialEq, Hash)]
pub struct FileId(pub usize);

impl PartitionId {
    /// Partition that contains all PCR information.
    pub const PCR: Self = Self(0x001007);
    /// Partition that contains all persistent objects.
    pub const PERSISTENT: Self = Self(0x001008);
}

pub trait Storage {
    /// Reads entire file into `buf` and returns the number of bytes written to `buf`
    fn read_all(&self, partition: PartitionId, file: FileId, buf: &mut [u8]) -> TpmResult<usize>;

    /// Reads the file starting at `offset` and for `buf.len()` bytes.
    fn read_at(
        &self,
        partition: PartitionId,
        file: FileId,
        offset: usize,
        buf: &mut [u8],
    ) -> TpmResult<()>;

    /// Creates or overwrites the file in the specified partition with the specified contents.
    fn write_all(&mut self, partition: PartitionId, file: FileId, buf: &[u8]) -> TpmResult<()>;
}

// TODO put in separate unit testing folder
#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::errors::TpmError;
    use std::collections::HashMap;

    pub struct FakeStorage {
        partitions: HashMap<PartitionId, HashMap<FileId, Vec<u8>>>,
    }

    impl FakeStorage {
        pub fn new() -> Self {
            Self {
                partitions: HashMap::new(),
            }
        }

        /// Gets the number of files in storage. Note this is a test only method.
        pub fn file_count(&self) -> usize {
            self.partitions.values().map(|p| p.keys().count()).sum()
        }

        /// Gets the contents of the file. Not this is a test only method
        pub fn file_contents(&self, partition: PartitionId, file: FileId) -> Option<&Vec<u8>> {
            self.partitions.get(&partition)?.get(&file)
        }

        /// Gets the contents of the file. Not this is a test only method
        pub fn file_contents_mut(
            &mut self,
            partition: PartitionId,
            file: FileId,
        ) -> Option<&mut Vec<u8>> {
            self.partitions.get_mut(&partition)?.get_mut(&file)
        }
    }

    impl Storage for FakeStorage {
        fn read_all(
            &self,
            partition: PartitionId,
            file: FileId,
            buf: &mut [u8],
        ) -> TpmResult<usize> {
            // Get the partition or return an error
            let Some(p) = self.partitions.get(&partition) else {
                return Err(TpmError::TSS2_BASE_RC_IO_ERROR);
            };

            // Get the file or return an error
            let Some(f) = p.get(&file) else {
                return Err(TpmError::TSS2_BASE_RC_IO_ERROR);
            };

            // Ensure that the buffer passed in is large enough for file contents
            let Some(buf) = buf.get_mut(..f.len()) else {
                return Err(TpmError::TSS2_BASE_RC_IO_ERROR);
            };

            buf.copy_from_slice(f);
            Ok(buf.len())
        }

        fn read_at(
            &self,
            partition: PartitionId,
            file: FileId,
            offset: usize,
            buf: &mut [u8],
        ) -> TpmResult<()> {
            // Get the partition or return an error
            let Some(p) = self.partitions.get(&partition) else {
                return Err(TpmError::TSS2_BASE_RC_IO_ERROR);
            };

            // Get the file or return an error
            let Some(f) = p.get(&file) else {
                return Err(TpmError::TSS2_BASE_RC_IO_ERROR);
            };

            // Ensure the file has the desired data range
            let Some(f) = f.get(offset..offset + buf.len()) else {
                return Err(TpmError::TSS2_BASE_RC_IO_ERROR);
            };

            buf.copy_from_slice(f);
            Ok(())
        }

        fn write_all(&mut self, partition: PartitionId, file: FileId, buf: &[u8]) -> TpmResult<()> {
            let current = self
                .partitions
                .entry(partition)
                .or_default()
                .entry(file)
                .or_default();
            core::mem::swap(current, &mut Vec::from(buf));

            Ok(())
        }
    }

    // TODO add tests for fake to ensure that fake is working as intended
}
