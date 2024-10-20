/// Error indicating that read would have read past the of of the `TpmReadBuffer`.
pub struct ReadOutOfBounds;

/// The input request buffer that can be read via random access.
pub trait TpmReadBuffer {
    /// Returns the available length of this buffer.
    fn len(&self) -> usize;

    /// Returns if the buffer is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // Reads into the specified buffer from the specified offset. The size of the out buffer
    // determines the size of the read operation. Returns [`ReadOutOfBounds`] if the request read
    // would go beyond the length of the buffer.
    fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<(), ReadOutOfBounds>;

    /// Reads a `u16` encoded in big endian at the specified offset. Specific implementors may
    /// provide a more optimized version.
    fn read_be_u16(&self, offset: usize) -> Result<u16, ReadOutOfBounds> {
        let mut buffer: [u8; 2] = Default::default();
        self.read_into(offset, &mut buffer[..])?;
        Ok(u16::from_be_bytes(buffer))
    }

    /// Reads a `u32` encoded in big endian at the specified offset. Specific implementors may
    /// provide a more optimized version.
    fn read_be_u32(&self, offset: usize) -> Result<u32, ReadOutOfBounds> {
        let mut buffer: [u8; 4] = Default::default();
        self.read_into(offset, &mut buffer[..])?;
        Ok(u32::from_be_bytes(buffer))
    }
}

/// Error indicating that write would have written past the of of the [`TpmWriteBuffer`].
pub struct WriteOutOfBounds;

/// The output response buffer that can be read and written via random access.
pub trait TpmWriteBuffer: TpmReadBuffer {
    /// Writes the specified data at the specified offset to the output [`TpmWriteBuffer`]. If this
    /// write would write past the bounds of this [`TpmWriteBuffer`], then [`WriteOutOfBounds`] is
    /// returned instead.
    fn write(&mut self, write_offset: usize, data: &[u8]) -> Result<(), WriteOutOfBounds>;

    /// Gets a mutable slice from the [`TpmWriteBuffer`] that can be written in place via the
    /// provided callback. The callback will return a mutable slice that has length `size`. If the
    /// write operation would have written past the bounds of this [`TpmWriteBuffer`], then
    /// [`WriteOutOfBounds`] is returned instead and the callback is never called.
    fn write_callback(
        &mut self,
        write_offset: usize,
        size: usize,
        callback: impl FnOnce(&mut [u8]),
    ) -> Result<(), WriteOutOfBounds>;
}

impl TpmReadBuffer for [u8] {
    fn len(&self) -> usize {
        self.len()
    }
    fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<(), ReadOutOfBounds> {
        let read_from = self
            .get(offset..offset + out.len())
            .ok_or(ReadOutOfBounds)?;
        out.copy_from_slice(read_from);
        Ok(())
    }
}

impl TpmWriteBuffer for [u8] {
    fn write(&mut self, write_offset: usize, data: &[u8]) -> Result<(), WriteOutOfBounds> {
        let write_to = self
            .get_mut(write_offset..write_offset + data.len())
            .ok_or(WriteOutOfBounds)?;
        write_to.copy_from_slice(data);

        Ok(())
    }
    fn write_callback(
        &mut self,
        write_offset: usize,
        size: usize,
        callback: impl FnOnce(&mut [u8]),
    ) -> Result<(), WriteOutOfBounds> {
        let Some(buffer) = self.get_mut(write_offset..write_offset + size) else {
            return Err(WriteOutOfBounds);
        };
        callback(buffer);
        Ok(())
    }
}

/// Allows access to the TPM request or TPM response. This layers allows handler code to be written
/// generically to handle either two separate buffers or a single in-place buffer. This is not meant
/// to be implemented by client code and is only used internally.
pub trait TpmBuffers {
    /// The type of the input request buffer for command processing.
    type Request: TpmReadBuffer + ?Sized;
    /// The type of the output response buffer for command processing.
    type Response: TpmWriteBuffer + ?Sized;

    /// Gets the request object.
    fn get_request(&self) -> &Self::Request;

    /// Gets the mutable response object.
    fn get_response(&mut self) -> &mut Self::Response;
}
