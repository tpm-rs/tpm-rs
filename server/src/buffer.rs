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

/// Provides access to the TPM command request object and then a one-way conversion to the mutable
/// response object for the TPM command.
pub struct RequestThenResponse<'a, B: TpmBuffers> {
    buffers: &'a mut RequestResponseCursor<B>,
}

impl<'a, B: TpmBuffers> RequestThenResponse<'a, B> {
    /// Reads a `u16` encoded in big endian from the request's last read position. Increments the
    /// last position past this field. Returns `None` if the read would have read past the end of
    /// the request.
    pub fn read_be_u16(&mut self) -> Option<u16> {
        let result = self
            .buffers
            .buffers
            .get_request()
            .read_be_u16(self.buffers.request_offset)
            .ok()?;
        self.buffers.request_offset += core::mem::size_of::<u16>();
        Some(result)
    }

    /// Reads a `u32` encoded in big endian from the request's last read position. Increments the
    /// last position past this field. Returns `None` if the read would have read past the end of
    /// the request.
    pub fn read_be_u32(&mut self) -> Option<u32> {
        let result = self
            .buffers
            .buffers
            .get_request()
            .read_be_u32(self.buffers.request_offset)
            .ok()?;
        self.buffers.request_offset += core::mem::size_of::<u32>();
        Some(result)
    }

    /// Converts this request view into a mutable response that can be written to.
    pub fn into_response(self) -> Response<'a, B> {
        Response {
            buffers: self.buffers,
        }
    }
}

/// A mutable [`Response`] view of the output `TpmWriteBuffer`.
pub struct Response<'a, B: TpmBuffers> {
    buffers: &'a mut RequestResponseCursor<B>,
}

impl<'a, B: TpmBuffers> Response<'a, B> {
    /// Writes the specified `data` at the last written location and updates the internal
    /// last written location. Returns [`WriteOutOfBounds`] if write would have written past the the
    /// of the underlying [`TpmWriteBuffer`].
    pub fn write(&mut self, data: &[u8]) -> Result<(), WriteOutOfBounds> {
        self.buffers
            .buffers
            .get_response()
            .write(self.buffers.response_offset, data)?;
        self.buffers.response_offset += data.len();
        Ok(())
    }

    /// Allows writing the the underlying [`TpmWriteBuffer`] in place at the current last written
    /// location and updates the last written location. Returns [`WriteOutOfBounds`] if write would
    /// have written past the the of the underlying [`TpmWriteBuffer`].
    pub fn write_callback(
        &mut self,
        size: usize,
        callback: impl FnOnce(&mut [u8]),
    ) -> Result<(), WriteOutOfBounds> {
        self.buffers.buffers.get_response().write_callback(
            self.buffers.response_offset,
            size,
            callback,
        )?;
        self.buffers.response_offset += size;
        Ok(())
    }
}

/// Provides access to request and response while along tracking most recent read and written
/// locations.
pub struct RequestResponseCursor<B: TpmBuffers> {
    buffers: B,
    request_offset: usize,
    response_offset: usize,
}

impl<B: TpmBuffers> RequestResponseCursor<B> {
    /// Create a new [`RequestResponseCursor`] with a request offset of `0` and the specified
    /// response offset.
    pub fn new(buffers: B, response_offset: usize) -> Self {
        Self {
            buffers,
            request_offset: 0,
            response_offset,
        }
    }

    /// Gets the [`RequestThenResponse`] that can access the request, then be converted into a
    /// response view.
    pub fn request(&mut self) -> RequestThenResponse<B> {
        RequestThenResponse { buffers: self }
    }

    /// Gets the index of the last byte written to response buffer.
    pub fn last_response_byte_written(&self) -> usize {
        self.response_offset
    }

    /// Gets the full response buffer including any unwritten portions.
    pub fn response(&mut self) -> &mut B::Response {
        self.buffers.get_response()
    }
}
