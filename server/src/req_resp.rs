use crate::platform::{TpmBuffers, TpmReadBuffer, TpmWriteBuffer, WriteOutOfBounds};

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
    #[expect(
        dead_code,
        reason = "This function may be used later in the future, but it is not yet"
    )]
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
