use crate::platform::{ReadOutOfBounds, TpmBuffers, TpmReadBuffer, TpmWriteBuffer};

/// Abstraction that Represents a request and response that existing in the same mutable buffer.
pub struct InOutBuffer<'a, W: ?Sized> {
    buffer: &'a mut W,
    // number of bytes that can be read from buffer
    len: usize,
}

impl<'a, W: TpmWriteBuffer + ?Sized> InOutBuffer<'a, W> {
    pub fn new(buffer: &'a mut W, request_size: usize) -> Self {
        let len = request_size.min(buffer.len());
        Self { buffer, len }
    }
}

impl<W: TpmWriteBuffer + ?Sized> TpmBuffers for InOutBuffer<'_, W> {
    type Request = Self;
    type Response = W;

    fn get_request(&self) -> &Self::Request {
        self
    }
    fn get_response(&mut self) -> &mut Self::Response {
        self.buffer
    }
}

impl<W: TpmWriteBuffer + ?Sized> TpmReadBuffer for InOutBuffer<'_, W> {
    fn len(&self) -> usize {
        self.len
    }

    fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<(), ReadOutOfBounds> {
        // Limit the read view to only the request portion of the in-place buffer
        if self.len < offset + out.len() {
            return Err(ReadOutOfBounds);
        }
        self.buffer.read_into(offset, out)
    }
}
