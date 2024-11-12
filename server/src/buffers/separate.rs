use crate::platform::{TpmBuffers, TpmReadBuffer, TpmWriteBuffer};

/// Abstraction layer that represents a separate request and response buffer.
pub struct SeparateBuffers<'a, R: ?Sized, W: ?Sized> {
    reader: &'a R,
    writer: &'a mut W,
}

impl<'a, R, W> SeparateBuffers<'a, R, W>
where
    R: TpmReadBuffer + ?Sized,
    W: TpmWriteBuffer + ?Sized,
{
    pub fn new(reader: &'a R, writer: &'a mut W) -> Self {
        Self { reader, writer }
    }
}

impl<'a, R, W> TpmBuffers for SeparateBuffers<'a, R, W>
where
    R: TpmReadBuffer + ?Sized,
    W: TpmWriteBuffer + ?Sized,
{
    type Request = R;
    type Response = W;

    fn get_request(&self) -> &Self::Request {
        self.reader
    }
    fn get_response(&mut self) -> &mut Self::Response {
        self.writer
    }
}
