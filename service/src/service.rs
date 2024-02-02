use crate::buffer::{
    ReadOutOfBounds, RequestResponseCursor, TpmBuffers, TpmReadBuffer, TpmWriteBuffer,
};
use crate::crypto::Crypto;
use crate::handler::{self, CommandContext, ContextDeps};
use tpm2_rs_base::constants::Command;
use tpm2_rs_base::errors::TpmRcError;

/// Specifies all of the dependent types for `Service`.
pub trait ServiceDeps {
    /// Interface to perform cryptographic operations.
    type Crypto: Crypto;
    /// The type of the input request buffer for command processing.
    type Request: TpmReadBuffer + ?Sized;
    /// The type of the output response buffer for command processing.
    type Response: TpmWriteBuffer + ?Sized;
}

/// The object that processes incoming TPM requests and produces the corresponding TPM response.
pub struct Service<'a, Deps: ServiceDeps> {
    crypto: &'a mut Deps::Crypto,
}

impl<'a, Deps: ServiceDeps> Service<'a, Deps> {
    /// Creates a new `Service` object that processes incoming TPM requests.
    pub fn new(crypto: &'a mut Deps::Crypto) -> Self {
        Self { crypto }
    }

    /// Process a TPM request and writes the response in a separate buffer. Returns the number of
    /// bytes written to the response buffer.
    pub fn execute_command_separate(
        &mut self,
        request: &Deps::Request,
        response: &mut Deps::Response,
    ) -> usize {
        match self.execute_command(SeparateBuffers(request, response)) {
            Ok(size) => size,
            Err(err) => self.fill_error(response, err),
        }
    }

    /// Process a TPM request and write the response back into the same buffer. Returns the number
    /// of bytes written to the response buffer.
    pub fn execute_command_in_place(
        &mut self,
        in_out: &mut Deps::Response,
        request_size: usize,
    ) -> usize {
        match self.execute_command(InOutBuffer::new(in_out, request_size)) {
            Ok(size) => size,
            Err(err) => self.fill_error(in_out, err),
        }
    }

    fn fill_error(&mut self, response: &mut Deps::Response, error: TpmRcError) -> usize {
        // TODO fill out more of the TPM header for an error
        if response.write(6, &error.get().to_be_bytes()).is_err() {
            return 0;
        }
        10
    }

    fn execute_command(&mut self, buffers: impl TpmBuffers) -> Result<usize, TpmRcError> {
        let request_size = buffers.get_request().len();
        const CMD_HANDLER_RESPONSE_OFFSET: usize = 10;
        let mut request_and_response =
            RequestResponseCursor::new(buffers, CMD_HANDLER_RESPONSE_OFFSET);
        let mut request = request_and_response.request();
        let _session = request.read_be_u16().ok_or(TpmRcError::CommandSize)?;
        let size = request.read_be_u32().ok_or(TpmRcError::CommandSize)?;
        if size as usize != request_size {
            return Err(TpmRcError::CommandSize);
        }
        let command_code = request.read_be_u32().ok_or(TpmRcError::CommandSize)?;

        // TODO, if _session is not NoSession, then parse session stuff here

        let context = &mut CommandContext::<Deps> {
            crypto: self.crypto,
        };

        match Command(command_code) {
            Command::GetRandom => handler::get_random(request, context),
            _ => Err(TpmRcError::CommandCode),
        }?;

        let response_size = request_and_response.last_response_byte_written();
        let response = request_and_response.response();
        // TODO add session information
        let session_tag = 0x8001_u16;
        response
            .write(0, &(session_tag).to_be_bytes())
            .or(Err(TpmRcError::Memory))?;

        response
            .write(2, &(response_size as u32).to_be_bytes())
            .or(Err(TpmRcError::Memory))?;
        const SUCCESS_STATUS: u32 = 0;
        response
            .write(6, &SUCCESS_STATUS.to_be_bytes())
            .or(Err(TpmRcError::Memory))?;

        Ok(response_size)
    }
}

// Implement the `ContextDeps` for all types that implement `ServiceDeps` since ContextDeps is a
// subset.
impl<T: ServiceDeps> ContextDeps for T {
    type Crypto = T::Crypto;
}

/// Represents a request and response that existing in the same mutable buffer.
struct InOutBuffer<'a, W: TpmWriteBuffer + ?Sized>(&'a mut W, usize);
impl<'a, W: TpmWriteBuffer + ?Sized> TpmBuffers for InOutBuffer<'a, W> {
    type Request = Self;
    type Response = W;

    fn get_request(&self) -> &Self::Request {
        self
    }
    fn get_response(&mut self) -> &mut Self::Response {
        self.0
    }
}

impl<'a, W: TpmWriteBuffer + ?Sized> InOutBuffer<'a, W> {
    pub fn new(buffer: &'a mut W, request_size: usize) -> Self {
        Self(buffer, request_size.min(buffer.len()))
    }
}

impl<'a, W: TpmWriteBuffer + ?Sized> TpmReadBuffer for InOutBuffer<'a, W> {
    fn len(&self) -> usize {
        self.1
    }

    fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<(), ReadOutOfBounds> {
        // Limit the read view to only the request portion of the in-place buffer
        if self.1 < offset + out.len() {
            return Err(ReadOutOfBounds);
        }
        self.0.read_into(offset, out)
    }
}

/// Represents a separate request and response buffer.
struct SeparateBuffers<'a, R: TpmReadBuffer + ?Sized, W: TpmWriteBuffer + ?Sized>(&'a R, &'a mut W);
impl<'a, R: TpmReadBuffer + ?Sized, W: TpmWriteBuffer + ?Sized> TpmBuffers
    for SeparateBuffers<'a, R, W>
{
    type Request = R;
    type Response = W;

    fn get_request(&self) -> &Self::Request {
        self.0
    }
    fn get_response(&mut self) -> &mut Self::Response {
        self.1
    }
}
