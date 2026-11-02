use tpm2::crypto::{Crypto, CryptoError, HashContext, hash};
use tpm2::{
    Handle, Tpm2bName, TpmCc, TpmHt, TpmiAlgHash, TpmsAuthCommand, TpmsAuthResponse, TpmtHa,
};

/// Error occurring during session authorization validation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthError {
    /// Authorization response attributes, nonce, or HMAC were invalid.
    InvalidResponse,
    /// A session needed the Name of a handle that can't be derived from the
    /// handle value (e.g. an NV index or object), and none was provided.
    MissingName,
    /// A cryptographic operation failed.
    Crypto(CryptoError),
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidResponse => write!(f, "invalid authorization response"),
            Self::MissingName => write!(f, "missing Name for command handle"),
            Self::Crypto(e) => write!(f, "cryptographic error: {e:?}"),
        }
    }
}

impl core::error::Error for AuthError {}

impl From<CryptoError> for AuthError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

/// The parts of a command that sessions authorize.
#[derive(Clone, Copy, Debug)]
pub struct CommandData<'a> {
    /// The command code.
    pub code: TpmCc,
    /// The command's handle area.
    pub handles: &'a [Handle],
    /// Names of the handles, in handle order. `None` (or a missing entry)
    /// means that the Name is derived from the handle value, which is only
    /// possible for PCR, session, and permanent handles.
    pub names: &'a [Option<Tpm2bName<'a>>],
    /// The marshaled command parameters.
    pub params: &'a [u8],
}

impl CommandData<'_> {
    /// Returns the Name of the `i`th handle.
    fn name(&self, i: usize) -> Result<NameBytes<'_>, AuthError> {
        if let Some(Some(name)) = self.names.get(i) {
            return Ok(NameBytes::Provided(*name));
        }
        // TPM 2.0 Part 1, Section 16: these handle types use the handle
        // value as their Name.
        let handle = self.handles[i];
        match handle.handle_type() {
            Some(TpmHt::PCR | TpmHt::HMACSession | TpmHt::PolicySession | TpmHt::Permanent) => {
                Ok(NameBytes::Handle(handle.0.to_be_bytes()))
            }
            _ => Err(AuthError::MissingName),
        }
    }

    /// Computes the command parameter hash:
    ///
    /// ```text
    /// cpHash := H(commandCode || Name(handle1) || ... || Name(handleN) || parameters)
    /// ```
    ///
    /// NOTE: This matches the TPM 2.0 reference implementation (C code),
    /// which we integrate against for now. We may review this against the
    /// latest spec later.
    pub fn cp_hash<'o, C: Crypto>(
        &self,
        alg: TpmiAlgHash,
        out: &'o mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
    ) -> Result<TpmtHa<'o>, AuthError> {
        if self.names.len() > self.handles.len() {
            return Err(AuthError::MissingName);
        }
        let mut stream = HashContext::<C>::new(alg)?;
        stream.update(&self.code.code().to_be_bytes())?;
        for i in 0..self.handles.len() {
            stream.update(self.name(i)?.as_slice())?;
        }
        stream.update(self.params)?;
        Ok(stream.finalize(out)?)
    }
}

/// A handle's Name, either provided by the caller or derived from the handle.
enum NameBytes<'a> {
    Provided(Tpm2bName<'a>),
    Handle([u8; 4]),
}

impl NameBytes<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Provided(name) => name.as_slice(),
            Self::Handle(bytes) => bytes,
        }
    }
}

/// The parts of a (successful) response that sessions authorize.
#[derive(Clone, Copy, Debug)]
pub struct ResponseData<'a> {
    /// The code of the command this is a response to.
    pub code: TpmCc,
    /// The marshaled response parameters.
    pub params: &'a [u8],
}

impl ResponseData<'_> {
    /// Computes the response parameter hash:
    ///
    /// ```text
    /// rpHash := H(responseCode || commandCode || parameters)
    /// ```
    ///
    /// where `responseCode` is always `TPM_RC_SUCCESS`, as only successful
    /// responses have an authorization area.
    ///
    /// NOTE: The latest spec omits `commandCode`, but the TPM 2.0 reference
    /// implementation (C code), which we integrate against for now,
    /// includes it. We may review this later.
    pub fn rp_hash<'o, C: Crypto>(
        &self,
        alg: TpmiAlgHash,
        out: &'o mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
    ) -> Result<TpmtHa<'o>, AuthError> {
        let parts: [&[u8]; 3] = [
            &0u32.to_be_bytes(),
            &self.code.code().to_be_bytes(),
            self.params,
        ];
        Ok(hash::<C>(alg, &parts, out)?)
    }
}

/// Trait for types representing TPM sessions.
///
/// Sessions are stateful (e.g. HMAC sessions roll their nonces on every
/// command), so they are used via `&mut`.
pub trait Session {
    /// Computes the authorization for the command `cmd`.
    fn auth_command(&mut self, cmd: &CommandData) -> Result<TpmsAuthCommand<'_>, AuthError>;
    /// Validates the authorization response for the response `rsp`.
    fn validate_auth_response(
        &mut self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
    ) -> Result<(), AuthError>;
}

// Forward methods, so that a tuple of `&mut` sessions is an `AuthorizationArea`.
impl<S: Session + ?Sized> Session for &mut S {
    fn auth_command(&mut self, cmd: &CommandData) -> Result<TpmsAuthCommand<'_>, AuthError> {
        (**self).auth_command(cmd)
    }
    fn validate_auth_response(
        &mut self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
    ) -> Result<(), AuthError> {
        (**self).validate_auth_response(rsp, auth)
    }
}

impl Session for ! {
    fn auth_command(&mut self, _: &CommandData) -> Result<TpmsAuthCommand<'_>, AuthError> {
        match *self {}
    }
    fn validate_auth_response(
        &mut self,
        _: &ResponseData,
        _: &TpmsAuthResponse,
    ) -> Result<(), AuthError> {
        match *self {}
    }
}
