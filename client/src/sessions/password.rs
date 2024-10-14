use crate::sessions::Session;
use tpm2_rs_base::errors::{TpmRcResult, TssResult, TssTcsError};
use tpm2_rs_base::{
    Tpm2bAuth, Tpm2bNonce, Tpm2bSimple, TpmaSession, TpmiShAuthSession, TpmsAuthCommand,
    TpmsAuthResponse,
};

/// A password session.
///
/// # Usage:
/// ```
/// use tpm2_rs_client::sessions::PasswordSession;
///
/// let password1 = PasswordSession::new("hello world").unwrap(); // from a string
/// let password2 = PasswordSession::new(&[1, 2, 3, 4, 5, 6]).unwrap(); // from a byte array
///
/// assert_eq!(password1.get_secret(), b"hello world");
/// assert_eq!(password2.get_secret(), &[1, 2, 3, 4, 5, 6]);
/// ```
#[derive(Debug, PartialEq, Default)]
pub struct PasswordSession {
    auth: Tpm2bAuth,
}

impl PasswordSession {
    /// This function creates a new password session using the
    /// specified password.
    ///
    /// # Errors:
    /// Returns [TpmRcError::Size](tpm2_rs_base::errors::TpmRcError::Size) if the
    /// password size in bytes exceeds [`Tpm2bAuth::MAX_BUFFER_SIZE`].
    ///
    /// ```
    /// use tpm2_rs_base::{errors::TpmRcError, Tpm2bAuth, Tpm2bSimple};
    /// use tpm2_rs_client::sessions::PasswordSession;
    ///
    /// let bad_password = [0u8; Tpm2bAuth::MAX_BUFFER_SIZE + 1];
    /// assert_eq!(
    ///     PasswordSession::new(&bad_password).err().unwrap(),
    ///     TpmRcError::Size
    /// );

    /// ```
    pub fn new<T: AsRef<[u8]> + ?Sized>(password: &T) -> TpmRcResult<Self> {
        Ok(PasswordSession {
            auth: Tpm2bAuth::from_bytes(password.as_ref())?,
        })
    }
    /// This function returns the data(password) stored inside a password session
    pub fn get_secret(&self) -> &[u8] {
        self.auth.get_buffer()
    }
}

impl Session for PasswordSession {
    fn get_auth_command(&self) -> TpmsAuthCommand {
        TpmsAuthCommand {
            session_handle: TpmiShAuthSession::RS_PW,
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession(0),
            hmac: self.auth,
        }
    }
    fn validate_auth_response(&self, auth: &TpmsAuthResponse) -> TssResult<()> {
        // Password response auth should have empty nonce/hmac and ContinueSession attribute.
        if auth.nonce.get_size() != 0
            || auth.session_attributes.0 != 0x1
            || auth.hmac.get_size() != 0
        {
            Err(TssTcsError::BadParameter.into())
        } else {
            Ok(())
        }
    }
}
