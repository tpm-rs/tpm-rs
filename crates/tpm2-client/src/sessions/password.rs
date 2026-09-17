use crate::sessions::{AuthError, Session};
use tpm2::errors::TpmRc;
use tpm2::{Handle, Tpm2bAuth, Tpm2bNonce, TpmaSession, TpmsAuthCommand, TpmsAuthResponse};

/// A password session.
///
/// # Usage:
/// ```
/// use tpm2_client::sessions::PasswordSession;
///
/// let password1 = PasswordSession::new("hello world").unwrap(); // from a string
/// let password2 = PasswordSession::new(&[1, 2, 3, 4, 5, 6]).unwrap(); // from a byte array
///
/// assert_eq!(password1.secret(), b"hello world");
/// assert_eq!(password2.secret(), &[1, 2, 3, 4, 5, 6]);
/// ```
#[derive(Debug, PartialEq, Default)]
pub struct PasswordSession<'a> {
    auth: Tpm2bAuth<'a>,
}

impl<'a> PasswordSession<'a> {
    /// This function creates a new password session using the
    /// specified password.
    ///
    /// # Errors:
    /// Returns [TpmRc::SIZE](TpmRc::SIZE) if the
    /// password size in bytes exceeds [`Tpm2bAuth::CAP`].
    ///
    /// ```
    /// use tpm2::{errors::TpmRc, Tpm2bAuth};
    /// use tpm2_client::sessions::PasswordSession;
    ///
    /// let bad_password = [0u8; Tpm2bAuth::CAP + 1];
    /// assert_eq!(
    ///     PasswordSession::new(&bad_password).err().unwrap(),
    ///     TpmRc::SIZE.to_rc()
    /// );
    /// ```
    pub fn new<T: AsRef<[u8]> + ?Sized>(password: &'a T) -> Result<Self, TpmRc> {
        Ok(PasswordSession {
            auth: Tpm2bAuth::new(password.as_ref()).ok_or(TpmRc::SIZE.to_rc())?,
        })
    }
    /// This function returns the data(password) stored inside a password session
    pub fn secret(&self) -> &[u8] {
        self.auth.as_slice()
    }
}

impl Session for PasswordSession<'_> {
    fn auth_command(&self) -> TpmsAuthCommand<'_> {
        TpmsAuthCommand {
            session_handle: Handle::RS_PW,
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession(0),
            hmac: self.auth,
        }
    }
    fn validate_auth_response(&self, auth: &TpmsAuthResponse) -> Result<(), AuthError> {
        // Password response auth should have empty nonce/hmac and ContinueSession attribute.
        if !auth.nonce.as_slice().is_empty()
            || auth.session_attributes.0 != 0x1
            || !auth.hmac.as_slice().is_empty()
        {
            Err(AuthError::InvalidResponse)
        } else {
            Ok(())
        }
    }
}
