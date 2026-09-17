use crate::sessions::{AuthError, Session};
use tpm2::{TpmsAuthCommand, TpmsAuthResponse};

/// [`NoSession`] is not a standard TPM session and cannot be instantiated,
/// making it unsuitable for use as a session. Its primary purpose is to serve
/// as a placeholder type for the `AuthorizationArea*` traits whenever
/// necessary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoSession {
    inaccessible: (),
}

impl Session for NoSession {
    fn validate_auth_response(&self, _: &TpmsAuthResponse) -> Result<(), AuthError> {
        // unreachable macro may interfere with #42. If it does we can just
        // replace it with a loop {}.
        unreachable!()
    }
    fn auth_command(&self) -> TpmsAuthCommand<'_> {
        unreachable!()
    }
}
