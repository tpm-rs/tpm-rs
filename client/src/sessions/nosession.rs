use crate::sessions::Session;
use tpm2_rs_base::{errors::TssResult, TpmsAuthCommand, TpmsAuthResponse};

/// [`NoSession`] is not a standard TPM session and cannot be instantiated,
/// making it unsuitable for use as a session. Its primary purpose is to serve
/// as a placeholder type for the `AuthorizationArea*` traits whenever
/// necessary.
pub struct NoSession {
    #[expect(dead_code, reason = "This prevents having NotSession instances")]
    inaccessible: (),
}

impl Session for NoSession {
    fn validate_auth_response(&self, _: &TpmsAuthResponse) -> TssResult<()> {
        // unreachable macro may interfere with #42. If it does we can just
        // replace it with a loop {}.
        unreachable!()
    }
    fn get_auth_command(&self) -> TpmsAuthCommand {
        unreachable!()
    }
}
