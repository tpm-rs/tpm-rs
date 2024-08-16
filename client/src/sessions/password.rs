use crate::sessions::Session;
use tpm2_rs_base::errors::{TssResult, TssTcsError};
use tpm2_rs_base::{
    Tpm2bAuth, Tpm2bNonce, Tpm2bSimple, TpmaSession, TpmiShAuthSession, TpmsAuthCommand,
    TpmsAuthResponse,
};

/// A password session.
#[derive(Debug, PartialEq, Default)]
pub struct PasswordSession {
    pub auth: Tpm2bAuth,
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
