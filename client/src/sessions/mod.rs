use arrayvec::ArrayVec;
use tpm2_rs_base::errors::{TpmResult, TssTcsError};
use tpm2_rs_base::{
    Tpm2bAuth, Tpm2bNonce, Tpm2bSimple, TpmaSession, TpmiShAuthSession, TpmsAuthCommand,
    TpmsAuthResponse,
};

/// Trait for types representing TPM sessions.
pub trait Session {
    /// Computes the authorization HMAC for this session.
    fn get_auth_command(&self) -> TpmsAuthCommand;
    /// Validates the authorization response for this session.
    fn validate_auth_response(&self, auth: &TpmsAuthResponse) -> TpmResult<()>;
}

/// Container for sessions associated with a TPM command. A command can have up to three sessions.
pub type CmdSessions<'a> = ArrayVec<&'a mut dyn Session, 3>;

/// A password session.
#[derive(Debug, PartialEq, Default)]
pub struct PasswordSession {
    auth: Tpm2bAuth,
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
    fn validate_auth_response(&self, auth: &TpmsAuthResponse) -> TpmResult<()> {
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

#[cfg(test)]
mod tests;
