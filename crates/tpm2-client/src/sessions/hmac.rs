use crate::sessions::session_auth_core::{Buf, SessionCore, trim_trailing_zeros};
use crate::sessions::{AuthError, CommandData, ResponseData, Session};
use core::fmt;
use tpm2::crypto::{ConstantTimeEq, CryptoError, Hash, Hmac, Random};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmaSession, TpmiAlgHash, TpmsAuthCommand,
    TpmsAuthResponse,
};

/// A live HMAC session, created with `TPM2_StartAuthSession`.
///
/// The session tracks the rolling nonces and computes the command HMAC
/// (TPM 2.0 Part 1, Section 19.6) using the cryptography backend `C`:
///
/// ```text
/// hmacKey  := sessionKey || authValue
/// cmdHMAC  := HMAC(hmacKey, cpHash || nonceCaller || nonceTPM || sessionAttributes)
/// rspHMAC  := HMAC(hmacKey, rpHash || nonceTPM || nonceCaller || sessionAttributes)
/// ```
///
/// See [`CommandData::cp_hash`] and [`ResponseData::rp_hash`] for cpHash and
/// rpHash.
///
/// For each command, [`Session::auth_command`] generates a fresh
/// `nonceCaller` and computes the command HMAC, and
/// [`Session::validate_auth_response`] verifies the response HMAC and stores
/// the new `nonceTPM`, which is needed for the next command's HMAC. So the
/// same session must be reused (via `&mut`) for every command.
///
/// `nonceDecrypt`/`nonceEncrypt` are not yet included in the HMAC, so this
/// session must not be combined with separate encrypt/decrypt sessions.
///
/// This is intentionally not `Copy`, as using a stale copy of the session
/// would send a stale `nonceTPM`.
#[derive(Clone)]
pub struct HmacSession<C> {
    core: SessionCore<C>,
    /// Session attributes sent with this session;
    /// defaults to [`TpmaSession::CONTINUE_SESSION`].
    pub session_attributes: TpmaSession,
    auth_value: Buf,
}

impl<C: Hash + Hmac + Random + ConstantTimeEq> HmacSession<C> {
    /// Creates a new unbound, unsalted HMAC session (i.e. `bind` and `tpmKey`
    /// were both `TPM_RH_NULL` in `TPM2_StartAuthSession`), which has an
    /// empty session key.
    ///
    /// `nonce_caller` is the nonce sent in `TPM2_StartAuthSession`, and
    /// `nonce_tpm` is the nonce returned in its response.
    ///
    /// The `continueSession` attribute is enabled by default; clear it
    /// (e.g. `session.session_attributes.set(TpmaSession::CONTINUE_SESSION, false)`)
    /// to request that the command terminate the session.
    pub fn new(
        crypto: C,
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
    ) -> Self {
        HmacSession {
            core: SessionCore::new(crypto, session_handle, auth_hash, nonce_caller, nonce_tpm),
            session_attributes: TpmaSession::CONTINUE_SESSION,
            auth_value: Buf::EMPTY,
        }
    }

    /// Creates a new bound and/or salted HMAC session, deriving the session
    /// key (TPM 2.0 Part 1, Section 19.6.8):
    ///
    /// ```text
    /// sessionKey := KDFa(authHash, bindAuth || salt, "ATH", nonceTPM, nonceCaller, bits)
    /// ```
    ///
    /// `bind_auth` is the authValue of the `bind` entity, and `salt` is the
    /// decrypted `encryptedSalt`. Either may be empty; if both are, this is
    /// equivalent to [`HmacSession::new`].
    pub fn new_bound_or_salted(
        crypto: C,
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
        bind_auth: Tpm2bAuth<'_>,
        salt: Tpm2bDigest<'_>,
    ) -> Result<Self, CryptoError> {
        Ok(HmacSession {
            core: SessionCore::new_bound_or_salted(
                crypto,
                session_handle,
                auth_hash,
                nonce_caller,
                nonce_tpm,
                bind_auth,
                salt,
            )?,
            session_attributes: TpmaSession::CONTINUE_SESSION,
            auth_value: Buf::EMPTY,
        })
    }

    /// Sets the authValue of the entity this session authorizes, which is
    /// appended to the session key to form the HMAC key.
    ///
    /// Leave this unset if the entity has an empty authValue, or if the
    /// session is bound to the entity being authorized.
    pub fn set_auth_value(&mut self, auth_value: Tpm2bAuth<'_>) {
        self.auth_value = Buf::new(trim_trailing_zeros(auth_value.as_slice()));
    }
}

impl<C> HmacSession<C> {
    /// Returns the session handle this session refers to.
    pub const fn handle(&self) -> Handle {
        self.core.session_handle
    }

    /// Returns the session's hash algorithm (`authHash`).
    pub const fn auth_hash(&self) -> TpmiAlgHash {
        self.core.auth_hash
    }

    /// Returns the most recent TPM nonce.
    pub fn nonce_tpm(&self) -> Tpm2bNonce<'_> {
        self.core.nonce_tpm()
    }

    /// Returns the most recent caller nonce.
    pub fn nonce_caller(&self) -> Tpm2bNonce<'_> {
        self.core.nonce_caller()
    }

    /// Updates the length of nonceCaller.
    pub fn set_new_nonce_caller_length(&mut self, len: usize) {
        self.core.nonce_caller.len = len;
    }
}

// Manual impl, to avoid printing the session key and authValue.
impl<C> fmt::Debug for HmacSession<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSession")
            .field("session_handle", &self.core.session_handle)
            .field("auth_hash", &self.core.auth_hash)
            .field("session_attributes", &self.session_attributes)
            .field("nonce_caller", &self.core.nonce_caller.as_slice())
            .field("nonce_tpm", &self.core.nonce_tpm.as_slice())
            .field("hmac", &self.core.hmac.as_slice())
            .finish_non_exhaustive()
    }
}

impl<C: Hash + Hmac + Random + ConstantTimeEq> Session for HmacSession<C> {
    fn auth_command(&mut self, cmd: &CommandData) -> Result<TpmsAuthCommand<'_>, AuthError> {
        self.core
            .auth_command(cmd, self.session_attributes, self.auth_value.as_slice())
    }

    fn validate_auth_response(
        &mut self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
    ) -> Result<(), AuthError> {
        self.core
            .validate_auth_response(rsp, auth, self.auth_value.as_slice())
    }
}
