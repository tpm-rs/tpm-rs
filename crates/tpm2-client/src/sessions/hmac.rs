use crate::CryptoBackend;
use crate::sessions::{AuthError, CommandData, ResponseData, Session};
use core::marker::PhantomData;
use tpm2::crypto::{Crypto, CryptoError, hmac, kdfa};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmaSession, TpmiAlgHash, TpmsAuthCommand,
    TpmsAuthResponse,
};

pub(super) const MAX_DIGEST: usize = TpmiAlgHash::MAX_DIGEST_BYTES;

/// Fixed-capacity storage for nonces, keys, and HMACs, which are all at most
/// [`TpmiAlgHash::MAX_DIGEST_BYTES`] long.
///
/// This is intentionally not `Copy`, so that copies are explicit (via
/// `clone()`).
//
// ATTN/NOTE: This may hold secrets (session keys, authValues, and passwords), which
// aren't overwritten when no longer needed. Neither are the other copies of
// them, e.g. in the temporary HMAC and KDFa key buffers below, or in the
// marshaled command in `run_command_with_sessions()`. Whether this matters
// depends on the environment (e.g. a discrete TPM has no other software that
// could read them, unlike a userspace process), so this needs a consistent
// approach (e.g. `zeroize` on drop) across the call stack, rather than
// piecemeal overwriting.
#[derive(Clone)]
pub(super) struct Buf {
    pub(super) bytes: [u8; MAX_DIGEST],
    pub(super) len: usize,
}

impl Buf {
    pub(super) const EMPTY: Self = Buf {
        bytes: [0; MAX_DIGEST],
        len: 0,
    };

    /// Callers must ensure `src.len() <= MAX_DIGEST` (e.g. by taking a
    /// [`Tpm2bDigest`] or a digest-sized slice).
    pub(super) fn new(src: &[u8]) -> Self {
        let mut buf = Self::EMPTY;
        buf.bytes[..src.len()].copy_from_slice(src);
        buf.len = src.len();
        buf
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Removes trailing zero octets, as required for an authValue used in an
/// HMAC key (TPM 2.0 Part 1, Section 19.6.5).
fn trim_trailing_zeros(s: &[u8]) -> &[u8] {
    let len = s.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &s[..len]
}

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
/// The session uses the cryptography backend `C`, which defaults to
/// [`CryptoBackend`].
///
/// This is intentionally neither `Clone` nor `Copy`: only the copy used for a
/// command would see the new `nonceTPM`, so the others would desynchronize
/// from the TPM.
//
// The `pub(super)` fields and methods are visible throughout `sessions` (but
// not outside it), for [`PolicySession`](super::PolicySession), which wraps
// this and chooses how the authValue is used.
pub struct HmacSession<C = CryptoBackend> {
    crypto: PhantomData<C>,
    pub(super) session_handle: Handle,
    pub(super) auth_hash: TpmiAlgHash,
    pub(super) session_key: Buf,
    pub(super) nonce_caller: Buf,
    pub(super) nonce_tpm: Buf,
    /// Backing storage for the HMAC in the last [`TpmsAuthCommand`], which
    /// borrows it.
    hmac: Buf,
    pub(super) session_attributes: TpmaSession,
    pub(super) auth_value: Buf,
}

impl<C: Crypto> HmacSession<C> {
    /// Creates a new unbound, unsalted HMAC session (i.e. `bind` and `tpmKey`
    /// were both `TPM_RH_NULL` in `TPM2_StartAuthSession`), which has an
    /// empty session key.
    ///
    /// `nonce_caller` is the nonce sent in `TPM2_StartAuthSession`, and
    /// `nonce_tpm` is the nonce returned in its response.
    ///
    /// The `continueSession` attribute is enabled by default; see
    /// [`HmacSession::clear_session_attributes`].
    //
    // TODO: Unless an authValue is set, the HMAC key of such a session is
    // empty, so the HMACs are empty and the session provides no integrity
    // (Part 1, Section 16.6.16). This is allowed and should stay supported
    // (this code is meant to become the TPM itself), but document it in a
    // `# Security` section, and consider requiring callers to opt into it.
    pub fn new(
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
    ) -> Self {
        HmacSession {
            crypto: PhantomData,
            session_handle,
            auth_hash,
            session_key: Buf::EMPTY,
            nonce_caller: Buf::new(nonce_caller.as_slice()),
            nonce_tpm: Buf::new(nonce_tpm.as_slice()),
            hmac: Buf::EMPTY,
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
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
        bind_auth: Tpm2bAuth<'_>,
        salt: Tpm2bDigest<'_>,
    ) -> Result<Self, CryptoError> {
        let mut session = Self::new(session_handle, auth_hash, nonce_caller, nonce_tpm);

        let bind_auth = trim_trailing_zeros(bind_auth.as_slice());
        let salt = salt.as_slice();
        if bind_auth.is_empty() && salt.is_empty() {
            return Ok(session);
        }

        let mut secret = [0u8; 2 * MAX_DIGEST];
        secret[..bind_auth.len()].copy_from_slice(bind_auth);
        secret[bind_auth.len()..][..salt.len()].copy_from_slice(salt);
        let secret = &secret[..bind_auth.len() + salt.len()];

        let mut session_key = [0u8; MAX_DIGEST];
        let session_key = &mut session_key[..auth_hash.digest_size()];
        kdfa::<C>(
            auth_hash,
            secret,
            c"ATH",
            (
                session.nonce_tpm.as_slice(),
                session.nonce_caller.as_slice(),
            ),
            session_key,
        )?;
        session.session_key = Buf::new(session_key);
        Ok(session)
    }

    /// Computes `HMAC(sessionKey || auth_value, parts[0] || parts[1] || ...)`.
    fn compute_hmac(&self, auth_value: &[u8], parts: &[&[u8]]) -> Result<Buf, CryptoError> {
        let session_key = self.session_key.as_slice();
        let mut key = [0u8; 2 * MAX_DIGEST];
        key[..session_key.len()].copy_from_slice(session_key);
        key[session_key.len()..][..auth_value.len()].copy_from_slice(auth_value);
        let key = &key[..session_key.len() + auth_value.len()];

        let mut out = [0u8; MAX_DIGEST];
        Ok(Buf::new(
            hmac::<C>(self.auth_hash, key, parts, &mut out)?.digest(),
        ))
    }

    /// Whether the HMAC key (`sessionKey || auth_value`) is empty, in which
    /// case the HMACs are empty too (Part 1, Section 16.6.16).
    fn hmac_key_is_empty(&self, auth_value: &[u8]) -> bool {
        self.session_key.len == 0 && auth_value.is_empty()
    }

    /// Generates a fresh `nonceCaller`, the same length as the current one.
    pub(super) fn fresh_nonce_caller(&self) -> Result<Buf, AuthError> {
        let mut nonce = Buf::EMPTY;
        nonce.len = self.nonce_caller.len;
        C::rand_bytes(&mut nonce.bytes[..nonce.len])?;
        Ok(nonce)
    }

    /// Computes the command HMAC for the new `nonce_caller`, with
    /// `auth_value` (trailing zeros already removed) as part of the HMAC key.
    ///
    /// This doesn't change the session; see [`Self::finish_auth_command`].
    pub(super) fn command_hmac(
        &self,
        cmd: &CommandData,
        nonce_caller: &[u8],
        auth_value: &[u8],
    ) -> Result<Buf, AuthError> {
        if self.hmac_key_is_empty(auth_value) {
            return Ok(Buf::EMPTY);
        }

        let mut cp_buf = [0u8; MAX_DIGEST];
        let cp_hash = cmd.cp_hash::<C>(self.auth_hash, &mut cp_buf)?;
        Ok(self.compute_hmac(
            auth_value,
            &[
                cp_hash.digest(),
                nonce_caller,
                self.nonce_tpm.as_slice(),
                &[self.session_attributes.0],
            ],
        )?)
    }

    /// Verifies the response HMAC, with `auth_value` (trailing zeros already
    /// removed) as part of the HMAC key.
    ///
    /// This doesn't change the session: on success, the caller stores the
    /// new `nonceTPM`.
    pub(super) fn check_response_hmac(
        &self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
        auth_value: &[u8],
    ) -> Result<(), AuthError> {
        let key_is_empty = self.hmac_key_is_empty(auth_value);
        let expected_hmac_len = if key_is_empty {
            0
        } else {
            self.auth_hash.digest_size()
        };
        if auth.nonce.as_slice().len() != self.nonce_tpm.len
            || auth.hmac.as_slice().len() != expected_hmac_len
        {
            return Err(AuthError::InvalidResponse);
        }
        if key_is_empty {
            return Ok(());
        }

        let mut rp_buf = [0u8; MAX_DIGEST];
        let rp_hash = rsp.rp_hash::<C>(self.auth_hash, &mut rp_buf)?;
        let expected = self.compute_hmac(
            auth_value,
            &[
                rp_hash.digest(),
                auth.nonce.as_slice(),
                self.nonce_caller.as_slice(),
                &[auth.session_attributes.0],
            ],
        )?;

        // Both are digest-sized (checked above), so comparing the
        // zero-padded buffers is equivalent.
        let received = Buf::new(auth.hmac.as_slice());
        if !C::ct_eq(&expected.bytes, &received.bytes) {
            return Err(AuthError::InvalidResponse);
        }
        Ok(())
    }
}

impl<C> HmacSession<C> {
    /// Stores the `nonce_caller` and `hmac` sent with a command, and returns
    /// the command's authorization.
    pub(super) fn finish_auth_command(
        &mut self,
        nonce_caller: Buf,
        hmac: Buf,
    ) -> TpmsAuthCommand<'_> {
        self.nonce_caller = nonce_caller;
        self.hmac = hmac;
        TpmsAuthCommand {
            session_handle: self.session_handle,
            nonce: self.nonce_caller(),
            session_attributes: self.session_attributes,
            hmac: Tpm2bAuth::new(self.hmac.as_slice()).unwrap(),
        }
    }

    /// Sets the authValue of the entity this session authorizes, which is
    /// appended to the session key to form the HMAC key.
    ///
    /// Leave this unset if the entity has an empty authValue, or if the
    /// session is bound to the entity being authorized.
    pub fn set_auth_value(&mut self, auth_value: Tpm2bAuth<'_>) {
        self.auth_value = Buf::new(trim_trailing_zeros(auth_value.as_slice()));
    }

    /// Returns the session attributes sent with this session; by default,
    /// only `continueSession`.
    pub const fn session_attributes(&self) -> TpmaSession {
        self.session_attributes
    }

    /// Sets the given session attributes, leaving the others unchanged.
    ///
    /// E.g. set [`TpmaSession::CONTINUE_SESSION`] (the default) for the
    /// session to remain active after the next command.
    //
    // TODO: Validate these. `decrypt`, `encrypt`, and the audit attributes
    // aren't supported yet (parameters aren't encrypted, and
    // `nonceDecrypt`/`nonceEncrypt` aren't included in the HMAC), but nothing
    // prevents setting them. Once they are, this should check that the
    // change is allowed, and return a `Result`.
    pub fn set_session_attributes(&mut self, attributes: TpmaSession) {
        self.session_attributes.insert(attributes);
    }

    /// Clears the given session attributes, leaving the others unchanged.
    ///
    /// E.g. clear [`TpmaSession::CONTINUE_SESSION`] to have the next command
    /// terminate the session.
    //
    // TODO: Validate these, as for `set_session_attributes()`.
    pub fn clear_session_attributes(&mut self, attributes: TpmaSession) {
        self.session_attributes.remove(attributes);
    }

    /// Returns the session handle this session refers to.
    pub const fn handle(&self) -> Handle {
        self.session_handle
    }

    /// Returns the session's hash algorithm (`authHash`).
    pub const fn auth_hash(&self) -> TpmiAlgHash {
        self.auth_hash
    }

    /// Returns the most recent TPM nonce.
    pub fn nonce_tpm(&self) -> Tpm2bNonce<'_> {
        Tpm2bNonce::new(self.nonce_tpm.as_slice()).unwrap()
    }

    /// Returns the most recent caller nonce.
    pub fn nonce_caller(&self) -> Tpm2bNonce<'_> {
        Tpm2bNonce::new(self.nonce_caller.as_slice()).unwrap()
    }

    /// Updates the length of nonceCaller.
    // FIXME/ATTN: This is only meant for testing (e.g. that the TPM tolerates
    // nonceCaller changing size, or rejects one longer than nonceTPM), so it
    // should only be compiled with a testing feature. It panics (via a slice
    // bounds check) on the next command if `len` exceeds `MAX_DIGEST`.
    pub fn set_new_nonce_caller_length(&mut self, len: usize) {
        self.nonce_caller.len = len;
    }
}

impl<C: Crypto> Session for HmacSession<C> {
    fn auth_command(&mut self, cmd: &CommandData) -> Result<TpmsAuthCommand<'_>, AuthError> {
        let nonce = self.fresh_nonce_caller()?;
        let hmac = self.command_hmac(cmd, nonce.as_slice(), self.auth_value.as_slice())?;
        Ok(self.finish_auth_command(nonce, hmac))
    }

    // TODO: If the response check fails, the session's state can no longer
    // be trusted (the TPM may have rolled `nonceTPM`, or the response may
    // have been tampered with), but the session can still be used, with the
    // old `nonceTPM`. Consider marking it invalid (so that further commands
    // are refused, and the caller must flush it), even though the TPM may
    // still consider it valid. This isn't trivial, as this code is also
    // meant to become TPM firmware, so the same state must work on both
    // sides.
    fn validate_auth_response(
        &mut self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
    ) -> Result<(), AuthError> {
        self.check_response_hmac(rsp, auth, self.auth_value.as_slice())?;
        self.nonce_tpm = Buf::new(auth.nonce.as_slice());
        Ok(())
    }
}
