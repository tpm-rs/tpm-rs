use crate::sessions::{AuthError, CommandData, ResponseData, Session};
use core::fmt;
use tpm2::crypto::{ConstantTimeEq, CryptoError, Hash, Hmac, HmacStream, Random, Rng, kdfa};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmaSession, TpmiAlgHash, TpmsAuthCommand,
    TpmsAuthResponse,
};

const MAX_DIGEST: usize = TpmiAlgHash::MAX_DIGEST_BYTES;

/// Fixed-capacity storage for nonces, keys, and HMACs, which are all at most
/// [`TpmiAlgHash::MAX_DIGEST_BYTES`] long.
#[derive(Clone, Copy)]
struct Buf {
    bytes: [u8; MAX_DIGEST],
    len: usize,
}

impl Buf {
    const EMPTY: Self = Buf {
        bytes: [0; MAX_DIGEST],
        len: 0,
    };

    /// Callers must ensure `src.len() <= MAX_DIGEST` (e.g. by taking a
    /// [`Tpm2bDigest`] or a digest-sized slice).
    fn new(src: &[u8]) -> Self {
        let mut buf = Self::EMPTY;
        buf.bytes[..src.len()].copy_from_slice(src);
        buf.len = src.len();
        buf
    }

    fn as_slice(&self) -> &[u8] {
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
/// This is intentionally not `Copy`, as using a stale copy of the session
/// would send a stale `nonceTPM`.
#[derive(Clone)]
pub struct HmacSession<C> {
    crypto: C,
    session_handle: Handle,
    auth_hash: TpmiAlgHash,
    /// Session attributes sent with this session;
    /// defaults to [`TpmaSession::CONTINUE_SESSION`].
    pub session_attributes: TpmaSession,
    session_key: Buf,
    auth_value: Buf,
    nonce_caller: Buf,
    nonce_tpm: Buf,
    hmac: Buf,
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
            crypto,
            session_handle,
            auth_hash,
            session_attributes: TpmaSession::CONTINUE_SESSION,
            session_key: Buf::EMPTY,
            auth_value: Buf::EMPTY,
            nonce_caller: Buf::new(nonce_caller.as_slice()),
            nonce_tpm: Buf::new(nonce_tpm.as_slice()),
            hmac: Buf::EMPTY,
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
        let mut session = Self::new(crypto, session_handle, auth_hash, nonce_caller, nonce_tpm);

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
        kdfa(
            &session.crypto,
            auth_hash,
            secret,
            c"ATH",
            session.nonce_tpm.as_slice(),
            session.nonce_caller.as_slice(),
            session_key,
        )?;
        session.session_key = Buf::new(session_key);
        Ok(session)
    }

    /// Sets the authValue of the entity this session authorizes, which is
    /// appended to the session key to form the HMAC key.
    ///
    /// Leave this unset if the entity has an empty authValue, or if the
    /// session is bound to the entity being authorized.
    pub fn set_auth_value(&mut self, auth_value: Tpm2bAuth<'_>) {
        self.auth_value = Buf::new(trim_trailing_zeros(auth_value.as_slice()));
    }

    /// Computes `HMAC(sessionKey || authValue, parts[0] || parts[1] || ...)`.
    fn compute_hmac(&self, parts: &[&[u8]]) -> Result<Buf, CryptoError> {
        let session_key = self.session_key.as_slice();
        let auth_value = self.auth_value.as_slice();
        let mut key = [0u8; 2 * MAX_DIGEST];
        key[..session_key.len()].copy_from_slice(session_key);
        key[session_key.len()..][..auth_value.len()].copy_from_slice(auth_value);
        let key = &key[..session_key.len() + auth_value.len()];

        let mut stream = HmacStream::new(&self.crypto, self.auth_hash, key)?;
        for part in parts {
            stream.update(part)?;
        }
        let mut out = [0u8; MAX_DIGEST];
        Ok(Buf::new(stream.finalize(&mut out)?.digest()))
    }
}

impl<C> HmacSession<C> {
    /// Returns the session handle this session refers to.
    pub const fn handle(&self) -> Handle {
        self.session_handle
    }

    /// Returns the session's hash algorithm (`authHash`).
    pub const fn auth_hash(&self) -> TpmiAlgHash {
        self.auth_hash
    }

    /// Returns the most recent caller nonce.
    pub fn nonce_caller(&self) -> Tpm2bNonce<'_> {
        Tpm2bNonce::new(self.nonce_caller.as_slice()).unwrap()
    }

    /// Returns the most recent TPM nonce.
    pub fn nonce_tpm(&self) -> Tpm2bNonce<'_> {
        Tpm2bNonce::new(self.nonce_tpm.as_slice()).unwrap()
    }
}

// Manual impl, to avoid printing the session key and authValue.
impl<C> fmt::Debug for HmacSession<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSession")
            .field("session_handle", &self.session_handle)
            .field("auth_hash", &self.auth_hash)
            .field("session_attributes", &self.session_attributes)
            .field("nonce_caller", &self.nonce_caller.as_slice())
            .field("nonce_tpm", &self.nonce_tpm.as_slice())
            .field("hmac", &self.hmac.as_slice())
            .finish_non_exhaustive()
    }
}

impl<C: Hash + Hmac + Random + ConstantTimeEq> Session for HmacSession<C> {
    fn auth_command(&mut self, cmd: &CommandData) -> Result<TpmsAuthCommand<'_>, AuthError> {
        let mut cp_buf = [0u8; MAX_DIGEST];
        let cp_hash = cmd.cp_hash(&self.crypto, self.auth_hash, &mut cp_buf)?;

        let mut nonce = [0u8; MAX_DIGEST];
        let nonce = &mut nonce[..self.auth_hash.digest_size()];
        self.crypto.rng()?.fill_bytes(nonce)?;

        let hmac = self.compute_hmac(&[
            cp_hash.digest(),
            nonce,
            self.nonce_tpm.as_slice(),
            &[self.session_attributes.0],
        ])?;
        self.nonce_caller = Buf::new(nonce);
        self.hmac = hmac;

        Ok(TpmsAuthCommand {
            session_handle: self.session_handle,
            nonce: self.nonce_caller(),
            session_attributes: self.session_attributes,
            hmac: Tpm2bAuth::new(self.hmac.as_slice()).unwrap(),
        })
    }

    fn validate_auth_response(
        &mut self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
    ) -> Result<(), AuthError> {
        let digest_size = self.auth_hash.digest_size();
        if auth.nonce.as_slice().len() != digest_size || auth.hmac.as_slice().len() != digest_size {
            return Err(AuthError::InvalidResponse);
        }

        let mut rp_buf = [0u8; MAX_DIGEST];
        let rp_hash = rsp.rp_hash(&self.crypto, self.auth_hash, &mut rp_buf)?;

        let nonce_tpm = auth.nonce.as_slice();
        let expected = self.compute_hmac(&[
            rp_hash.digest(),
            nonce_tpm,
            self.nonce_caller.as_slice(),
            &[auth.session_attributes.0],
        ])?;

        // Both are digest-sized (checked above), so comparing the
        // zero-padded buffers is equivalent.
        let received = Buf::new(auth.hmac.as_slice());
        if !self
            .crypto
            .constant_time_eq(&expected.bytes, &received.bytes)
        {
            return Err(AuthError::InvalidResponse);
        }

        self.nonce_tpm = Buf::new(nonce_tpm);
        Ok(())
    }
}
