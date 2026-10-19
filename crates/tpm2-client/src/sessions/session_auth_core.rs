use crate::sessions::{AuthError, CommandData, ResponseData};
use tpm2::crypto::{ConstantTimeEq, CryptoError, Hash, Hmac, HmacStream, Random, Rng, kdfa};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmaSession, TpmiAlgHash, TpmsAuthCommand,
    TpmsAuthResponse,
};

pub(super) const MAX_DIGEST: usize = TpmiAlgHash::MAX_DIGEST_BYTES;

/// Fixed-capacity storage for nonces, keys, and HMACs, which are all at most
/// [`TpmiAlgHash::MAX_DIGEST_BYTES`] long.
#[derive(Clone, Copy)]
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
pub(super) fn trim_trailing_zeros(s: &[u8]) -> &[u8] {
    let len = s.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &s[..len]
}

/// The state shared by all sessions started with `TPM2_StartAuthSession`
/// (HMAC and policy sessions): the session key, the rolling nonces, and the
/// HMAC computation (TPM 2.0 Part 1, Section 19.6):
///
/// ```text
/// hmacKey  := sessionKey || authValue
/// cmdHMAC  := HMAC(hmacKey, cpHash || nonceCaller || nonceTPM || sessionAttributes)
/// rspHMAC  := HMAC(hmacKey, rpHash || nonceTPM || nonceCaller || sessionAttributes)
/// ```
///
/// Which authValue (if any) is part of the HMAC key depends on the session
/// type, so it is passed in by the caller.
#[derive(Clone)]
pub(super) struct SessionCore<C> {
    pub(super) crypto: C,
    pub(super) session_handle: Handle,
    pub(super) auth_hash: TpmiAlgHash,
    pub(super) session_key: Buf,
    pub(super) nonce_caller: Buf,
    pub(super) nonce_tpm: Buf,
    pub(super) hmac: Buf,
}

impl<C> SessionCore<C> {
    /// Creates the state of an unbound, unsalted session, which has an empty
    /// session key.
    pub(super) fn new(
        crypto: C,
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
    ) -> Self {
        SessionCore {
            crypto,
            session_handle,
            auth_hash,
            session_key: Buf::EMPTY,
            nonce_caller: Buf::new(nonce_caller.as_slice()),
            nonce_tpm: Buf::new(nonce_tpm.as_slice()),
            hmac: Buf::EMPTY,
        }
    }

    pub(super) fn nonce_tpm(&self) -> Tpm2bNonce<'_> {
        Tpm2bNonce::new(self.nonce_tpm.as_slice()).unwrap()
    }

    pub(super) fn nonce_caller(&self) -> Tpm2bNonce<'_> {
        Tpm2bNonce::new(self.nonce_caller.as_slice()).unwrap()
    }
}

impl<C: Hash + Hmac + Random + ConstantTimeEq> SessionCore<C> {
    /// Creates the state of a bound and/or salted session, deriving the
    /// session key (TPM 2.0 Part 1, Section 19.6.8):
    ///
    /// ```text
    /// sessionKey := KDFa(authHash, bindAuth || salt, "ATH", nonceTPM, nonceCaller, bits)
    /// ```
    pub(super) fn new_bound_or_salted(
        crypto: C,
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
        bind_auth: Tpm2bAuth<'_>,
        salt: Tpm2bDigest<'_>,
    ) -> Result<Self, CryptoError> {
        let mut core = Self::new(crypto, session_handle, auth_hash, nonce_caller, nonce_tpm);

        let bind_auth = trim_trailing_zeros(bind_auth.as_slice());
        let salt = salt.as_slice();
        if bind_auth.is_empty() && salt.is_empty() {
            return Ok(core);
        }

        let mut secret = [0u8; 2 * MAX_DIGEST];
        secret[..bind_auth.len()].copy_from_slice(bind_auth);
        secret[bind_auth.len()..][..salt.len()].copy_from_slice(salt);
        let secret = &secret[..bind_auth.len() + salt.len()];

        let mut session_key = [0u8; MAX_DIGEST];
        let session_key = &mut session_key[..auth_hash.digest_size()];
        kdfa(
            &core.crypto,
            auth_hash,
            secret,
            c"ATH",
            core.nonce_tpm.as_slice(),
            core.nonce_caller.as_slice(),
            session_key,
        )?;
        core.session_key = Buf::new(session_key);
        Ok(core)
    }

    /// Computes `HMAC(sessionKey || auth_value, parts[0] || parts[1] || ...)`.
    fn compute_hmac(&self, auth_value: &[u8], parts: &[&[u8]]) -> Result<Buf, CryptoError> {
        let session_key = self.session_key.as_slice();
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

    /// Generates a fresh `nonceCaller` and computes the command HMAC, with
    /// `auth_value` (trailing zeros already removed) as part of the HMAC key.
    pub(super) fn auth_command(
        &mut self,
        cmd: &CommandData,
        session_attributes: TpmaSession,
        auth_value: &[u8],
    ) -> Result<TpmsAuthCommand<'_>, AuthError> {
        let mut nonce = [0u8; MAX_DIGEST];
        let nonce = &mut nonce[..self.nonce_caller.len];
        self.crypto.rng()?.fill_bytes(nonce)?;

        // Part 1: Architecture - Section 16.6.16 declares that in this case, this can be empty.
        let hmac = if self.session_key.len == 0 && auth_value.is_empty() {
            Buf::EMPTY
        } else {
            let mut cp_buf = [0u8; MAX_DIGEST];
            let cp_hash = cmd.cp_hash(&self.crypto, self.auth_hash, &mut cp_buf)?;

            self.compute_hmac(
                auth_value,
                &[
                    cp_hash.digest(),
                    nonce,
                    self.nonce_tpm.as_slice(),
                    &[session_attributes.0],
                ],
            )?
        };

        self.nonce_caller = Buf::new(nonce);
        self.hmac = hmac;

        Ok(TpmsAuthCommand {
            session_handle: self.session_handle,
            nonce: self.nonce_caller(),
            session_attributes,
            hmac: Tpm2bAuth::new(self.hmac.as_slice()).unwrap(),
        })
    }

    /// Verifies the response HMAC, with `auth_value` (trailing zeros already
    /// removed) as part of the HMAC key, and stores the new `nonceTPM`.
    pub(super) fn validate_auth_response(
        &mut self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
        auth_value: &[u8],
    ) -> Result<(), AuthError> {
        let digest_size = self.auth_hash.digest_size();
        let expected_hmac_len = if self.session_key.len == 0 && auth_value.is_empty() {
            0
        } else {
            digest_size
        };

        if auth.nonce.as_slice().len() != digest_size || auth.hmac.as_slice().len() != expected_hmac_len {
            return Err(AuthError::InvalidResponse);
        }

        let nonce_tpm = auth.nonce.as_slice();

        // Part 1: Architecture - Section 16.6.16 declares that in this case, this can be empty.
        let expected = if self.session_key.len == 0 && auth_value.is_empty() {
            Buf::EMPTY
        } else {
            let mut rp_buf = [0u8; MAX_DIGEST];
            let rp_hash = rsp.rp_hash(&self.crypto, self.auth_hash, &mut rp_buf)?;

            self.compute_hmac(
                auth_value,
                &[
                    rp_hash.digest(),
                    nonce_tpm,
                    self.nonce_caller.as_slice(),
                    &[auth.session_attributes.0],
                ],
            )?
        };

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
