use crate::sessions::session_auth_core::{Buf, MAX_DIGEST, SessionCore, trim_trailing_zeros};
use crate::sessions::{AuthError, CommandData, ResponseData, Session};
use core::fmt;
use tpm2::crypto::{ConstantTimeEq, CryptoError, Hash, HashStream, Hmac, Random};
use tpm2::{
    Handle, Marshal, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bOperand, TpmCap, TpmCc,
    TpmEo, TpmaLocality, TpmaSession, TpmiAlgHash, TpmlPcrSelection, TpmsAuthCommand,
    TpmsAuthResponse, TpmtTkAuth,
};

/// A client-side computation of a policyDigest (TPM 2.0 Part 1, Section 19.7;
/// Part 3, Section 23).
///
/// Each `policy_*` method applies the same update to the digest as the
/// matching `TPM2_Policy*` command does to a policy session's policyDigest.
/// This can be used to compute the `authPolicy` of an entity without a TPM,
/// or to compute the digest a policy session is expected to have (see
/// [`PolicySession::policy`]).
///
/// The methods take the values that go into the digest, which aren't always
/// the command's parameters: e.g. [`PolicyDigest::policy_secret`] takes the
/// Name of `authHandle`, and [`PolicyDigest::policy_pcr`] needs the actual
/// PCR digest, even if the command is sent with an empty `pcrDigest`.
///
/// The TPM also checks some commands' arguments against its state (e.g.
/// `TPM2_PolicyOR` checks that the current digest is in `pHashList`). These
/// checks are not replicated here.
#[derive(Clone)]
pub struct PolicyDigest<C> {
    crypto: C,
    alg: TpmiAlgHash,
    digest: Buf,
}

impl<C> PolicyDigest<C> {
    /// Creates a new policyDigest for the hash algorithm `alg`, which is
    /// initially all zeros, like that of a new policy session.
    pub fn new(crypto: C, alg: TpmiAlgHash) -> Self {
        let mut digest = Buf::EMPTY;
        digest.len = alg.digest_size();
        PolicyDigest {
            crypto,
            alg,
            digest,
        }
    }

    /// Returns the hash algorithm of this policyDigest.
    pub const fn alg(&self) -> TpmiAlgHash {
        self.alg
    }

    /// Returns the current policyDigest.
    pub fn digest(&self) -> Tpm2bDigest<'_> {
        Tpm2bDigest::new(self.digest.as_slice()).unwrap()
    }

    /// Resets the policyDigest to all zeros, as `TPM2_PolicyRestart` does.
    pub fn reset(&mut self) {
        self.digest.bytes = [0; MAX_DIGEST];
    }
}

impl<C: Hash> PolicyDigest<C> {
    /// Updates the digest:
    ///
    /// ```text
    /// policyDigest := H(policyDigest || parts[0] || parts[1] || ...)
    /// ```
    fn extend(&mut self, parts: &[&[u8]]) -> Result<(), CryptoError> {
        let mut stream = HashStream::new(&self.crypto, self.alg)?;
        stream.update(self.digest.as_slice())?;
        for part in parts {
            stream.update(part)?;
        }
        let mut out = [0u8; MAX_DIGEST];
        self.digest = Buf::new(stream.finalize(&mut out)?.digest());
        Ok(())
    }

    /// Computes `H(parts[0] || parts[1] || ...)`, e.g. for an `args` hash.
    fn hash(&self, parts: &[&[u8]]) -> Result<Buf, CryptoError> {
        let mut stream = HashStream::new(&self.crypto, self.alg)?;
        for part in parts {
            stream.update(part)?;
        }
        let mut out = [0u8; MAX_DIGEST];
        Ok(Buf::new(stream.finalize(&mut out)?.digest()))
    }

    /// The update shared by `TPM2_PolicySigned`, `TPM2_PolicySecret`,
    /// `TPM2_PolicyTicket` and `TPM2_PolicyAuthorize` (`PolicyUpdate()` in
    /// Part 3, Section 23.2.3):
    ///
    /// ```text
    /// policyDigest := H(policyDigest || code || name)
    /// policyDigest := H(policyDigest || policyRef)
    /// ```
    ///
    /// The second update is done even if `policyRef` is empty.
    fn update_with_ref(
        &mut self,
        code: TpmCc,
        name: &[u8],
        policy_ref: &[u8],
    ) -> Result<(), CryptoError> {
        self.extend(&[&code.code().to_be_bytes(), name])?;
        self.extend(&[policy_ref])
    }

    /// `TPM2_PolicySigned`, where `auth_object_name` is the Name of
    /// `authObject`.
    pub fn policy_signed(
        &mut self,
        auth_object_name: Tpm2bName<'_>,
        policy_ref: Tpm2bNonce<'_>,
    ) -> Result<(), CryptoError> {
        self.update_with_ref(
            TpmCc::PolicySigned,
            auth_object_name.as_slice(),
            policy_ref.as_slice(),
        )
    }

    /// `TPM2_PolicySecret`, where `auth_name` is the Name of `authHandle`.
    pub fn policy_secret(
        &mut self,
        auth_name: Tpm2bName<'_>,
        policy_ref: Tpm2bNonce<'_>,
    ) -> Result<(), CryptoError> {
        self.update_with_ref(
            TpmCc::PolicySecret,
            auth_name.as_slice(),
            policy_ref.as_slice(),
        )
    }

    /// `TPM2_PolicyTicket`, which has the same effect as the
    /// `TPM2_PolicySigned` or `TPM2_PolicySecret` that produced `ticket`.
    pub fn policy_ticket(
        &mut self,
        ticket: &TpmtTkAuth<'_>,
        auth_name: Tpm2bName<'_>,
        policy_ref: Tpm2bNonce<'_>,
    ) -> Result<(), CryptoError> {
        let code = match ticket {
            TpmtTkAuth::Signed(..) => TpmCc::PolicySigned,
            TpmtTkAuth::Secret(..) => TpmCc::PolicySecret,
        };
        self.update_with_ref(code, auth_name.as_slice(), policy_ref.as_slice())
    }

    /// `TPM2_PolicyOR`:
    ///
    /// ```text
    /// policyDigest := H(0...0 || TPM_CC_PolicyOR || digests[0] || digests[1] || ...)
    /// ```
    pub fn policy_or(&mut self, digests: &[Tpm2bDigest<'_>]) -> Result<(), CryptoError> {
        self.reset();
        let mut stream = HashStream::new(&self.crypto, self.alg)?;
        stream.update(self.digest.as_slice())?;
        stream.update(&TpmCc::PolicyOR.code().to_be_bytes())?;
        for digest in digests {
            stream.update(digest.as_slice())?;
        }
        let mut out = [0u8; MAX_DIGEST];
        self.digest = Buf::new(stream.finalize(&mut out)?.digest());
        Ok(())
    }

    /// `TPM2_PolicyPCR`, where `pcr_digest` is the digest of the selected
    /// PCR values (`H(PCR[i] || PCR[j] || ...)`, using this policy's hash
    /// algorithm).
    pub fn policy_pcr(
        &mut self,
        pcr_digest: Tpm2bDigest<'_>,
        pcrs: &TpmlPcrSelection,
    ) -> Result<(), CryptoError> {
        let mut pcrs_buf = [0u8; TpmlPcrSelection::MAX_SIZE];
        let pcrs_size = pcrs.marshal(&mut pcrs_buf);
        self.extend(&[
            &TpmCc::PolicyPCR.code().to_be_bytes(),
            &pcrs_buf[..pcrs_size],
            pcr_digest.as_slice(),
        ])
    }

    /// `TPM2_PolicyLocality`.
    pub fn policy_locality(&mut self, locality: TpmaLocality) -> Result<(), CryptoError> {
        self.extend(&[&TpmCc::PolicyLocality.code().to_be_bytes(), &[locality.0]])
    }

    /// `TPM2_PolicyNV`, where `nv_index_name` is the Name of `nvIndex`:
    ///
    /// ```text
    /// args         := H(operandB || offset || operation)
    /// policyDigest := H(policyDigest || TPM_CC_PolicyNV || args || nvIndexName)
    /// ```
    pub fn policy_nv(
        &mut self,
        operand_b: Tpm2bOperand<'_>,
        offset: u16,
        operation: TpmEo,
        nv_index_name: Tpm2bName<'_>,
    ) -> Result<(), CryptoError> {
        let args = self.hash(&[
            operand_b.as_slice(),
            &offset.to_be_bytes(),
            &(operation as u16).to_be_bytes(),
        ])?;
        self.extend(&[
            &TpmCc::PolicyNV.code().to_be_bytes(),
            args.as_slice(),
            nv_index_name.as_slice(),
        ])
    }

    /// `TPM2_PolicyCounterTimer`:
    ///
    /// ```text
    /// args         := H(operandB || offset || operation)
    /// policyDigest := H(policyDigest || TPM_CC_PolicyCounterTimer || args)
    /// ```
    pub fn policy_counter_timer(
        &mut self,
        operand_b: Tpm2bOperand<'_>,
        offset: u16,
        operation: TpmEo,
    ) -> Result<(), CryptoError> {
        let args = self.hash(&[
            operand_b.as_slice(),
            &offset.to_be_bytes(),
            &(operation as u16).to_be_bytes(),
        ])?;
        self.extend(&[
            &TpmCc::PolicyCounterTimer.code().to_be_bytes(),
            args.as_slice(),
        ])
    }

    /// `TPM2_PolicyCommandCode`.
    pub fn policy_command_code(&mut self, code: TpmCc) -> Result<(), CryptoError> {
        self.extend(&[
            &TpmCc::PolicyCommandCode.code().to_be_bytes(),
            &code.code().to_be_bytes(),
        ])
    }

    /// `TPM2_PolicyPhysicalPresence`.
    pub fn policy_physical_presence(&mut self) -> Result<(), CryptoError> {
        self.extend(&[&TpmCc::PolicyPhysicalPresence.code().to_be_bytes()])
    }

    /// `TPM2_PolicyCpHash`. See [`CommandData::cp_hash`] to compute
    /// `cp_hash_a`.
    pub fn policy_cp_hash(&mut self, cp_hash_a: Tpm2bDigest<'_>) -> Result<(), CryptoError> {
        self.extend(&[
            &TpmCc::PolicyCpHash.code().to_be_bytes(),
            cp_hash_a.as_slice(),
        ])
    }

    /// `TPM2_PolicyNameHash`.
    pub fn policy_name_hash(&mut self, name_hash: Tpm2bDigest<'_>) -> Result<(), CryptoError> {
        self.extend(&[
            &TpmCc::PolicyNameHash.code().to_be_bytes(),
            name_hash.as_slice(),
        ])
    }

    /// `TPM2_PolicyDuplicationSelect`. `object_name` is only included in the
    /// digest if `include_object` is set.
    pub fn policy_duplication_select(
        &mut self,
        object_name: Tpm2bName<'_>,
        new_parent_name: Tpm2bName<'_>,
        include_object: bool,
    ) -> Result<(), CryptoError> {
        let object_name: &[u8] = if include_object {
            object_name.as_slice()
        } else {
            &[]
        };
        self.extend(&[
            &TpmCc::PolicyDuplicationSelect.code().to_be_bytes(),
            object_name,
            new_parent_name.as_slice(),
            &[u8::from(include_object)],
        ])
    }

    /// `TPM2_PolicyAuthorize`, which resets the digest before updating it
    /// with the Name of the signing key.
    pub fn policy_authorize(
        &mut self,
        key_sign: Tpm2bName<'_>,
        policy_ref: Tpm2bNonce<'_>,
    ) -> Result<(), CryptoError> {
        self.reset();
        self.update_with_ref(
            TpmCc::PolicyAuthorize,
            key_sign.as_slice(),
            policy_ref.as_slice(),
        )
    }

    /// `TPM2_PolicyAuthValue`. On a [`PolicySession`], use
    /// [`PolicySession::policy_auth_value`] instead, which also updates how
    /// the session authorizes.
    pub fn policy_auth_value(&mut self) -> Result<(), CryptoError> {
        self.extend(&[&TpmCc::PolicyAuthValue.code().to_be_bytes()])
    }

    /// `TPM2_PolicyPassword`. On a [`PolicySession`], use
    /// [`PolicySession::policy_password`] instead, which also updates how the
    /// session authorizes.
    ///
    /// Note that this results in the same digest as `TPM2_PolicyAuthValue`
    /// (i.e. it uses `TPM_CC_PolicyAuthValue`).
    pub fn policy_password(&mut self) -> Result<(), CryptoError> {
        self.extend(&[&TpmCc::PolicyAuthValue.code().to_be_bytes()])
    }

    /// `TPM2_PolicyNvWritten`.
    pub fn policy_nv_written(&mut self, written_set: bool) -> Result<(), CryptoError> {
        self.extend(&[
            &TpmCc::PolicyNvWritten.code().to_be_bytes(),
            &[u8::from(written_set)],
        ])
    }

    /// `TPM2_PolicyTemplate`.
    pub fn policy_template(&mut self, template_hash: Tpm2bDigest<'_>) -> Result<(), CryptoError> {
        self.extend(&[
            &TpmCc::PolicyTemplate.code().to_be_bytes(),
            template_hash.as_slice(),
        ])
    }

    /// `TPM2_PolicyAuthorizeNV`, where `nv_index_name` is the Name of
    /// `nvIndex`. This resets the digest before updating it.
    pub fn policy_authorize_nv(&mut self, nv_index_name: Tpm2bName<'_>) -> Result<(), CryptoError> {
        self.reset();
        self.extend(&[
            &TpmCc::PolicyAuthorizeNV.code().to_be_bytes(),
            nv_index_name.as_slice(),
        ])
    }

    /// `TPM2_PolicyCapability`:
    ///
    /// ```text
    /// args         := H(operandB || offset || operation || capability || property)
    /// policyDigest := H(policyDigest || TPM_CC_PolicyCapability || args)
    /// ```
    pub fn policy_capability(
        &mut self,
        operand_b: Tpm2bOperand<'_>,
        offset: u16,
        operation: TpmEo,
        capability: TpmCap,
        property: u32,
    ) -> Result<(), CryptoError> {
        let args = self.hash(&[
            operand_b.as_slice(),
            &offset.to_be_bytes(),
            &(operation as u16).to_be_bytes(),
            &(capability as u32).to_be_bytes(),
            &property.to_be_bytes(),
        ])?;
        self.extend(&[
            &TpmCc::PolicyCapability.code().to_be_bytes(),
            args.as_slice(),
        ])
    }

    /// `TPM2_PolicyParameters`.
    pub fn policy_parameters(&mut self, p_hash: Tpm2bDigest<'_>) -> Result<(), CryptoError> {
        self.extend(&[
            &TpmCc::PolicyParameters.code().to_be_bytes(),
            p_hash.as_slice(),
        ])
    }
}

impl<C> fmt::Debug for PolicyDigest<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyDigest")
            .field("alg", &self.alg)
            .field("digest", &self.digest.as_slice())
            .finish_non_exhaustive()
    }
}

/// How a policy session authorizes, which depends on whether
/// `TPM2_PolicyAuthValue` or `TPM2_PolicyPassword` was executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyAuth {
    /// Neither: the HMAC key is only the session key, so the policy alone
    /// authorizes.
    Policy,
    /// `TPM2_PolicyAuthValue`: the HMAC key includes the entity's authValue.
    AuthValue,
    /// `TPM2_PolicyPassword`: the authValue is sent in place of the HMAC.
    Password,
}

/// A live policy session, created with `TPM2_StartAuthSession` (with
/// `sessionType` `TPM_SE_POLICY`).
///
/// The `TPM2_Policy*` commands take the session as a handle (and are sent
/// without sessions), so the session isn't involved in sending them. Instead,
/// after each one succeeds, call the matching `policy_*` method on
/// [`PolicySession::policy_mut`], which tracks the policyDigest the session is
/// expected to have. The exceptions are `TPM2_PolicyAuthValue`,
/// `TPM2_PolicyPassword`, and `TPM2_PolicyRestart`, which also change how the
/// session authorizes: call [`PolicySession::policy_auth_value`],
/// [`PolicySession::policy_password`], and [`PolicySession::policy_restart`]
/// on the session instead.
///
/// When used to authorize a command, the TPM checks that the session's
/// policyDigest matches the entity's `authPolicy`, and the session computes
/// the command HMAC (TPM 2.0 Part 1, Section 19.6) as follows:
///
/// - By default, like an [`HmacSession`](super::HmacSession) whose HMAC key
///   is only the session key. For an unbound, unsalted session, that is
///   empty, so the HMACs are empty.
/// - After `TPM2_PolicyAuthValue`, like an
///   [`HmacSession`](super::HmacSession), where the HMAC key includes the
///   entity's authValue.
/// - After `TPM2_PolicyPassword`, the authValue is sent in place of the HMAC
///   (like a [`PasswordSession`](super::PasswordSession)), and the response
///   HMAC is empty.
///
/// Like the TPM, the session resets the policy (the policyDigest, and how the
/// session authorizes) after each successful use.
///
/// `nonceDecrypt`/`nonceEncrypt` are not yet included in the HMAC, so this
/// session must not be combined with separate encrypt/decrypt sessions.
///
/// This is intentionally not `Copy`, as using a stale copy of the session
/// would send a stale `nonceTPM`.
#[derive(Clone)]
pub struct PolicySession<C> {
    core: SessionCore<C>,
    /// Session attributes sent with this session;
    /// defaults to [`TpmaSession::CONTINUE_SESSION`].
    pub session_attributes: TpmaSession,
    auth_value: Buf,
    auth: PolicyAuth,
    policy: PolicyDigest<C>,
}

impl<C: Clone + Hash + Hmac + Random + ConstantTimeEq> PolicySession<C> {
    /// Creates a new unsalted policy session (i.e. `tpmKey` was
    /// `TPM_RH_NULL` in `TPM2_StartAuthSession`), with an empty session key.
    /// If `bind` was not `TPM_RH_NULL`, use
    /// [`PolicySession::new_bound_or_salted`] instead.
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
        PolicySession {
            policy: PolicyDigest::new(crypto.clone(), auth_hash),
            core: SessionCore::new(crypto, session_handle, auth_hash, nonce_caller, nonce_tpm),
            session_attributes: TpmaSession::CONTINUE_SESSION,
            auth_value: Buf::EMPTY,
            auth: PolicyAuth::Policy,
        }
    }

    /// Creates a new bound and/or salted policy session, deriving the session
    /// key as for an HMAC session (see
    /// [`HmacSession::new_bound_or_salted`](super::HmacSession::new_bound_or_salted)).
    ///
    /// Unlike for an HMAC session, binding only affects the session key: the
    /// authValue of the entity being authorized is only included in the HMAC
    /// key after `TPM2_PolicyAuthValue`, whether or not it is the bound
    /// entity.
    pub fn new_bound_or_salted(
        crypto: C,
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
        bind_auth: Tpm2bAuth<'_>,
        salt: Tpm2bDigest<'_>,
    ) -> Result<Self, CryptoError> {
        Ok(PolicySession {
            policy: PolicyDigest::new(crypto.clone(), auth_hash),
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
            auth: PolicyAuth::Policy,
        })
    }

    /// Records that `TPM2_PolicyAuthValue` was executed on this session: the
    /// HMAC key now includes `auth_value`, the authValue of the entity this
    /// session will authorize (see [`PolicySession::set_auth_value`]).
    pub fn policy_auth_value(&mut self, auth_value: Tpm2bAuth<'_>) -> Result<(), CryptoError> {
        self.policy.policy_auth_value()?;
        self.auth = PolicyAuth::AuthValue;
        self.set_auth_value(auth_value);
        Ok(())
    }

    /// Records that `TPM2_PolicyPassword` was executed on this session:
    /// `auth_value`, the authValue of the entity this session will authorize
    /// (see [`PolicySession::set_auth_value`]), is now sent in place of the
    /// HMAC.
    pub fn policy_password(&mut self, auth_value: Tpm2bAuth<'_>) -> Result<(), CryptoError> {
        self.policy.policy_password()?;
        self.auth = PolicyAuth::Password;
        self.set_auth_value(auth_value);
        Ok(())
    }
}

impl<C> PolicySession<C> {
    /// Sets the authValue of the entity this session authorizes.
    ///
    /// This is only used after `TPM2_PolicyAuthValue` or
    /// `TPM2_PolicyPassword` (see [`PolicySession::policy_auth_value`] and
    /// [`PolicySession::policy_password`], which set it too). Otherwise, the
    /// TPM ignores the entity's authValue, and so does this session.
    pub fn set_auth_value(&mut self, auth_value: Tpm2bAuth<'_>) {
        self.auth_value = Buf::new(trim_trailing_zeros(auth_value.as_slice()));
    }

    /// Records that the TPM reset the session's policy: the policyDigest is
    /// reset, and the session authorizes with the policy alone again.
    ///
    /// Call this after `TPM2_PolicyRestart`. This is called automatically
    /// after the session is successfully used, as the TPM then resets the
    /// policy too.
    pub fn policy_restart(&mut self) {
        self.policy.reset();
        self.auth = PolicyAuth::Policy;
    }

    /// Returns the policyDigest this session is expected to have.
    pub const fn policy(&self) -> &PolicyDigest<C> {
        &self.policy
    }

    /// Returns the policyDigest this session is expected to have, to update
    /// after each `TPM2_Policy*` command (see [`PolicySession`]).
    pub const fn policy_mut(&mut self) -> &mut PolicyDigest<C> {
        &mut self.policy
    }

    /// Returns the session handle this session refers to.
    pub const fn handle(&self) -> Handle {
        self.core.session_handle
    }

    /// Returns the session's hash algorithm (`authHash`).
    pub const fn auth_hash(&self) -> TpmiAlgHash {
        self.core.auth_hash
    }

    /// Returns the most recent TPM nonce, which is needed as a parameter of
    /// e.g. `TPM2_PolicySecret` and `TPM2_PolicySigned`.
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
impl<C> fmt::Debug for PolicySession<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicySession")
            .field("session_handle", &self.core.session_handle)
            .field("auth_hash", &self.core.auth_hash)
            .field("session_attributes", &self.session_attributes)
            .field("auth", &self.auth)
            .field("policy_digest", &self.policy.digest.as_slice())
            .field("nonce_caller", &self.core.nonce_caller.as_slice())
            .field("nonce_tpm", &self.core.nonce_tpm.as_slice())
            .finish_non_exhaustive()
    }
}

impl<C: Hash + Hmac + Random + ConstantTimeEq> Session for PolicySession<C> {
    fn auth_command(&mut self, cmd: &CommandData) -> Result<TpmsAuthCommand<'_>, AuthError> {
        match self.auth {
            PolicyAuth::Policy => self.core.auth_command(cmd, self.session_attributes, &[]),
            PolicyAuth::AuthValue => {
                self.core
                    .auth_command(cmd, self.session_attributes, self.auth_value.as_slice())
            }
            PolicyAuth::Password => self
                .core
                .password_auth_command(self.session_attributes, self.auth_value.as_slice()),
        }
    }

    fn validate_auth_response(
        &mut self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
    ) -> Result<(), AuthError> {
        match self.auth {
            PolicyAuth::Policy => self.core.validate_auth_response(rsp, auth, &[])?,
            PolicyAuth::AuthValue => {
                self.core
                    .validate_auth_response(rsp, auth, self.auth_value.as_slice())?
            }
            PolicyAuth::Password => self.core.validate_password_response(auth)?,
        }
        // After a successful command, the TPM resets the policy (if the
        // session continues; otherwise, the session is gone anyway).
        self.policy_restart();
        Ok(())
    }
}
