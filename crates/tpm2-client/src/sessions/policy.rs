use crate::CryptoBackend;
use crate::sessions::hmac::{Buf, MAX_DIGEST};
use crate::sessions::{AuthError, CommandData, HmacSession, ResponseData, Session};
use core::marker::PhantomData;
use tpm2::crypto::{Crypto, CryptoError, HashContext, hash};
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
///
/// The digest is computed using the cryptography backend `C`, which defaults
/// to [`CryptoBackend`].
pub struct PolicyDigest<C = CryptoBackend> {
    crypto: PhantomData<C>,
    alg: TpmiAlgHash,
    digest: Buf,
}

// Manual impl, as the backend `C` itself needn't be `Clone`. Unlike a
// session, a policyDigest has no TPM state, so it can be cloned (e.g. to
// compute the branches of a `TPM2_PolicyOR` from a common prefix).
impl<C> Clone for PolicyDigest<C> {
    fn clone(&self) -> Self {
        PolicyDigest {
            crypto: PhantomData,
            alg: self.alg,
            digest: self.digest.clone(),
        }
    }
}

impl<C> PolicyDigest<C> {
    /// Creates a new policyDigest for the hash algorithm `alg`, which is
    /// initially all zeros, like that of a new policy session.
    pub fn new(alg: TpmiAlgHash) -> Self {
        let mut digest = Buf::EMPTY;
        digest.len = alg.digest_size();
        PolicyDigest {
            crypto: PhantomData,
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

impl<C: Crypto> PolicyDigest<C> {
    /// Updates the digest:
    ///
    /// ```text
    /// policyDigest := H(policyDigest || parts[0] || parts[1] || ...)
    /// ```
    fn extend(&mut self, parts: &[&[u8]]) -> Result<(), CryptoError> {
        let mut stream = HashContext::<C>::new(self.alg)?;
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
        let mut out = [0u8; MAX_DIGEST];
        Ok(Buf::new(hash::<C>(self.alg, parts, &mut out)?.digest()))
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
        let mut stream = HashContext::<C>::new(self.alg)?;
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
/// The session uses the cryptography backend `C`, which defaults to
/// [`CryptoBackend`].
///
/// This is intentionally neither `Clone` nor `Copy`: only the copy used for a
/// command would see the new `nonceTPM`, so the others would desynchronize
/// from the TPM.
pub struct PolicySession<C = CryptoBackend> {
    // Tracks the nonces, session key, session attributes, and authValue.
    core: HmacSession<C>,
    auth: PolicyAuth,
    // TODO: This is only the policyDigest the session is expected to have:
    // it's only correct if the caller updates it exactly when a
    // `TPM2_Policy*` command succeeds, and a mismatch only shows up as a
    // failed authorization later. Consider checking it (e.g. against
    // `TPM2_PolicyGetDigest`), and marking the session invalid on a
    // mismatch, as for a failed response check (see
    // `HmacSession::validate_auth_response()`).
    policy: PolicyDigest<C>,
}

impl<C: Crypto> PolicySession<C> {
    /// Creates a new unsalted policy session (i.e. `tpmKey` was
    /// `TPM_RH_NULL` in `TPM2_StartAuthSession`), with an empty session key.
    /// If `bind` was not `TPM_RH_NULL`, use
    /// [`PolicySession::new_bound_or_salted`] instead.
    ///
    /// `nonce_caller` is the nonce sent in `TPM2_StartAuthSession`, and
    /// `nonce_tpm` is the nonce returned in its response.
    ///
    /// The `continueSession` attribute is enabled by default; see
    /// [`PolicySession::clear_session_attributes`].
    pub fn new(
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
    ) -> Self {
        PolicySession {
            policy: PolicyDigest::new(auth_hash),
            core: HmacSession::new(session_handle, auth_hash, nonce_caller, nonce_tpm),
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
        session_handle: Handle,
        auth_hash: TpmiAlgHash,
        nonce_caller: Tpm2bNonce<'_>,
        nonce_tpm: Tpm2bNonce<'_>,
        bind_auth: Tpm2bAuth<'_>,
        salt: Tpm2bDigest<'_>,
    ) -> Result<Self, CryptoError> {
        Ok(PolicySession {
            policy: PolicyDigest::new(auth_hash),
            core: HmacSession::new_bound_or_salted(
                session_handle,
                auth_hash,
                nonce_caller,
                nonce_tpm,
                bind_auth,
                salt,
            )?,
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
        self.core.set_auth_value(auth_value);
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

    /// Returns the session attributes sent with this session; by default,
    /// only `continueSession`.
    pub const fn session_attributes(&self) -> TpmaSession {
        self.core.session_attributes()
    }

    /// Sets the given session attributes, leaving the others unchanged. See
    /// [`HmacSession::set_session_attributes`].
    pub fn set_session_attributes(&mut self, attributes: TpmaSession) {
        self.core.set_session_attributes(attributes);
    }

    /// Clears the given session attributes, leaving the others unchanged.
    /// See [`HmacSession::clear_session_attributes`].
    pub fn clear_session_attributes(&mut self, attributes: TpmaSession) {
        self.core.clear_session_attributes(attributes);
    }

    /// Returns the session handle this session refers to.
    pub const fn handle(&self) -> Handle {
        self.core.handle()
    }

    /// Returns the session's hash algorithm (`authHash`).
    pub const fn auth_hash(&self) -> TpmiAlgHash {
        self.core.auth_hash()
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
    // FIXME/ATTN: This is only meant for testing (e.g. that the TPM tolerates
    // nonceCaller changing size, or rejects one longer than nonceTPM), so it
    // should only be compiled with a testing feature. It panics (via a slice
    // bounds check) on the next command if `len` exceeds `MAX_DIGEST`.
    pub fn set_new_nonce_caller_length(&mut self, len: usize) {
        self.core.set_new_nonce_caller_length(len);
    }
}

impl<C: Crypto> Session for PolicySession<C> {
    fn auth_command(&mut self, cmd: &CommandData) -> Result<TpmsAuthCommand<'_>, AuthError> {
        let nonce = self.core.fresh_nonce_caller()?;
        if self.auth == PolicyAuth::Password {
            // The authValue is sent in place of the command HMAC.
            let core = &mut self.core;
            core.nonce_caller = nonce;
            Ok(TpmsAuthCommand {
                session_handle: core.session_handle,
                nonce: core.nonce_caller(),
                session_attributes: core.session_attributes,
                hmac: Tpm2bAuth::new(core.auth_value.as_slice()).unwrap(),
            })
        } else {
            let auth_value: &[u8] = if self.auth == PolicyAuth::AuthValue {
                self.core.auth_value.as_slice()
            } else {
                &[]
            };
            let hmac = self.core.command_hmac(cmd, nonce.as_slice(), auth_value)?;
            Ok(self.core.finish_auth_command(nonce, hmac))
        }
    }

    fn validate_auth_response(
        &mut self,
        rsp: &ResponseData,
        auth: &TpmsAuthResponse,
    ) -> Result<(), AuthError> {
        if self.auth == PolicyAuth::Password {
            // The response HMAC is empty.
            if auth.nonce.as_slice().len() != self.core.nonce_tpm.len
                || !auth.hmac.as_slice().is_empty()
            {
                return Err(AuthError::InvalidResponse);
            }
        } else {
            let auth_value: &[u8] = if self.auth == PolicyAuth::AuthValue {
                self.core.auth_value.as_slice()
            } else {
                &[]
            };
            self.core.check_response_hmac(rsp, auth, auth_value)?;
        }
        self.core.nonce_tpm = Buf::new(auth.nonce.as_slice());
        // After a successful command, the TPM resets the policy (if the
        // session continues; otherwise, the session is gone anyway).
        self.policy_restart();
        Ok(())
    }
}
