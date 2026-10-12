use super::crypt_ops::{PaddedEccPoint, ecc_point_multiply, load_ecc_public, load_rsa_private};
use crate::Crypto;
use crate::MAX_ACTIVE_SESSIONS;
use crate::handle_checks::{Tpmi, check};
use crate::handler::{CommandHandler, SessionState};
use crate::owned::{OwnedName, OwnedNonce, OwnedPublicParmsAndId, OwnedSensitiveComposite};
use crate::req_resp::RequestThenResponse;
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use tpm2::TpmCc;
use tpm2::commands::{
    PolicyCommandCode, PolicyGetDigest, PolicyRestart, StartAuthSession, responses,
};
use tpm2::crypto::{Ecc, Mlkem, ModeIv, Rsa, RsaEncryptScheme, SymmetricKey, kdfa, kdfe};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2b, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bKemCiphertext, Tpm2bNonce, TpmEccCurve,
    TpmHt, TpmSe, TpmaObject, TpmaSession, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode,
    TpmiMlkemParms, TpmiRsaKeyBits, TpmsAuthCommand, TpmsAuthResponse, TpmsEccPoint, TpmtSymDef,
    Unmarshal,
};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::StartAuthSession] (`0x176`) command.
    ///
    /// # Description
    /// This command starts an authorization session (either HMAC, Policy, or Trial policy session)
    /// and returns the session handle and a TPM nonce.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 11.1 (TPM2_StartAuthSession).
    ///
    /// # Relationships
    /// - Starts a session that can be used for HMAC authorization, parameter encryption/decryption,
    ///   or policy building via commands like [TpmCc::PolicyPCR](policy_pcr.rs)
    ///   and [TpmCc::PolicySigned](policy_signed.rs).
    /// - Policy sessions can be restarted using [TpmCc::PolicyRestart](session.rs).
    pub fn start_auth_session(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let [tpm_key, bind] = request.try_unmarshal_handles::<StartAuthSession>()?;
        check(tpm_key, Tpmi::DhObjectOrNull, Position::handle(1))?;
        check(bind, Tpmi::DhEntityOrNull, Position::handle(2))?;

        let mut session_responses = [TpmsAuthResponse::default(); 3];
        // Parse authorization sessions if present.
        let num_sessions =
            self.parse_auth_sessions_for_start_session(&mut request, &mut session_responses)?;

        let cmd = match request.try_unmarshal_command::<StartAuthSession>([tpm_key, bind]) {
            Ok(cmd) => cmd,
            Err(e) => {
                let mut slice = request.remaining_slice();
                if Tpm2bNonce::unmarshal(&mut slice).is_ok()
                    && Tpm2bEncryptedSecret::unmarshal(&mut slice).is_ok()
                    && TpmSe::unmarshal(&mut slice).is_ok()
                    && let Some(alg) = slice.first_chunk::<2>()
                    && u16::from_be_bytes(*alg) > 0x0080
                {
                    return Err(TpmRc::VALUE.with(Position::parameter(4)));
                }
                return Err(e);
            }
        };

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate symmetric block cipher mode (if not Null, mode must be CFB)
        if let Some(TpmtSymDef::Obj(sym_obj)) = cmd.symmetric
            && sym_obj.mode != Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb))
        {
            return Err(TpmRc::MODE.with(Position::parameter(4)));
        }

        // Generate nonceTPM
        let auth_hash_digest_size = cmd.auth_hash.digest_size();
        if auth_hash_digest_size == 0 {
            return Err(TpmRc::HASH.with(Position::parameter(5)));
        }

        let nonce_caller_len = cmd.nonce_caller.as_slice().len();
        if !(16..=auth_hash_digest_size).contains(&nonce_caller_len) {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        let mut nonce_tpm_bytes = [0u8; Tpm2bNonce::CAP];
        let nonce_tpm_bytes = nonce_tpm_bytes
            .get_mut(..nonce_caller_len)
            .ok_or(TpmRc::FAILURE)?;
        self.fill_random(nonce_tpm_bytes)
            .map_err(|_| TpmRc::FAILURE)?;
        let nonce_tpm = Tpm2bNonce::new(nonce_tpm_bytes).ok_or(TpmRc::FAILURE)?;

        // Decrypt salt
        let mut decrypted_salt = [0u8; 64];
        let decrypted_salt_len = self.decrypt_session_salt(
            tpm_key,
            cmd.encrypted_salt.as_slice(),
            &nonce_tpm,
            &cmd.nonce_caller,
            &mut decrypted_salt,
        )?;

        // Retrieve auth value of bind entity
        let mut bind_auth = [0u8; 64];
        let bind_auth_len = self.retrieve_bind_auth(bind, &mut bind_auth)?;
        let bind_auth_stripped = crate::util::strip_trailing_zeros(&bind_auth[..bind_auth_len]);

        // Generate unique session handle
        let session_handle = self.generate_session_handle(cmd.session_type)?;

        // Derive session key (if not Trial session)
        let (session_key, session_key_len) = self.derive_session_key(
            cmd.session_type,
            tpm_key,
            bind,
            bind_auth_stripped,
            &decrypted_salt[..decrypted_salt_len],
            cmd.auth_hash,
            &nonce_tpm,
            &cmd.nonce_caller,
            &cmd.symmetric,
        )?;

        let bound_entity = if bind == Handle::RH_NULL {
            OwnedName::default()
        } else {
            let bind_name = self.context.handle_name(self.global_state, bind.0);
            crate::util::bound_entity(bind_name.get_buffer(), bind_auth_stripped)
                .ok_or(TpmRc::FAILURE)?
        };

        // Add to active sessions
        let session_state = SessionState {
            session_handle,
            session_type: cmd.session_type,
            auth_hash: cmd.auth_hash,
            nonce_tpm: OwnedNonce::from(nonce_tpm),
            nonce_caller: OwnedNonce::from(cmd.nonce_caller),
            session_key,
            session_key_len,
            symmetric: cmd.symmetric,
            bind_entity: bind,
            bound_entity,
            audit_digest: None,
            audit_digest_len: 0,
            audit_cp_hash: [0u8; 64],
            audit_cp_hash_len: 0,
            policy_hash: [0u8; 64],
            policy_hash_len: 0,
            is_cp_hash_defined: false,
            is_name_hash_defined: false,
            is_template_hash_defined: false,
            policy_digest: [0u8; 64],
            policy_digest_len: auth_hash_digest_size,
            command_code: 0,
            start_time: self.global_state.tpm_time_ms,
            timeout: 0,
            epoch: self.global_state.time_epoch,
            is_auth_value_needed: false,
            is_password_needed: false,
            pcr_counter: None,
            check_nv_written: false,
            nv_written_state: false,
            command_locality: 0,
            include_auth: false,
        };
        self.global_state.add_session(session_state)?;

        // Write response
        let rsp = responses::StartAuthSession {
            session_handle: Handle(session_handle),
            nonce_tpm,
        };

        let response = request.into_response();

        self.write_response_all(
            response,
            &rsp.session_handle,
            &rsp,
            &session_responses[..num_sessions],
        )?;

        Ok(())
    }

    /// Helper function to parse authorization sessions for start session command.
    fn parse_auth_sessions_for_start_session(
        &self,
        request: &mut RequestThenResponse<'_, '_>,
        session_responses: &mut [TpmsAuthResponse<'static>; 3],
    ) -> Result<usize, TpmRc> {
        let mut num_sessions = 0;
        let auth_size = if request.session_tag() == tpm2::TpmiStCommandTag::Sessions {
            request.read_be_u32().ok_or(TpmRc::SIZE.to_rc())?
        } else {
            0
        };

        if auth_size > 0 {
            let mut auth_slice = request
                .read_slice(usize::try_from(auth_size).map_err(|_| TpmRc::SIZE.to_rc())?)
                .ok_or(TpmRc::SIZE.to_rc())?;
            while !auth_slice.is_empty() {
                if num_sessions >= 3 {
                    return Err(TpmRc::SIZE.with(Position::session(4)));
                }
                let session_position = crate::util::session_position(num_sessions);
                // PORTING: exp's `TpmsAuthCommand` unmarshal typed `sessionHandle` as
                // `TPMI_SH_AUTH_SESSION+` (checked before the rest of the structure).
                if let Some(session_handle) = auth_slice.first_chunk::<4>() {
                    let session_handle = Handle(u32::from_be_bytes(*session_handle));
                    check(session_handle, Tpmi::ShAuthSessionOrPw, session_position)?;
                }
                TpmsAuthCommand::unmarshal(&mut auth_slice)
                    .map_err(|e| e.fmt1().with(session_position))?;

                session_responses[num_sessions] = TpmsAuthResponse {
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession::CONTINUE_SESSION,
                    hmac: tpm2::Tpm2bData::default(),
                };
                num_sessions += 1;
            }
        }
        Ok(num_sessions)
    }

    /// Decrypts the session salt using the specified TPM key (via RSA-OAEP decryption or ECC key agreement).
    fn decrypt_session_salt(
        &mut self,
        tpm_key: Handle,
        encrypted_salt: &[u8],
        _nonce_tpm: &Tpm2bNonce,
        nonce_caller: &Tpm2bNonce,
        decrypted_salt: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        if tpm_key != Handle::RH_NULL {
            let handle_val = tpm_key.0;
            let key_obj = self.resolve_object(handle_val, Position::handle(1))?;

            let handle_err = TpmRc::HANDLE.with(Position::handle(1));
            // PORTING: exp checked `key_obj.private_len == 0` (public-only object).
            if key_obj.sensitive.as_bytes().is_empty() {
                return Err(handle_err);
            }

            if !key_obj
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
            {
                return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
            }

            match &key_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, modulus) => {
                    let expected_size = usize::from(parms.key_bits.as_u16() / 8);
                    if encrypted_salt.is_empty() || encrypted_salt.len() != expected_size {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    let mut plaintext_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                    let name_alg = key_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;

                    // PORTING: exp called `CryptoProvider::decrypt(Alg::OAEP, ..)` on the raw
                    // private blob; the key is now loaded from the public area and prime `p`.
                    // Any failure is still TPM_RC_VALUE (parameter 2).
                    let value_err = TpmRc::VALUE.with(Position::parameter(2));
                    let crypto = self.crypto();
                    let private =
                        load_rsa_private(crypto, parms, modulus.get_buffer(), &key_obj.sensitive)
                            .ok_or(value_err)?;
                    let scheme = RsaEncryptScheme::Oaep {
                        hash: name_alg,
                        label: b"SECRET\0",
                    };
                    let plaintext =
                        Rsa::decrypt(crypto, &private, scheme, encrypted_salt, &mut plaintext_buf)
                            .ok()
                            .flatten()
                            .ok_or(value_err)?;
                    let plaintext = plaintext.as_slice();
                    let decrypted_len = plaintext.len();

                    let name_alg_digest_size = name_alg.digest_size();
                    if name_alg_digest_size == 0 || decrypted_len > name_alg_digest_size {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }

                    decrypted_salt[..decrypted_len].copy_from_slice(plaintext);
                    Ok(decrypted_len)
                }
                OwnedPublicParmsAndId::Ecc(ecc_parms, ecc_unique) => {
                    if encrypted_salt.is_empty() {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }

                    let curve = ecc_parms.curve_id;
                    let param_size =
                        ecc_coordinate_size(curve).ok_or(TpmRc::CURVE.with(Position::handle(1)))?;

                    let mut slice = encrypted_salt;
                    let in_point_struct = TpmsEccPoint::unmarshal(&mut slice)
                        .map_err(|_| TpmRc::VALUE.with(Position::parameter(2)))?;
                    if !slice.is_empty() {
                        return Err(TpmRc::SIZE.with(Position::parameter(2)));
                    }

                    // Fails if either coordinate is longer than `param_size`.
                    let value_err = TpmRc::VALUE.with(Position::parameter(2));
                    let in_point =
                        PaddedEccPoint::from_tpms(&in_point_struct, param_size).ok_or(value_err)?;

                    // PORTING: exp called `CryptoProvider::validate_point` and then
                    // `point_multiply` with the raw private blob; this is now `Ecc::load_public`
                    // (point validation) followed by ECDH with the loaded private key. Any
                    // failure is still TPM_RC_VALUE (parameter 2).
                    let crypto = self.crypto();
                    let peer = load_ecc_public(crypto, curve, &in_point).ok_or(value_err)?;
                    let ek_point = PaddedEccPoint::new(
                        ecc_unique.x.get_buffer(),
                        ecc_unique.y.get_buffer(),
                        param_size,
                    )
                    .ok_or(value_err)?;
                    let OwnedSensitiveComposite::Ecc(scalar) = &key_obj.sensitive else {
                        return Err(value_err);
                    };
                    let private = load_ecc_public(crypto, curve, &ek_point)
                        .and_then(|public| {
                            Ecc::load_private(crypto, public, scalar.as_tpm2b())
                                .ok()
                                .flatten()
                        })
                        .ok_or(value_err)?;
                    let z = ecc_point_multiply(crypto, &private, &peer, param_size)
                        .ok()
                        .flatten()
                        .ok_or(value_err)?;

                    let name_alg = key_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                    let hash_size = name_alg.digest_size();

                    let mut derived_salt = [0u8; 64];
                    kdfe(
                        crypto,
                        name_alg,
                        z.x(),
                        c"SECRET",
                        in_point.x(),
                        ek_point.x(),
                        &mut derived_salt[..hash_size],
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                    let derived_salt_len = hash_size;

                    decrypted_salt[..derived_salt_len]
                        .copy_from_slice(&derived_salt[..derived_salt_len]);
                    Ok(derived_salt_len)
                }
                OwnedPublicParmsAndId::Sym(sym_def, _) => {
                    if encrypted_salt.is_empty() || encrypted_salt.len() > 64 {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    let mut iv = [0u8; 16];
                    let nonce_buf = nonce_caller.as_slice();
                    let iv_len = nonce_buf.len().min(16);
                    iv[..iv_len].copy_from_slice(&nonce_buf[..iv_len]);

                    let mut plaintext_buf = [0u8; 64];
                    plaintext_buf[..encrypted_salt.len()].copy_from_slice(encrypted_salt);

                    // The salt is always decrypted in CFB mode, regardless of `sym_def.mode`.
                    let key = SymmetricKey::new(sym_def.alg, key_obj.sensitive.as_bytes())
                        .ok_or(TpmRc::VALUE.with(Position::parameter(2)))?;
                    tpm2::crypto::decrypt(
                        self.crypto(),
                        key,
                        ModeIv::Cfb(&mut iv),
                        &mut plaintext_buf[..encrypted_salt.len()],
                    )
                    .map_err(|_| TpmRc::VALUE.with(Position::parameter(2)))?;

                    decrypted_salt[..encrypted_salt.len()]
                        .copy_from_slice(&plaintext_buf[..encrypted_salt.len()]);
                    Ok(encrypted_salt.len())
                }
                OwnedPublicParmsAndId::Mlkem(parms, unique) => {
                    let value_err = TpmRc::VALUE.with(Position::parameter(2));
                    let OwnedSensitiveComposite::Mlkem(seed) = &key_obj.sensitive else {
                        return Err(value_err);
                    };
                    let crypto = self.crypto();
                    let priv_key = Mlkem::derive_key(crypto, parms.parameter_set, Tpm2b(seed))
                        .map_err(|_| value_err)?;
                    let ct = Tpm2bKemCiphertext::new(encrypted_salt).ok_or(value_err)?;
                    let mut ss_buf = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
                    let ss = Mlkem::decapsulate(crypto, &priv_key, ct, &mut ss_buf)
                        .ok()
                        .flatten()
                        .ok_or(value_err)?;
                    let name_alg = key_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                    let hash_size = name_alg.digest_size();
                    kdfa(
                        crypto,
                        name_alg,
                        ss.as_slice(),
                        c"SECRET",
                        encrypted_salt,
                        unique.get_buffer(),
                        &mut decrypted_salt[..hash_size],
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                    Ok(hash_size)
                }
                _ => Err(TpmRc::KEY.with(Position::handle(1))),
            }
        } else {
            if !encrypted_salt.is_empty() {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }
            Ok(0)
        }
    }

    /// Resolves the auth value for the session bind entity (owner, endorsement, platform, lockout,
    /// or transient objects).
    fn retrieve_bind_auth(
        &mut self,
        bind: Handle,
        bind_auth: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        if bind != Handle::RH_NULL {
            let bind_handle = bind.0;
            let handle_err = TpmRc::HANDLE.with(Position::handle(2));
            let handle_type = bind.handle_type();
            if handle_type == Some(TpmHt::Transient) {
                let Some(obj) = self.global_state.find_transient_object(bind_handle) else {
                    return Err(TpmRc::REFERENCE_H1);
                };
                if obj.sensitive.as_bytes().is_empty() {
                    return Err(handle_err);
                }
            } else if handle_type == Some(TpmHt::Persistent) {
                let Ok(obj) = self
                    .context
                    .load_persistent_object(self.global_state, bind_handle)
                else {
                    return Err(TpmRc::REFERENCE_H1);
                };
                if obj.sensitive.as_bytes().is_empty() {
                    return Err(handle_err);
                }
            } else if handle_type == Some(TpmHt::PCR) {
                if bind_handle <= 23 {
                    return Ok(0);
                } else {
                    return Err(handle_err);
                }
            } else if handle_type == Some(TpmHt::NVIndex) {
                let storage_mgr = crate::storage::manager::StorageManager::new(
                    &mut *self.context.platform.storage,
                );
                if storage_mgr.get_metadata(bind_handle).is_err() {
                    return Err(TpmRc::REFERENCE_H1);
                }
            } else if bind != Handle::RH_OWNER
                && bind != Handle::RH_ENDORSEMENT
                && bind != Handle::RH_PLATFORM
                && bind != Handle::RH_LOCKOUT
                && bind != crate::util::RH_AUTH_00
            {
                return Err(handle_err);
            }
            let auth_buf_struct = self.context.handle_auth(self.global_state, bind_handle);
            let auth_buf = auth_buf_struct.get_buffer();
            bind_auth[..auth_buf.len()].copy_from_slice(auth_buf);
            Ok(auth_buf.len())
        } else {
            Ok(0)
        }
    }

    /// Allocates a unique handle for the new session, avoiding conflicts in the global session map.
    fn generate_session_handle(&self, session_type: TpmSe) -> Result<u32, TpmRc> {
        let handle_prefix = match session_type {
            TpmSe::HMAC => 0x02000000,
            TpmSe::Policy => 0x03000000,
            TpmSe::Trial => 0x03000000,
        };

        for offset in 0..MAX_ACTIVE_SESSIONS {
            let hmac_candidate = 0x02000000 | offset;
            let policy_candidate = 0x03000000 | offset;
            if self.global_state.session(hmac_candidate).is_none()
                && self.global_state.session(policy_candidate).is_none()
                && !self
                    .global_state
                    .saved_sessions
                    .contains(&Some(hmac_candidate))
                && !self
                    .global_state
                    .saved_sessions
                    .contains(&Some(policy_candidate))
            {
                return Ok(handle_prefix | offset);
            }
        }
        Err(TpmRc::SESSION_MEMORY)
    }

    /// Derives the cryptographic session key from bind auth and decrypted salt using KDFa,
    /// aligned with the requested hash algorithm and symmetric parameters.
    #[allow(clippy::too_many_arguments)]
    fn derive_session_key(
        &self,
        session_type: TpmSe,
        tpm_key: Handle,
        bind: Handle,
        bind_auth: &[u8],
        decrypted_salt: &[u8],
        auth_hash: TpmiAlgHash,
        nonce_tpm: &Tpm2bNonce,
        nonce_caller: &Tpm2bNonce,
        _symmetric: &Option<TpmtSymDef>,
    ) -> Result<([u8; 128], usize), TpmRc> {
        if session_type != TpmSe::Trial && (tpm_key != Handle::RH_NULL || bind != Handle::RH_NULL) {
            let bind_auth_len = bind_auth.len();
            let decrypted_salt_len = decrypted_salt.len();
            let secret_len = bind_auth_len + decrypted_salt_len;
            if secret_len > 128 {
                return Err(TpmRc::FAILURE);
            }
            let mut secret = [0u8; 128];
            secret[..bind_auth_len].copy_from_slice(bind_auth);
            secret[bind_auth_len..secret_len].copy_from_slice(decrypted_salt);

            // The session key is `digest_size` bytes (`8 * digest_size` bits) long.
            let derived_key_len = auth_hash.digest_size();
            if derived_key_len > 128 {
                return Err(TpmRc::FAILURE);
            }
            let mut derived_key = [0u8; 128];

            kdfa(
                self.crypto(),
                auth_hash,
                &secret[..secret_len],
                c"ATH",
                nonce_tpm.as_slice(),
                nonce_caller.as_slice(),
                &mut derived_key[..derived_key_len],
            )
            .map_err(|_| TpmRc::FAILURE)?;

            Ok((derived_key, derived_key_len))
        } else {
            Ok(([0u8; 128], 0))
        }
    }

    /// Handles the [TpmCc::PolicyCommandCode] (`0x16C`) command.
    ///
    /// # Description
    /// This command binds a requirement to the policy session that it can only be used to authorize
    /// a command with the specified command code (`code`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.11 (TPM2_PolicyCommandCode).
    ///
    /// # Relationships
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    pub fn policy_command_code(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let [policy_session] = request.try_unmarshal_handles::<PolicyCommandCode>()?;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let mut session_responses = [TpmsAuthResponse::default(); 3];
        let num_sessions =
            self.parse_auth_sessions_for_start_session(&mut request, &mut session_responses)?;
        let cmd = request.try_unmarshal_command::<PolicyCommandCode>([policy_session])?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Check if the code is supported.
        if !crate::engine::is_command_supported(cmd.code) {
            return Err(TpmRc::POLICY_CC.to_rc());
        }

        // 2. Retrieve session state details.
        let session_handle = policy_session.0;
        let (auth_hash, policy_digest, policy_digest_len) = {
            let session_state = self
                .global_state
                .session(session_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }
            if session_state.command_code != 0 && session_state.command_code != cmd.code.code() {
                return Err(TpmRc::VALUE.to_rc());
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
            )
        };

        // 5. Update policy digest.
        let mut updates = [0u8; 128];
        let mut offset = 0;
        if policy_digest_len > 0 {
            updates[..policy_digest_len].copy_from_slice(&policy_digest[..policy_digest_len]);
            offset += policy_digest_len;
        }
        let cc_val = TpmCc::PolicyCommandCode.code();
        updates[offset..offset + 4].copy_from_slice(&cc_val.to_be_bytes());
        offset += 4;
        updates[offset..offset + 4].copy_from_slice(&cmd.code.code().to_be_bytes());
        offset += 4;

        let mut new_digest = [0u8; 64];
        let new_digest_len = compute_hash(
            self.crypto(),
            auth_hash,
            &updates[..offset],
            &mut new_digest,
        )?;

        // Now mutate the session state.
        {
            let session_state = self
                .global_state
                .session_mut(session_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            session_state.command_code = cmd.code.code();
        }

        let response = request.into_response();
        self.write_response_all(response, &(), &(), &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PolicyGetDigest] (`0x189`) command.
    ///
    /// # Description
    /// This command returns the current policy digest value of the active policy session.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.19 (TPM2_PolicyGetDigest).
    ///
    /// # Relationships
    /// - Reads the accumulated policy digest of a session created via [TpmCc::StartAuthSession](session.rs).
    pub fn policy_get_digest(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let [policy_session] = request.try_unmarshal_handles::<PolicyGetDigest>()?;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<PolicyGetDigest>([policy_session])?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Retrieve session state.
        let session_handle = policy_session.0;
        let global_state = &self.global_state;
        let session_state = global_state
            .session(session_handle)
            .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;

        // 2. Verify session type is Policy.
        if session_state.session_type != TpmSe::Policy && session_state.session_type != TpmSe::Trial
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        // 3. Construct response.
        let policy_digest =
            Tpm2bDigest::new(&session_state.policy_digest[..session_state.policy_digest_len])
                .ok_or(TpmRc::FAILURE)?;
        let rsp = responses::PolicyGetDigest { policy_digest };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PolicyRestart] (`0x180`) command.
    ///
    /// # Description
    /// This command resets the policy digest of the active session back to the zero digest and clears
    /// any bound constraints (such as cpHash, nameHash, or authValue requirement flags).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 11.2 (TPM2_PolicyRestart).
    ///
    /// # Relationships
    /// - Resets a policy session started by [TpmCc::StartAuthSession](session.rs).
    /// - Allows reusing an existing policy session handle for a fresh policy evaluation.
    pub fn policy_restart(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let [session_handle] = request.try_unmarshal_handles::<PolicyRestart>()?;
        check(session_handle, Tpmi::ShPolicy, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal_command::<PolicyRestart>([session_handle])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let session_handle = session_handle.0;

        let auth_hash = {
            let session_state = self
                .global_state
                .session(session_handle)
                .ok_or(TpmRc::REFERENCE_H0)?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }
            session_state.auth_hash
        };

        let auth_hash_digest_size = auth_hash.digest_size();

        // Mutate session state to initial state
        {
            let session_state = self
                .global_state
                .session_mut(session_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;

            session_state.policy_digest = [0u8; 64];
            session_state.policy_digest_len = auth_hash_digest_size;
            session_state.command_code = 0;
            session_state.is_auth_value_needed = false;
            session_state.is_password_needed = false;
            session_state.is_cp_hash_defined = false;
            session_state.is_name_hash_defined = false;
            session_state.is_template_hash_defined = false;
            session_state.check_nv_written = false;
            session_state.nv_written_state = false;
            session_state.pcr_counter = None;
            session_state.command_locality = 0;
        }

        let response = request.into_response();
        self.write_response_all(response, &(), &(), &session_responses[..num_sessions])?;
        Ok(())
    }
}

fn compute_hash<C: Crypto>(
    crypto: &C,
    auth_hash: TpmiAlgHash,
    data: &[u8],
    hash_out: &mut [u8],
) -> Result<usize, TpmRc> {
    let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash(crypto, auth_hash, data, &mut digest_buf)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    let slice = digest.digest();
    let len = slice.len();
    hash_out[..len].copy_from_slice(slice);
    Ok(len)
}

/// Coordinate size (in bytes) of the ECC curves exp supported for salted sessions and
/// `TPM2_PolicySigned` (`TPM_ECC_NIST_P192`, `TPM_ECC_NIST_P224`, `TPM_ECC_NIST_P256`,
/// `TPM_ECC_BN_P256`, `TPM_ECC_NIST_P384` and `TPM_ECC_NIST_P521`), or `None` for any other curve.
///
/// PORTING: replaces exp's inline `match curve { NistP192 => 24, .. }` tables. Unlike
/// `crypt_ops::ecc_param_size`, this keeps exp's `TPM_ECC_NIST_P192` entry.
pub(super) const fn ecc_coordinate_size(curve: TpmEccCurve) -> Option<usize> {
    match curve {
        TpmEccCurve::NistP192
        | TpmEccCurve::NistP224
        | TpmEccCurve::NistP256
        | TpmEccCurve::BNP256
        | TpmEccCurve::NistP384
        | TpmEccCurve::NistP521 => Some(curve.key_bytes()),
        _ => None,
    }
}
