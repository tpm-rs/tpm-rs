use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::self_test::kdfa_bits;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::commands::ActivateCredential;
use tpm2::commands::responses;
use tpm2::crypto::{CryptoProvider, Direction, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Tpm2bDigest, TpmaObject, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmtSymDefObject,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ActivateCredential] (`0x147`) command.
    ///
    /// # Description
    /// This command enables the association of a credential with an object in a way that ensures
    /// that the TPM has validated the parameters of the credentialed object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.5 (TPM2_ActivateCredential).
    ///
    /// # Relationships
    /// - Use [TpmCc::MakeCredential](make_credential.rs)
    ///   (usually executed off-TPM) to create the credential blob and encrypted secret.
    /// - The `activate_handle` must reference a loaded object created by [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs)
    ///   and loaded via [TpmCc::Load](load.rs).
    pub fn activate_credential(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<ActivateCredential>()?;
        let [activate_handle, key_handle] = handles;
        check(activate_handle, Tpmi::DhObject, Position::handle(1))?;
        check(key_handle, Tpmi::DhObject, Position::handle(2))?;
        let activate_handle = activate_handle.0;
        let key_handle = key_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<ActivateCredential>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 2. Retrieve decryption (protector) object. A sequence object is not an
        // asymmetric key (`TPM_RC_TYPE + RC_ActivateCredential_keyHandle`).
        if self
            .context
            .state
            .find_active_sequence(key_handle)
            .is_some()
        {
            return Err(TpmRc::TYPE.with(Position::handle(2)));
        }
        let key_obj = self.resolve_object(key_handle, Position::handle(2))?;

        // 3. Decryption key must be an asymmetric, restricted decryption key
        let attrs = key_obj.public.object_attributes;
        if !matches!(
            key_obj.public.parms_and_id,
            crate::owned::OwnedPublicParmsAndId::Rsa(_, _)
                | crate::owned::OwnedPublicParmsAndId::Ecc(_, _)
        ) || !attrs.contains(TpmaObject::DECRYPT)
            || !attrs.contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::TYPE.with(Position::handle(2)));
        }

        let name_alg = key_obj
            .public
            .name_alg
            .ok_or(TpmRc::TYPE.with(Position::handle(2)))?;
        let digest_size = name_alg.digest_size();

        // A sequence object as `activateHandle` is rejected after the protector key's checks.
        // TPM 2.0 Part 3, TPM2_ActivateCredential: "This command enables the association of a
        // credential with an object in a way that ensures that the TPM has validated the
        // parameters of the credentialed object." A sequence object has no such parameters; the
        // specification gives no response code for it, so the TCG reference's (version 185,
        // "Cannot activate credential of sequence object")
        // `TPM_RC_TYPE + RC_ActivateCredential_activateHandle` is used.
        if self
            .context
            .state
            .find_active_sequence(activate_handle)
            .is_some()
        {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }

        // 4. Decrypt secret to recover seed (`CryptSecretDecrypt`). C maps `TPM_RC_KEY` to
        // `TPM_RC_FAILURE` and adds `RC_ActivateCredential_secret` to the other errors.
        let mut seed = [0u8; 64];
        let seed_len = self
            .crypt_secret_decrypt(&key_obj, b"IDENTITY", cmd.secret.get_buffer(), &mut seed)
            .map_err(|e| {
                if e == TpmRc::KEY.to_rc() {
                    TpmRc::FAILURE
                } else {
                    e.with_position(Position::parameter(2))
                }
            })?;

        // The activated object is used only for its Name, after the protector key's checks
        // and the seed's decryption (C `TPM2_ActivateCredential()`: the key's type check and
        // `CryptSecretDecrypt()` come first; "this assertion is deliberately late, after other
        // validation has happened"). Any loaded object other than a sequence object
        // qualifies.
        // TPM 2.0 Part 3, TPM2_ActivateCredential: "The key associated with *keyHandle* is used
        // to recover a seed from *secret*, which is the encrypted seed. The Name of the object
        // associated with *activateHandle*, and the recovered seed are used in a KDF to recover
        // the symmetric key."
        let activate_name = self.context.handle_name(activate_handle);

        // 5. Derive symmetric key and HMAC key using KDFa. The credential is always decrypted in
        // CFB mode with the key's symmetric algorithm, whatever mode its public area names (TPM
        // 2.0 Part 1, "Credential Protection": "encIdentity := CFB_ekSymAlg (symKey, 0, CV)",
        // where "CFB_ekSymAlg | is symmetric encryption in CFB mode using the symmetric algorithm
        // of the key serving as "EK"").
        let key_sym = match &key_obj.public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::Rsa(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::TYPE.with(Position::handle(2)))?,
            crate::owned::OwnedPublicParmsAndId::Ecc(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::TYPE.with(Position::handle(2)))?,
            _ => return Err(TpmRc::TYPE.with(Position::handle(2))),
        };
        let sym_alg = TpmtSymDefObject {
            alg: key_sym.alg,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        };
        let sym_key_bits = sym_alg.key_bits() as u32;
        let outer_key_len = (sym_key_bits / 8) as usize;

        let mut sym_key_iv = [0u8; 64];
        let mut integrity_key = [0u8; 64];

        let digest_bits = (digest_size * 8) as u32;
        kdfa_bits(
            &self.crypto(),
            name_alg,
            &seed[..seed_len],
            b"STORAGE",
            activate_name.get_buffer(),
            &[],
            sym_key_bits,
            &mut sym_key_iv,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        kdfa_bits(
            &self.crypto(),
            name_alg,
            &seed[..seed_len],
            b"INTEGRITY",
            &[],
            &[],
            digest_bits,
            &mut integrity_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        // 6. Unmarshal integrity_hmac and get the remaining encrypted slice. All
        // `CredentialToSecret` errors carry `RC_ActivateCredential_credentialBlob`.
        let mut slice = cmd.credential_blob.get_buffer();
        let integrity_hmac =
            Tpm2bDigest::unmarshal(&mut slice).map_err(|e| e.in_parameter(1).to_rc())?;
        let encrypted_enc_identity = slice;

        // 7. Verify integrity HMAC
        let mut hmac_ctx = self
            .crypto()
            .hmac_stream(name_alg, &integrity_key[..digest_size])
            .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(encrypted_enc_identity)
            .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(activate_name.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        let mut hmac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let hmac_digest = hmac_ctx
            .finalize(&mut hmac_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        let expected_hmac = Tpm2bDigest::from_bytes(hmac_digest.digest()).unwrap();

        if integrity_hmac != expected_hmac {
            return Err(TpmRc::INTEGRITY.with(Position::parameter(1)));
        }

        // 8. Decrypt credential
        let mut decrypted_enc_identity = [0u8; tpm2::Tpm2bIdObject::CAP];
        let encrypt_len = encrypted_enc_identity.len();
        if encrypt_len > decrypted_enc_identity.len() {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        decrypted_enc_identity[..encrypt_len].copy_from_slice(encrypted_enc_identity);

        let mut iv = [0u8; 16];
        self.sym_encrypt_decrypt(
            sym_alg,
            &sym_key_iv[..outer_key_len],
            &mut iv,
            Direction::Decrypt,
            &mut decrypted_enc_identity[..encrypt_len],
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let mut slice = &decrypted_enc_identity[..encrypt_len];
        let cert_info =
            Tpm2bDigest::unmarshal(&mut slice).map_err(|e| e.in_parameter(1).to_rc())?;
        // All of the decrypted data must be consumed (C `CredentialToSecret`).
        if !slice.is_empty() {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        let rsp = responses::ActivateCredential { cert_info };

        // 9. Write response
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
