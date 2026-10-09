use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::commands::responses;
use tpm2::commands::{ActivateCredential, ActivateCredentialHandles};
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bDigest, TpmaObject};

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

        let handles = request.try_unmarshal::<ActivateCredentialHandles>()?;
        let activate_handle = handles.activate_handle.0;
        let key_handle = handles.key_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<ActivateCredential>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Retrieve target (activated) object
        let activate_obj = self.resolve_object(activate_handle, Position::handle(1))?;

        // 2. Retrieve decryption (protector) object. A sequence object is not an
        // asymmetric key (`TPM_RC_TYPE + RC_ActivateCredential_keyHandle`).
        if self.global_state.find_active_sequence(key_handle).is_some() {
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

        // 5. Derive symmetric key and HMAC key using KDFa
        let sym_alg = match &key_obj.public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::Rsa(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::TYPE.with(Position::handle(2)))?,
            crate::owned::OwnedPublicParmsAndId::Ecc(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::TYPE.with(Position::handle(2)))?,
            _ => return Err(TpmRc::TYPE.with(Position::handle(2))),
        };
        let sym_key_bits = sym_alg.key_bits() as u32;
        let outer_key_len = (sym_key_bits / 8) as usize;

        let mut sym_key_iv = [0u8; 64];
        let mut integrity_key = [0u8; 64];

        let digest_bits = (digest_size * 8) as u32;
        kdfa(
            self.crypto(),
            name_alg,
            &seed[..seed_len],
            b"STORAGE",
            activate_obj.name.get_buffer(),
            &[],
            sym_key_bits,
            &mut sym_key_iv,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        kdfa(
            self.crypto(),
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
        let mut hmac_ctx =
            tpm2::crypto::HmacCtx::new(self.crypto(), name_alg, &integrity_key[..digest_size])
                .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(encrypted_enc_identity)
            .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(activate_obj.name.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        let mut hmac_buf = [0u8; 64];
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
        tpm2::crypto::decrypt(
            self.crypto(),
            sym_alg,
            &sym_key_iv[..outer_key_len],
            &mut iv,
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
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
