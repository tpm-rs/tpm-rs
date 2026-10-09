use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{MakeCredential, MakeCredentialHandles};
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bIdObject, TpmaObject, TpmsIdObject};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::MakeCredential] (`0x168`) command.
    ///
    /// # Description
    /// This command is used to encrypt a credential (like a symmetric key or seed) under a loaded restricted decryption key
    /// and bind it to a target object name. The resulting credential blob and encrypted seed can only be decrypted by a TPM
    /// that possesses both the private key of the restricted decryption key and the private key of the target object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.6 (TPM2_MakeCredential).
    ///
    /// # Relationships
    /// - The outputs `credential_blob` and `secret` are designed to be sent to a target TPM that executes [TpmCc::ActivateCredential](activate_credential.rs)
    ///   to decrypt the credential.
    /// - The restricted decryption key (`handle`) must be loaded on the TPM executing this command.
    pub fn make_credential(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<MakeCredentialHandles>()?;
        let handle = handles.handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<MakeCredential>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve protector key. A sequence object is not an asymmetric key.
        if self.global_state.find_active_sequence(handle).is_some() {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }
        let protector_obj = self.resolve_object(handle, Position::handle(1))?;

        // 2. The protector key must be an asymmetric, restricted decryption key
        let attrs = protector_obj.public.object_attributes;
        if !matches!(
            protector_obj.public.parms_and_id,
            crate::owned::OwnedPublicParmsAndId::Rsa(_, _)
                | crate::owned::OwnedPublicParmsAndId::Ecc(_, _)
        ) || !attrs.contains(TpmaObject::DECRYPT)
            || !attrs.contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }

        let name_alg = protector_obj
            .public
            .name_alg
            .ok_or(TpmRc::TYPE.with(Position::handle(1)))?;
        let digest_size = name_alg.digest_size();

        // The credential may not be larger than the digest of the key's nameAlg; C checks
        // this during input validation, before any secret is generated.
        let cred_len = cmd.credential.get_size() as usize;
        if cred_len > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // 3. Generate seed and encrypt it into secret (`CryptSecretEncrypt`, returned unmodified)
        let mut seed = [0u8; 64];
        let mut secret_buf = [0u8; 512];
        let (_, secret_len) =
            self.crypt_secret_encrypt(&protector_obj, b"IDENTITY", &mut seed, &mut secret_buf)?;
        let secret = Tpm2bEncryptedSecret::from_bytes(&secret_buf[..secret_len])
            .map_err(|_| TpmRc::FAILURE)?;

        // 4. Derive symmetric key and HMAC key using KDFa
        let sym_alg = match &protector_obj.public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::Rsa(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::TYPE.with(Position::handle(1)))?,
            crate::owned::OwnedPublicParmsAndId::Ecc(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::TYPE.with(Position::handle(1)))?,
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };
        let sym_key_bits = sym_alg.key_bits() as u32;
        let outer_key_len = (sym_key_bits / 8) as usize;

        let mut sym_key_iv = [0u8; 64];
        let mut integrity_key = [0u8; 64];

        let digest_bits = (digest_size * 8) as u32;
        kdfa(
            self.crypto(),
            name_alg,
            &seed[..digest_size],
            b"STORAGE",
            cmd.object_name.get_buffer(),
            &[],
            sym_key_bits,
            &mut sym_key_iv,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        kdfa(
            self.crypto(),
            name_alg,
            &seed[..digest_size],
            b"INTEGRITY",
            &[],
            &[],
            digest_bits,
            &mut integrity_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        // 5. Marshal credential to encrypt (includes 2-byte size prefix)
        let mut credential_to_encrypt = [0u8; 68];
        credential_to_encrypt[0..2].copy_from_slice(&(cred_len as u16).to_be_bytes());
        credential_to_encrypt[2..2 + cred_len].copy_from_slice(cmd.credential.get_buffer());
        let encrypt_len = 2 + cred_len;

        let mut iv = [0u8; 16];
        tpm2::crypto::encrypt(
            self.crypto(),
            sym_alg,
            &sym_key_iv[..outer_key_len],
            &mut iv,
            &mut credential_to_encrypt[..encrypt_len],
        )
        .map_err(|_| TpmRc::FAILURE)?;

        // 6. Compute integrity HMAC over the encrypted credential (includes encrypted size prefix)
        let mut hmac_ctx =
            tpm2::crypto::HmacCtx::new(self.crypto(), name_alg, &integrity_key[..digest_size])
                .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(&credential_to_encrypt[..encrypt_len])
            .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(cmd.object_name.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        let mut hmac_buf = [0u8; 64];
        let hmac_digest = hmac_ctx
            .finalize(&mut hmac_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        let integrity_hmac = Tpm2bDigest::from_bytes(hmac_digest.digest()).unwrap();

        // 7. Assemble Tpm2bIdObject from TpmsIdObject
        let id_obj = TpmsIdObject::new(integrity_hmac, &credential_to_encrypt[..encrypt_len])
            .map_err(|_| TpmRc::FAILURE)?;
        let mut id_obj_buf = [0u8; TpmsIdObject::MAX_SIZE];
        let id_obj_len = id_obj.marshal(&mut id_obj_buf);
        let credential_blob =
            Tpm2bIdObject::from_bytes(&id_obj_buf[..id_obj_len]).map_err(|_| TpmRc::FAILURE)?;

        let rsp = responses::MakeCredential {
            credential_blob,
            secret,
        };

        // 8. Write response
        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
