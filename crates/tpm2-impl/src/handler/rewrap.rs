use crate::handler::CommandHandler;
use crate::owned::OwnedPublicParmsAndId;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Alg;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{Rewrap, RewrapHandles};
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bEncryptedSecret, Tpm2bPrivate, TpmaObject};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::Rewrap] (`0x152`) command.
    ///
    /// # Description
    /// This command allows the TPM to serve in the role of a Migration Authority (MA),
    /// changing the outer wrapper of a duplicate key from `old_parent` to `new_parent`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 13.2 (TPM2_Rewrap).
    pub fn rewrap(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<RewrapHandles>()?;
        let old_parent_handle = handles.old_parent.0;
        let new_parent_handle = handles.new_parent.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<Rewrap>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Input Validation: in_sym_seed consistency with old_parent
        if (cmd.in_sym_seed.get_size() == 0 && old_parent_handle != Handle::RH_NULL.0)
            || (cmd.in_sym_seed.get_size() != 0 && old_parent_handle == Handle::RH_NULL.0)
        {
            return Err(TpmRc::HANDLE.with(Position::handle(1)));
        }

        let mut seed = [0u8; 64];
        let mut seed_len = 0;
        let mut private_blob = [0u8; 1024];
        let private_blob_len;

        // 1. Unwrap Outer using oldParent (if present)
        if old_parent_handle != Handle::RH_NULL.0 {
            let old_parent_obj = if old_parent_handle >> 24 == 0x80 {
                self.global_state
                    .find_transient_object(old_parent_handle)
                    .cloned()
                    .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?
            } else if old_parent_handle >> 24 == 0x81 {
                self.context
                    .load_persistent_object(self.global_state, old_parent_handle)
                    .map_err(|_| TpmRc::HANDLE.with(Position::handle(1)))?
            } else {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            };

            // old_parent must be a storage object (decrypt + restricted)
            if !old_parent_obj
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
                || !old_parent_obj
                    .public
                    .object_attributes
                    .contains(TpmaObject::RESTRICTED)
            {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }

            // Decrypt in_sym_seed using old_parent private key
            seed_len = match &old_parent_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(_, _) => self
                    .crypto()
                    .decrypt(
                        Alg::OAEP,
                        Alg::from(old_parent_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?),
                        &old_parent_obj.private[..old_parent_obj.private_len],
                        cmd.in_sym_seed.get_buffer(),
                        &mut seed,
                        b"DUPLICATE\0",
                    )
                    .map_err(|_| TpmRc::VALUE.with(Position::parameter(3)))?,
                _ => {
                    return Err(TpmRc::TYPE.with(Position::handle(1)));
                }
            };

            let duplicate_bytes = cmd.in_duplicate.get_buffer();
            if duplicate_bytes.len() < 2 {
                return Err(TpmRc::SIZE.to_rc());
            }
            let mac_len = u16::from_be_bytes([duplicate_bytes[0], duplicate_bytes[1]]) as usize;
            if duplicate_bytes.len() < 2 + mac_len {
                return Err(TpmRc::SIZE.to_rc());
            }
            let mac_bytes = &duplicate_bytes[2..2 + mac_len];
            let encrypted_blob = &duplicate_bytes[2 + mac_len..];

            let mut sym_key_bits = match &old_parent_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, _) => {
                    parms.symmetric.map(|s| s.key_bits() as u32).unwrap_or(128)
                }
                OwnedPublicParmsAndId::Ecc(parms, _) => {
                    parms.symmetric.map(|s| s.key_bits() as u32).unwrap_or(128)
                }
                _ => 128,
            };
            if sym_key_bits == 0 {
                sym_key_bits = 128;
            }
            let outer_key_len = (sym_key_bits / 8) as usize;

            let mut sym_key_iv = [0u8; 48];
            let mut integrity_key = [0u8; 64];
            let mut computed_mac_bytes = [0u8; 64];

            let old_name_alg = old_parent_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
            let old_digest_size = old_name_alg.digest_size();
            let old_bits = (old_digest_size * 8) as u32;
            kdfa(
                self.crypto(),
                old_name_alg,
                &seed[..seed_len],
                b"INTEGRITY",
                &[],
                &[],
                old_bits,
                &mut integrity_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            kdfa(
                self.crypto(),
                old_name_alg,
                &seed[..seed_len],
                b"STORAGE",
                cmd.name.get_buffer(),
                &[],
                sym_key_bits,
                &mut sym_key_iv,
            )
            .map_err(|_| TpmRc::FAILURE)?;

            let mut hmac_ctx = tpm2::crypto::HmacCtx::new(
                self.crypto(),
                old_name_alg,
                &integrity_key[..old_digest_size],
            )
            .map_err(|_| TpmRc::FAILURE)?;
            hmac_ctx
                .update(encrypted_blob)
                .map_err(|_| TpmRc::FAILURE)?;
            hmac_ctx
                .update(cmd.name.get_buffer())
                .map_err(|_| TpmRc::FAILURE)?;
            let hmac_res = hmac_ctx
                .finalize(&mut computed_mac_bytes)
                .map_err(|_| TpmRc::FAILURE)?;
            let computed_mac_len = hmac_res.digest().len();

            if mac_len != computed_mac_len
                || !crate::util::constant_time_eq(
                    mac_bytes,
                    &computed_mac_bytes[..computed_mac_len],
                )
            {
                return Err(TpmRc::INTEGRITY.to_rc());
            }

            // Decrypt outer layer using outer key (CFB mode)
            let mut outer_key = [0u8; 32];
            outer_key[..outer_key_len].copy_from_slice(&sym_key_iv[..outer_key_len]);
            let mut outer_iv = [0u8; 16];

            let mut decrypted_blob = [0u8; 1024];
            let dec_len = encrypted_blob.len();
            decrypted_blob[..dec_len].copy_from_slice(encrypted_blob);
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((outer_key_len * 8) as u16)
                .map_err(|_| TpmRc::FAILURE)?;
            tpm2::crypto::decrypt(
                self.crypto(),
                sym_alg,
                &outer_key[..outer_key_len],
                &mut outer_iv,
                &mut decrypted_blob[..dec_len],
            )
            .map_err(|_| TpmRc::FAILURE)?;

            private_blob_len = dec_len;
            private_blob[..private_blob_len].copy_from_slice(&decrypted_blob[..dec_len]);
        } else {
            let dup_buf = cmd.in_duplicate.get_buffer();
            private_blob_len = dup_buf.len();
            private_blob[..private_blob_len].copy_from_slice(dup_buf);
        }

        // 2. Produce Outer Wrap using newParent (if present)
        let mut encrypted_secret = [0u8; 512];
        let mut final_duplicate = [0u8; 1024];
        let out_sym_seed;
        let out_duplicate;

        if new_parent_handle != Handle::RH_NULL.0 {
            let new_parent_obj = if new_parent_handle >> 24 == 0x80 {
                self.global_state
                    .find_transient_object(new_parent_handle)
                    .cloned()
                    .ok_or(TpmRc::HANDLE.with(Position::handle(2)))?
            } else if new_parent_handle >> 24 == 0x81 {
                self.context
                    .load_persistent_object(self.global_state, new_parent_handle)
                    .map_err(|_| TpmRc::HANDLE.with(Position::handle(2)))?
            } else {
                return Err(TpmRc::HANDLE.with(Position::handle(2)));
            };

            // new_parent must be a storage object (decrypt + restricted)
            if !new_parent_obj
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
                || !new_parent_obj
                    .public
                    .object_attributes
                    .contains(TpmaObject::RESTRICTED)
            {
                return Err(TpmRc::TYPE.with(Position::handle(2)));
            }

            let new_name_alg = new_parent_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;

            // Encrypt seed under new_parent public key
            let enc_len = match &new_parent_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(_, unique) => {
                    let pub_modulus = unique.get_buffer();
                    self.crypto()
                        .encrypt(
                            Alg::OAEP,
                            Alg::from(new_name_alg),
                            pub_modulus,
                            &seed[..seed_len],
                            &mut encrypted_secret,
                            b"DUPLICATE\0",
                        )
                        .map_err(|_| TpmRc::FAILURE)?
                }
                _ => {
                    return Err(TpmRc::TYPE.with(Position::handle(2)));
                }
            };
            out_sym_seed = Tpm2bEncryptedSecret::from_bytes(&encrypted_secret[..enc_len])
                .map_err(|_| TpmRc::FAILURE)?;

            // Derive outer symmetric key/IV and integrity key using newParent nameAlg
            let mut sym_key_bits = match &new_parent_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, _) => {
                    parms.symmetric.map(|s| s.key_bits() as u32).unwrap_or(128)
                }
                OwnedPublicParmsAndId::Ecc(parms, _) => {
                    parms.symmetric.map(|s| s.key_bits() as u32).unwrap_or(128)
                }
                _ => 128,
            };
            if sym_key_bits == 0 {
                sym_key_bits = 128;
            }
            let outer_key_len = (sym_key_bits / 8) as usize;

            let mut sym_key_iv = [0u8; 48];
            let mut integrity_key = [0u8; 64];

            let new_digest_size = new_name_alg.digest_size();
            let new_bits = (new_digest_size * 8) as u32;
            kdfa(
                self.crypto(),
                new_name_alg,
                &seed[..seed_len],
                b"STORAGE",
                cmd.name.get_buffer(),
                &[],
                sym_key_bits,
                &mut sym_key_iv,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            kdfa(
                self.crypto(),
                new_name_alg,
                &seed[..seed_len],
                b"INTEGRITY",
                &[],
                &[],
                new_bits,
                &mut integrity_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;

            // Encrypt private_blob with outer key (CFB mode)
            let mut outer_key = [0u8; 32];
            outer_key[..outer_key_len].copy_from_slice(&sym_key_iv[..outer_key_len]);
            let mut outer_iv = [0u8; 16];

            let mut encrypted_inner = [0u8; 1024];
            encrypted_inner[..private_blob_len].copy_from_slice(&private_blob[..private_blob_len]);
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((outer_key_len * 8) as u16)
                .map_err(|_| TpmRc::FAILURE)?;
            tpm2::crypto::encrypt(
                self.crypto(),
                sym_alg,
                &outer_key[..outer_key_len],
                &mut outer_iv,
                &mut encrypted_inner[..private_blob_len],
            )
            .map_err(|_| TpmRc::FAILURE)?;

            // Compute outer HMAC over ciphertext + name
            let mut outer_mac = [0u8; 64];
            let mut hmac_ctx = tpm2::crypto::HmacCtx::new(
                self.crypto(),
                new_name_alg,
                &integrity_key[..new_digest_size],
            )
            .map_err(|_| TpmRc::FAILURE)?;
            hmac_ctx
                .update(&encrypted_inner[..private_blob_len])
                .map_err(|_| TpmRc::FAILURE)?;
            hmac_ctx
                .update(cmd.name.get_buffer())
                .map_err(|_| TpmRc::FAILURE)?;
            let res = hmac_ctx
                .finalize(&mut outer_mac)
                .map_err(|_| TpmRc::FAILURE)?;
            let outer_mac_len = res.digest().len();

            let mut offset = 0;
            final_duplicate[offset..offset + 2]
                .copy_from_slice(&(outer_mac_len as u16).to_be_bytes());
            offset += 2;
            final_duplicate[offset..offset + outer_mac_len]
                .copy_from_slice(&outer_mac[..outer_mac_len]);
            offset += outer_mac_len;
            final_duplicate[offset..offset + private_blob_len]
                .copy_from_slice(&encrypted_inner[..private_blob_len]);
            offset += private_blob_len;

            out_duplicate =
                Tpm2bPrivate::from_bytes(&final_duplicate[..offset]).map_err(|_| TpmRc::FAILURE)?;
        } else {
            out_sym_seed = Tpm2bEncryptedSecret::default();
            out_duplicate = Tpm2bPrivate::from_bytes(&private_blob[..private_blob_len])
                .map_err(|_| TpmRc::FAILURE)?;
        }

        let resp = responses::Rewrap {
            out_duplicate,
            out_sym_seed,
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &resp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
