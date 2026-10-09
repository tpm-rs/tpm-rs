use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use tpm2::Handle;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::commands::responses;
use tpm2::commands::{Load, LoadHandles, LoadRespHandles};
use tpm2::errors::{Position, TpmRc};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::{Tpm2bPrivate, TpmaObject, TpmiAlgHash, TpmtSensitive};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::Load] (`0x12C`) command.
    ///
    /// # Description
    /// This command loads a child key (or data object) into the TPM's volatile memory, making it available for cryptographic operations.
    /// It decrypts and validates the encrypted private area using the parent key's storage seed.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.2 (TPM2_Load).
    ///
    /// # Relationships
    /// - Loads objects created by [TpmCc::Create](create.rs)
    ///   or imported by [TpmCc::Import](import.rs).
    /// - The parent key (`parent_handle`) must be loaded in the TPM (e.g. via [TpmCc::CreatePrimary](create_primary.rs) or a prior [TpmCc::Load]).
    /// - Returns a transient handle that can be passed to cryptographic commands like [TpmCc::Sign](crypt_ops.rs).
    pub fn load(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<LoadHandles>()?;
        let parent_handle = handles.parent_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<Load>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let public_struct = cmd
            .in_public
            .to_struct()
            .map_err(|e| e.in_parameter(2).to_rc())?;

        // C `Load.c` order: free object slot, empty inPrivate, parent type, Name (nameAlg),
        // private-area unwrap, then `ObjectLoad` (public area validation and key checks).
        let (index, handle) = self.global_state.find_empty_transient_slot(false)?;

        if (parent_handle >> 24) != 0x80 && (parent_handle >> 24) != 0x81 {
            // `parentHandle` is a `TPMI_DH_OBJECT`: permanent handles are invalid values.
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        if cmd.in_private.get_size() == 0 {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // 1. Resolve parent object or hierarchy seed and parameters.
        let mut parent_seed_val = [0u8; 64];
        let mut parent_qn_buf = [0u8; 66];
        let parent_info = self.resolve_parent_object_or_hierarchy(
            parent_handle,
            &mut parent_seed_val,
            &mut parent_qn_buf,
            false, // allow_derivation_parent
        )?;

        // 2. Compute object name.
        let name_alg = public_struct
            .name_alg
            .ok_or(TpmRc::HASH.with(Position::parameter(2)))?;
        if name_alg != TpmiAlgHash::Sha1
            && name_alg != TpmiAlgHash::Sha256
            && name_alg != TpmiAlgHash::Sha384
            && name_alg != TpmiAlgHash::Sha512
        {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }

        let mut pub_buf = [0u8; tpm2::TpmtPublic::MAX_SIZE];
        let pub_len = public_struct.marshal(&mut pub_buf);
        let object_name = self.compute_name(public_struct.name_alg, &pub_buf[..pub_len])?;

        // 3. Decrypt and verify the sensitive area.
        let mut decrypted_blob = [0u8; 2048];
        let sensitive_struct = self.decrypt_and_verify_private_area(
            &cmd.in_private,
            &parent_seed_val[..parent_info.seed_len],
            parent_info.name_alg,
            parent_info.sym_bits,
            &object_name,
            &mut decrypted_blob,
        )?;

        self.validate_object_attributes(
            &public_struct,
            parent_handle,
            parent_info.hierarchy_val,
            Some(parent_info.attributes),
            false, // is_import
            false, // allow_null_name_alg
            Position::parameter(2),
            parent_info.scheme,
        )?;
        // 4. Validate public-private key consistency and import the private key. C ObjectLoad
        // skips CryptValidateKeys when the parent is fixedTPM (this TPM produced the blob).
        let mut actual_private_key = [0u8; 1536];
        let actual_private_key_len = if parent_info.attributes.contains(TpmaObject::FIXED_TPM) {
            self.import_sensitive_unvalidated(
                &public_struct,
                &sensitive_struct,
                &mut actual_private_key,
                Position::parameter(1),
            )?
        } else {
            self.validate_public_parameters(&public_struct, false)?;
            self.validate_and_import_sensitive(
                &public_struct,
                &sensitive_struct,
                &mut actual_private_key,
                Position::parameter(1),
                Position::parameter(2),
                false,
            )?
        };

        // 5. Compute qualified name.
        let qualified_name = self.compute_qualified_name(
            public_struct.name_alg,
            &parent_qn_buf[..parent_info.qn_len],
            object_name.get_buffer(),
        )?;

        let resp_handles = LoadRespHandles {
            object_handle: Handle(handle),
        };
        let rsp = responses::Load {
            name: object_name.as_tpm2b(),
        };

        // 6. Write the response.
        let response = request.into_response();
        self.write_response_all(
            response,
            &resp_handles,
            &rsp,
            &session_responses[..num_sessions],
        )?;

        // 7. Store the transient object.
        let st_clear = public_struct
            .object_attributes
            .contains(TpmaObject::ST_CLEAR);
        self.store_transient_object(
            index,
            handle,
            sensitive_struct.seed_value.get_buffer(),
            object_name,
            crate::owned::OwnedAuth::from(sensitive_struct.auth_value),
            crate::owned::OwnedPublic::from(public_struct),
            actual_private_key,
            actual_private_key_len,
            qualified_name,
            Some(parent_handle),
            parent_info.hierarchy_val,
            parent_info.has_st_clear || st_clear,
        );

        Ok(())
    }

    /// Decrypts the sensitive area of the private blob using storage seed, verifies integrity HMAC.
    fn decrypt_and_verify_private_area<'c>(
        &self,
        in_private: &Tpm2bPrivate<'_>,
        parent_seed_val: &[u8],
        parent_name_alg: TpmiAlgHash,
        sym_key_bits: u32,
        object_name: &crate::owned::OwnedName,
        decrypted_blob: &'c mut [u8; 2048],
    ) -> Result<TpmtSensitive<'c>, TpmRc> {
        // UnwrapOuter: errors unmarshaling the outer integrity `TPM2B_DIGEST` / `TPM2B_IV` are
        // returned with `RC_Load_inPrivate` (`RcSafeAddToResult` in `Load.c`).
        let private_bytes = in_private.get_buffer();
        if private_bytes.len() < 2 {
            return Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)));
        }

        let mac_len = u16::from_be_bytes([private_bytes[0], private_bytes[1]]) as usize;
        if mac_len > 64 {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        if private_bytes.len() < 2 + mac_len {
            return Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)));
        }
        let mac_bytes = &private_bytes[2..2 + mac_len];
        let iv_and_enc = &private_bytes[2 + mac_len..];

        // 1. Verify integrity HMAC
        let mut integrity_key = [0u8; 64];
        let mut computed_mac_bytes = [0u8; 64];

        let parent_digest_size = parent_name_alg.digest_size();
        let parent_bits = (parent_digest_size * 8) as u32;
        kdfa(
            self.crypto(),
            parent_name_alg,
            parent_seed_val,
            b"INTEGRITY",
            &[],
            &[],
            parent_bits,
            &mut integrity_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let mut hmac_ctx = tpm2::crypto::HmacCtx::new(
            self.crypto(),
            parent_name_alg,
            &integrity_key[..parent_digest_size],
        )
        .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx.update(iv_and_enc).map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(object_name.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        let hmac_res = hmac_ctx
            .finalize(&mut computed_mac_bytes)
            .map_err(|_| TpmRc::FAILURE)?;
        let computed_mac_len = hmac_res.digest().len();

        if computed_mac_bytes[..computed_mac_len] != *mac_bytes {
            return Err(TpmRc::INTEGRITY.with(Position::parameter(1)));
        }

        // 2. Extract IV and decrypt the blob
        if iv_and_enc.len() < 2 {
            return Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)));
        }
        let iv_len = u16::from_be_bytes([iv_and_enc[0], iv_and_enc[1]]) as usize;
        if iv_len > 16 {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        if iv_and_enc.len() < 2 + iv_len {
            return Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)));
        }
        if iv_len != 16 {
            return Err(TpmRc::SENSITIVE);
        }
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_and_enc[2..18]);
        let encrypted_blob = &iv_and_enc[18..];

        let mut sym_key_buf = [0u8; 32];
        let sym_key_len = (sym_key_bits / 8) as usize;
        kdfa(
            self.crypto(),
            parent_name_alg,
            parent_seed_val,
            b"STORAGE",
            object_name.get_buffer(),
            &[],
            sym_key_bits,
            &mut sym_key_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        if encrypted_blob.len() > 2048 {
            return Err(TpmRc::SIZE.to_rc());
        }
        decrypted_blob[..encrypted_blob.len()].copy_from_slice(encrypted_blob);

        let sym_alg =
            tpm2::TpmtSymDefObject::aes_cfb(sym_key_bits as u16).map_err(|_| TpmRc::FAILURE)?;
        tpm2::crypto::decrypt(
            self.crypto(),
            sym_alg,
            &sym_key_buf[..sym_key_len],
            &mut iv,
            &mut decrypted_blob[..encrypted_blob.len()],
        )
        .map_err(|_| TpmRc::FAILURE)?;

        // 3. Parse the decrypted `TPM2B_SENSITIVE` (C `PrivateToSensitive`): its 2-byte size
        // must account for exactly the rest of the decrypted data and the `TPMT_SENSITIVE`
        // must unmarshal completely; otherwise `TPM_RC_SENSITIVE`.
        let dec_len = encrypted_blob.len();
        if dec_len < 2 {
            return Err(TpmRc::SENSITIVE);
        }
        let sensitive_size = u16::from_be_bytes([decrypted_blob[0], decrypted_blob[1]]) as usize;
        if 2 + sensitive_size != dec_len {
            return Err(TpmRc::SENSITIVE);
        }
        let mut slice = &decrypted_blob[2..dec_len];
        let sensitive_struct =
            TpmtSensitive::unmarshal(&mut slice).map_err(|_| TpmRc::SENSITIVE)?;
        if !slice.is_empty() {
            return Err(TpmRc::SENSITIVE);
        }

        Ok(sensitive_struct)
    }
}
