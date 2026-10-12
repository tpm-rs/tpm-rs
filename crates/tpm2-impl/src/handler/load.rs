use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::handler::object_helpers::null_name_alg_error;
use crate::owned::{OwnedAuth, OwnedDigest, OwnedName, OwnedPublic};
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::commands::{Load, responses};
use tpm2::crypto::{HmacStream, ModeIv, SymmetricKey, decrypt, kdfa};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Handle, Marshal, Tpm2bName, Tpm2bPrivate, TpmHt, TpmaObject, TpmiAlgHash,
    TpmtPublic, TpmtSensitive,
};

/// Size of the buffer the private area is decrypted into.
///
/// The sensitive area is unmarshaled from the decrypted data *and the zeros after it* (exp
/// decrypted into a zeroed 2048-byte buffer). This size keeps at least
/// `TpmtSensitive::MAX_SIZE` zero bytes after the largest encrypted area, so the unmarshal
/// never reaches the end of the buffer, exactly as with exp's buffer.
const DECRYPT_BUFFER_SIZE: usize = Tpm2bPrivate::CAP + TpmtSensitive::MAX_SIZE;

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Load] (`0x157`) command.
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

        let [parent] = request.try_unmarshal_handles::<Load>()?;
        check(parent, Tpmi::DhObject, Position::handle(1))?;
        let parent_handle = parent.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        if let Some(rc) =
            null_name_alg_error::<Tpm2bPrivate>(request.remaining_slice(), Position::parameter(2))
        {
            return Err(rc);
        }
        let cmd = request.try_unmarshal_command::<Load>([parent])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let public_struct = cmd.in_public.0;

        if Handle(parent_handle).handle_type() != Some(TpmHt::Transient)
            && Handle(parent_handle).handle_type() != Some(TpmHt::Persistent)
        {
            return Err(TpmRc::HANDLE.with(Position::handle(1)));
        }

        if cmd.in_private.as_slice().is_empty() {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // 1. Resolve parent object or hierarchy seed and parameters.
        let mut parent_seed_val = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mut parent_qn_buf = [0u8; Tpm2bName::CAP];
        let parent_info = self.resolve_parent_object_or_hierarchy(
            parent_handle,
            &mut parent_seed_val,
            &mut parent_qn_buf,
            true, // expect_type_error
        )?;

        self.validate_object_attributes(
            &public_struct,
            parent_handle,
            parent_info.hierarchy_val,
            Some(parent_info.attributes),
            false, // is_import
            false, // allow_null_name_alg
            Position::parameter(2),
        )?;
        self.validate_public_parameters(&public_struct, false)?;

        // 2. Compute object name.
        let name_alg = public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        if !matches!(
            name_alg,
            TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
        ) {
            return Err(TpmRc::VALUE.to_rc());
        }

        let mut pub_buf = [0u8; TpmtPublic::MAX_SIZE];
        let pub_len = public_struct.marshal(&mut pub_buf);
        let object_name = self.compute_name(public_struct.name_alg, &pub_buf[..pub_len])?;

        // 3. Decrypt and verify the sensitive area.
        let mut decrypted_blob = [0u8; DECRYPT_BUFFER_SIZE];
        let sensitive_struct = self.decrypt_and_verify_private_area(
            &cmd.in_private,
            &parent_seed_val[..parent_info.seed_len],
            parent_info.name_alg,
            parent_info.sym_bits,
            &object_name,
            &mut decrypted_blob,
        )?;

        // 4. Validate public-private key consistency and import the private key.
        let sensitive = self.validate_and_import_sensitive(
            &public_struct,
            &sensitive_struct,
            Position::parameter(1),
            Position::parameter(2),
            false,
        )?;

        // 5. Compute qualified name.
        let qualified_name = self.compute_qualified_name(
            public_struct.name_alg,
            &parent_qn_buf[..parent_info.qn_len],
            object_name.get_buffer(),
        )?;

        // Allocate transient object slot.
        let (index, handle) = self.global_state.find_empty_transient_slot(false)?;

        let rsp = responses::Load {
            object_handle: Handle(handle),
            name: object_name.as_tpm2b(),
        };

        // 6. Write the response.
        let response = request.into_response();
        self.write_response_all(
            response,
            &rsp.object_handle,
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
            OwnedDigest::from(sensitive_struct.seed_value),
            object_name,
            OwnedAuth::from(sensitive_struct.auth_value),
            OwnedPublic::from(public_struct),
            sensitive,
            qualified_name,
            Some(parent_handle),
            parent_info.hierarchy_val,
            parent_info.has_st_clear || st_clear,
        );

        Ok(())
    }

    /// Decrypts the sensitive area of the private blob using storage seed, verifies integrity HMAC.
    ///
    /// Expects exp's private blob format (see `encrypt_sensitive_area`).
    fn decrypt_and_verify_private_area<'c>(
        &self,
        in_private: &Tpm2bPrivate<'_>,
        parent_seed_val: &[u8],
        parent_name_alg: TpmiAlgHash,
        sym_key_bits: u16,
        object_name: &OwnedName,
        decrypted_blob: &'c mut [u8; DECRYPT_BUFFER_SIZE],
    ) -> Result<TpmtSensitive<'c>, TpmRc> {
        let size_err = TpmRc::SIZE.to_rc();
        let read_u16 = |bytes: &[u8]| -> Option<usize> {
            bytes
                .first_chunk::<2>()
                .map(|b| usize::from(u16::from_be_bytes(*b)))
        };

        let private_bytes = in_private.as_slice();
        let mac_len = read_u16(private_bytes).ok_or(size_err)?;
        let mac_bytes = private_bytes.get(2..2 + mac_len).ok_or(size_err)?;
        let iv_and_enc = &private_bytes[2 + mac_len..];

        // 1. Verify integrity HMAC
        let parent_digest_size = parent_name_alg.digest_size();
        let mut integrity_key_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let integrity_key = integrity_key_buf
            .get_mut(..parent_digest_size)
            .ok_or(TpmRc::FAILURE)?;
        kdfa(
            self.crypto(),
            parent_name_alg,
            parent_seed_val,
            c"INTEGRITY",
            &[],
            &[],
            integrity_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let mut hmac_ctx = HmacStream::new(self.crypto(), parent_name_alg, integrity_key)
            .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx.update(iv_and_enc).map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(object_name.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        let mut computed_mac_bytes = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let computed_mac = hmac_ctx
            .finalize(&mut computed_mac_bytes)
            .map_err(|_| TpmRc::FAILURE)?;

        if !crate::util::constant_time_eq(computed_mac.digest(), mac_bytes) {
            return Err(TpmRc::INTEGRITY.to_rc());
        }

        // 2. Extract IV and decrypt the blob
        let iv_len = read_u16(iv_and_enc).ok_or(size_err)?;
        if iv_and_enc.len() < 2 + iv_len || iv_len != AlgSym::BLOCK_SIZE {
            return Err(size_err);
        }
        let (iv, encrypted_blob) = iv_and_enc[2..]
            .split_first_chunk::<{ AlgSym::BLOCK_SIZE }>()
            .ok_or(size_err)?;
        let mut iv = *iv;

        let mut sym_key_buf = [0u8; AlgSym::MAX_KEY_BYTES];
        let sym_key_len = usize::from(sym_key_bits / 8);
        let sym_key = sym_key_buf.get_mut(..sym_key_len).ok_or(TpmRc::FAILURE)?;
        kdfa(
            self.crypto(),
            parent_name_alg,
            parent_seed_val,
            c"STORAGE",
            object_name.get_buffer(),
            &[],
            sym_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let sym_key: &[u8] = sym_key;

        let decrypted = decrypted_blob
            .get_mut(..encrypted_blob.len())
            .ok_or(size_err)?;
        decrypted.copy_from_slice(encrypted_blob);

        // exp always used AES-CFB with the parent's symmetric key size.
        let key = AlgSym::new(Alg::AES, sym_key_bits)
            .and_then(|alg| SymmetricKey::new(alg, sym_key))
            .ok_or(TpmRc::FAILURE)?;
        decrypt(self.crypto(), key, ModeIv::Cfb(&mut iv), decrypted).map_err(|_| TpmRc::FAILURE)?;

        // 3. Parse decrypted sensitive structure
        let decrypted_blob: &'c [u8; DECRYPT_BUFFER_SIZE] = decrypted_blob;
        let inner_integrity_len = read_u16(decrypted_blob).ok_or(size_err)?;
        let sensitive_offset = 2 + inner_integrity_len;
        if sensitive_offset > encrypted_blob.len() {
            return Err(size_err);
        }

        let mut sensitive_bytes = decrypted_blob.get(sensitive_offset..).ok_or(size_err)?;
        TpmtSensitive::unmarshal(&mut sensitive_bytes).map_err(|_| size_err)
    }
}
