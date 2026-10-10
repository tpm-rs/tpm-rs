use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
#[allow(deprecated)]
use tpm2::commands::{EncryptDecrypt, EncryptDecrypt2, responses};
use tpm2::crypto::{Direction, ModeIv, SymmetricKey};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, Tpm2bIv, Tpm2bMaxBuffer, TpmaObject, TpmiAlgCipherMode};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::EncryptDecrypt] (`0x164`) command.
    ///
    /// # Description
    /// This command is used to encrypt or decrypt data using a loaded symmetric key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.1 (TPM2_EncryptDecrypt).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be a loaded unrestricted symmetric key (created by [TpmCc::Create] or [TpmCc::CreatePrimary]).
    /// - For a similar command with different parameter layout, see [TpmCc::EncryptDecrypt2](encrypt_decrypt.rs).
    #[allow(deprecated)]
    pub fn encrypt_decrypt(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<EncryptDecrypt>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<EncryptDecrypt>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut out_data_buf = [0u8; Tpm2bMaxBuffer::CAP];
        let mut iv_buf = [0u8; Tpm2bIv::CAP];
        let (out_data, iv_out) = self.encrypt_decrypt_shared(
            key_handle,
            cmd.decrypt,
            cmd.mode,
            cmd.iv_in,
            cmd.in_data,
            Position::parameter(2), // decrypt is Pos1, mode is Pos2
            Position::parameter(3), // iv_in is Pos3
            Position::parameter(4), // in_data is Pos4
            &mut out_data_buf,
            &mut iv_buf,
        )?;

        let rsp = responses::EncryptDecrypt { out_data, iv_out };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::EncryptDecrypt2] (`0x193`) command.
    ///
    /// # Description
    /// This command performs the same symmetric encryption/decryption as [TpmCc::EncryptDecrypt]
    /// but has a different command/response parameter layout where the data block is the first parameter.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.2 (TPM2_EncryptDecrypt2).
    ///
    /// # Relationships
    /// - Behaves identically to [TpmCc::EncryptDecrypt](encrypt_decrypt.rs) in cryptographic actions.
    /// - Designed to allow parameter decryption of the data buffer in cases where the client wants to hide the plaintext message over the bus.
    pub fn encrypt_decrypt_2(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<EncryptDecrypt2>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<EncryptDecrypt2>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut out_data_buf = [0u8; Tpm2bMaxBuffer::CAP];
        let mut iv_buf = [0u8; Tpm2bIv::CAP];
        let (out_data, iv_out) = self.encrypt_decrypt_shared(
            key_handle,
            cmd.decrypt,
            cmd.mode,
            cmd.iv_in,
            cmd.in_data,
            Position::parameter(3), // in_data is Pos1, decrypt is Pos2, mode is Pos3
            Position::parameter(4), // iv_in is Pos4
            Position::parameter(1), // in_data is Pos1
            &mut out_data_buf,
            &mut iv_buf,
        )?;

        let rsp_2 = responses::EncryptDecrypt2 { out_data, iv_out };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp_2, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Shared implementation of [TpmCc::EncryptDecrypt] and [TpmCc::EncryptDecrypt2].
    ///
    /// Returns `(outData, ivOut)`, borrowed from `out_data_buf` and `iv_buf`.
    ///
    /// PORTING: returned exp's `responses::EncryptDecrypt` (deprecated in the new `tpm2` crate).
    #[allow(clippy::too_many_arguments)]
    fn encrypt_decrypt_shared<'c>(
        &mut self,
        key_handle: Handle,
        decrypt: bool,
        cmd_mode: Option<TpmiAlgCipherMode>,
        iv_in: Tpm2bIv<'_>,
        in_data: Tpm2bMaxBuffer<'_>,
        mode_pos: Position,
        iv_pos: Position,
        in_data_pos: Position,
        out_data_buf: &'c mut [u8; Tpm2bMaxBuffer::CAP],
        iv_buf: &'c mut [u8; Tpm2bIv::CAP],
    ) -> Result<(Tpm2bMaxBuffer<'c>, Tpm2bIv<'c>), TpmRc> {
        let sym_key = self.resolve_object(key_handle.0, Position::handle(1))?;

        let sym_def = match &sym_key.public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::Sym(sym_def, _) => *sym_def,
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };

        if sym_key
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        if decrypt {
            if !sym_key
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
            {
                return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
            }
        } else if !sym_key
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // The key's mode must be a cipher mode (or `TPM_ALG_NULL`), not `TPM_ALG_CMAC`.
        let key_mode = Option::<TpmiAlgCipherMode>::try_from(Alg::from(sym_def.mode))
            .map_err(|_| TpmRc::MODE.with(Position::handle(1)))?;

        let mode = match key_mode {
            Some(key_mode) => {
                if let Some(mode) = cmd_mode
                    && mode != key_mode
                {
                    return Err(TpmRc::MODE.with(mode_pos));
                }
                key_mode
            }
            None => cmd_mode.ok_or(TpmRc::MODE.with(mode_pos))?,
        };

        // PORTING: exp checked the IV size (`0` for ECB, the 16-byte block size otherwise) and
        // the CBC/ECB data alignment itself; these are now [`ModeIv::new`] and
        // [`ModeIv::is_valid_data_len`]. All symmetric algorithms (AES, SM4, Camellia) have a
        // 16-byte block, so exp's `TPM_RC_KEY` for other algorithms is unreachable.
        let iv_len = iv_in.as_slice().len();
        let iv = iv_buf.get_mut(..iv_len).ok_or(TpmRc::SIZE.with(iv_pos))?;
        iv.copy_from_slice(iv_in.as_slice());
        let mode_iv = ModeIv::new(mode, iv).ok_or(TpmRc::SIZE.with(iv_pos))?;

        let data_len = in_data.as_slice().len();
        if !mode_iv.is_valid_data_len(data_len) {
            return Err(TpmRc::SIZE.with(in_data_pos));
        }

        let data = out_data_buf.get_mut(..data_len).ok_or(TpmRc::FAILURE)?;
        data.copy_from_slice(in_data.as_slice());

        let key =
            SymmetricKey::new(sym_def.alg, sym_key.sensitive.as_bytes()).ok_or(TpmRc::FAILURE)?;
        let direction = if decrypt {
            Direction::Decrypt
        } else {
            Direction::Encrypt
        };
        tpm2::crypto::encrypt_decrypt(self.crypto(), key, mode_iv, direction, data)
            .map_err(|_| TpmRc::FAILURE)?;

        let out_data_buf: &'c [u8; Tpm2bMaxBuffer::CAP] = out_data_buf;
        let iv_buf: &'c [u8; Tpm2bIv::CAP] = iv_buf;
        let out_data = out_data_buf
            .get(..data_len)
            .and_then(Tpm2bMaxBuffer::new)
            .ok_or(TpmRc::FAILURE)?;
        let iv_out = iv_buf
            .get(..iv_len)
            .and_then(Tpm2bIv::new)
            .ok_or(TpmRc::FAILURE)?;

        Ok((out_data, iv_out))
    }
}
