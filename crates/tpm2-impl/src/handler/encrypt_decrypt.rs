use bool;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{
    EncryptDecrypt, EncryptDecrypt2, EncryptDecrypt2Handles, EncryptDecryptHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, Tpm2bIv, Tpm2bMaxBuffer, TpmaObject, TpmiAlgCipherMode, TpmiAlgSymMode};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::crypto::{CryptoProvider, Rng};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::EncryptDecrypt] (`0x162`) command.
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
    pub fn encrypt_decrypt(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<EncryptDecryptHandles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<EncryptDecrypt>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut out_data_buf = [0u8; 1024];
        let mut iv_buf = [0u8; 16];
        let rsp = self.encrypt_decrypt_shared(
            handles.key_handle,
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
        let handles = request.try_unmarshal::<EncryptDecrypt2Handles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<EncryptDecrypt2>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut out_data_buf = [0u8; 1024];
        let mut iv_buf = [0u8; 16];
        let rsp = self.encrypt_decrypt_shared(
            handles.key_handle,
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

        let rsp_2 = responses::EncryptDecrypt2 {
            out_data: rsp.out_data,
            iv_out: rsp.iv_out,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp_2, &session_responses[..num_sessions])?;
        Ok(())
    }

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
        out_data_buf: &'c mut [u8; 1024],
        iv_buf: &'c mut [u8; 16],
    ) -> Result<responses::EncryptDecrypt<'c>, TpmRc> {
        let sym_key = self.resolve_object(key_handle.0, Position::handle(1))?;

        let sym_def = match &sym_key.public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::Sym(sym_def, _) => sym_def,
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };

        if sym_key
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        if (decrypt as u8) != 0 {
            if !sym_key
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
            {
                return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
            }
        } else {
            if !sym_key
                .public
                .object_attributes
                .contains(TpmaObject::SIGN_ENCRYPT)
            {
                return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
            }
        }

        let key_alg = sym_def.algorithm();
        let mut key_mode = Alg::from(sym_def.mode());
        let _key_bits = sym_def.key_bits();

        if Option::<TpmiAlgCipherMode>::try_from(key_mode).is_err() {
            return Err(TpmRc::MODE.with(Position::handle(1)));
        }

        let cmd_mode_opt = cmd_mode;
        if key_mode != Alg::NULL {
            if let Some(mode) = cmd_mode_opt
                && Alg::from(Some(mode)) != key_mode
            {
                return Err(TpmRc::MODE.with(mode_pos));
            }
        } else {
            match cmd_mode_opt {
                None => return Err(TpmRc::MODE.with(mode_pos)),
                Some(mode) => {
                    key_mode = Alg::from(Some(mode));
                }
            }
        }

        let block_size = match key_alg {
            Alg::AES | Alg::SM4 | Alg::CAMELLIA => 16,
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };

        let iv_len = iv_in.get_size() as usize;
        if (key_mode == Alg::ECB && iv_len != 0) || (key_mode != Alg::ECB && iv_len != block_size) {
            return Err(TpmRc::SIZE.with(iv_pos));
        }

        let data_len = in_data.get_size() as usize;
        if (key_mode == Alg::CBC || key_mode == Alg::ECB) && !data_len.is_multiple_of(block_size) {
            return Err(TpmRc::SIZE.with(in_data_pos));
        }

        out_data_buf[..data_len].copy_from_slice(in_data.get_buffer());

        if iv_len > 0 {
            iv_buf[..iv_len].copy_from_slice(iv_in.get_buffer());
        }

        let sym_alg =
            sym_def.with_mode(Option::<TpmiAlgSymMode>::try_from(key_mode).ok().flatten());
        tpm2::crypto::encrypt_decrypt(
            self.crypto(),
            sym_alg,
            &sym_key.private[..sym_key.private_len],
            &mut iv_buf[..iv_len],
            (decrypt as u8) != 0,
            &mut out_data_buf[..data_len],
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let out_data =
            Tpm2bMaxBuffer::from_bytes(&out_data_buf[..data_len]).map_err(|_| TpmRc::FAILURE)?;
        let iv_out = Tpm2bIv::from_bytes(&iv_buf[..iv_len]).map_err(|_| TpmRc::FAILURE)?;

        Ok(responses::EncryptDecrypt { out_data, iv_out })
    }
}
