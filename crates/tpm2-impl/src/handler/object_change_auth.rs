#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{ObjectChangeAuth, ObjectChangeAuthHandles};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bPrivate, Tpm2bPrivateKeyRsa,
    Tpm2bSensitiveData, Tpm2bSymKey, TpmtSensitive, TpmuSensitiveComposite,
};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::crypto::{CryptoProvider, Rng};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ObjectChangeAuth] (`0x14C`) command.
    ///
    /// # Description
    /// This command changes the authorization value of a transient object without modifying its key material or public area.
    /// It returns a new encrypted private area (`out_private`) containing the updated authorization value.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.8 (TPM2_ObjectChangeAuth).
    ///
    /// # Relationships
    /// - The target object (`object_handle`) must be a transient object.
    /// - The parent key (`parent_handle`) must be the loaded parent of the target object.
    /// - The output `out_private` must be loaded using [TpmCc::Load](load.rs)
    ///   for the new authorization value to take effect.
    pub fn object_change_auth(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<ObjectChangeAuthHandles>()?;
        let object_handle = handles.object_handle.0;
        let parent_handle = handles.parent_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<ObjectChangeAuth>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Enforce that target object handle is transient
        if (object_handle >> 24) == 0x81 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        if (object_handle >> 24) != 0x80 {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }

        // Ensure target object is not an active sequence
        if self.state().find_active_sequence(object_handle).is_some() {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }

        // Resolve target object
        let object = self.resolve_object(object_handle, Position::handle(1))?;

        // Resolve parent object or hierarchy seed and parameters
        let mut parent_seed_val = [0u8; 64];
        let mut parent_qn_buf = [0u8; 66];
        let parent_info = self
            .resolve_parent_object_or_hierarchy(
                parent_handle,
                &mut parent_seed_val,
                &mut parent_qn_buf,
                true, // expect_type_error
            )
            .map_err(|err| {
                if err == TpmRc::ATTRIBUTES.with(Position::handle(1)) {
                    TpmRc::ATTRIBUTES.with(Position::handle(2))
                } else {
                    err
                }
            })?;

        // Validate that parent is the correct parent by QN comparison
        let qn_compare = self.compute_qualified_name(
            object.public.name_alg,
            &parent_qn_buf[..parent_info.qn_len],
            object.name.get_buffer(),
        )?;
        let obj_dyn_qn = self.get_dynamic_qualified_name(&object);
        if qn_compare.get_buffer() != obj_dyn_qn.get_buffer() {
            return Err(TpmRc::TYPE.with(Position::handle(2)));
        }

        // Adjust authorization secret size
        let digest_size = object
            .public
            .name_alg
            .ok_or(TpmRc::HASH.to_rc())?
            .digest_size();
        let new_auth_slice = cmd.new_auth.get_buffer();
        let stripped = crate::util::strip_trailing_zeros(new_auth_slice);
        if stripped.len() > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        let mut adjusted_auth = [0u8; 64];
        adjusted_auth[..stripped.len()].copy_from_slice(stripped);
        let new_auth_padded =
            Tpm2bAuth::from_bytes(&adjusted_auth[..digest_size]).map_err(|_| TpmRc::FAILURE)?;

        // Construct new TpmtSensitive
        let mut prime_p = [0u8; 256];
        let sensitive_comp = match &object.public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::Ecc(_, _) => TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::from_bytes(&object.private[..object.private_len])
                    .map_err(|_| TpmRc::FAILURE)?,
            ),
            crate::owned::OwnedPublicParmsAndId::Rsa(_, _) => {
                let prime_p_len = self
                    .crypto()
                    .rsa_private_key_to_prime_p(&object.private[..object.private_len], &mut prime_p)
                    .map_err(|_| TpmRc::FAILURE)?;
                TpmuSensitiveComposite::Rsa(
                    Tpm2bPrivateKeyRsa::from_bytes(&prime_p[..prime_p_len])
                        .map_err(|_| TpmRc::FAILURE)?,
                )
            }
            crate::owned::OwnedPublicParmsAndId::KeyedHash(_, _) => {
                TpmuSensitiveComposite::KeyedHash(
                    Tpm2bSensitiveData::from_bytes(&object.private[..object.private_len])
                        .map_err(|_| TpmRc::FAILURE)?,
                )
            }
            crate::owned::OwnedPublicParmsAndId::Sym(_, _) => TpmuSensitiveComposite::Sym(
                Tpm2bSymKey::from_bytes(&object.private[..object.private_len])
                    .map_err(|_| TpmRc::FAILURE)?,
            ),
            crate::owned::OwnedPublicParmsAndId::Mldsa(_, _) => TpmuSensitiveComposite::Mldsa(
                tpm2::Tpm2bPrivateKeyMldsa::from_bytes(&object.private[..object.private_len])
                    .map_err(|_| TpmRc::FAILURE)?,
            ),
            crate::owned::OwnedPublicParmsAndId::HashMldsa(_, _) => {
                TpmuSensitiveComposite::HashMldsa(
                    tpm2::Tpm2bPrivateKeyMldsa::from_bytes(&object.private[..object.private_len])
                        .map_err(|_| TpmRc::FAILURE)?,
                )
            }
            crate::owned::OwnedPublicParmsAndId::Mlkem(_, _) => TpmuSensitiveComposite::Mlkem(
                tpm2::Tpm2bPrivateKeyMlkem::from_bytes(&object.private[..object.private_len])
                    .map_err(|_| TpmRc::FAILURE)?,
            ),
        };

        let tpmt_sensitive = TpmtSensitive {
            auth_value: new_auth_padded,
            seed_value: Tpm2bDigest::from_bytes(&object.seed).map_err(|_| TpmRc::FAILURE)?,
            sensitive: sensitive_comp,
        };

        // Encrypt the sensitive area using parent seed and name algorithm
        let mut private_buf = [0u8; 2048];
        let encrypted_len = self.encrypt_sensitive_area(
            &tpmt_sensitive,
            &parent_seed_val[..parent_info.seed_len],
            &object.name,
            parent_info.name_alg,
            parent_info.sym_bits,
            &mut private_buf,
        )?;

        let out_private =
            Tpm2bPrivate::from_bytes(&private_buf[..encrypted_len]).map_err(|_| TpmRc::FAILURE)?;
        let rsp = responses::ObjectChangeAuth { out_private };

        // Write the response
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
