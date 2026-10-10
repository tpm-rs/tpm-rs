#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{ObjectChangeAuth, responses};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bPrivate, TpmHt, TpmiAlgHash, TpmtSensitive};

use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::ObjectChangeAuth] (`0x150`) command.
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

        let [object, parent] = request.try_unmarshal_handles::<ObjectChangeAuth>()?;
        check(object, Tpmi::DhObject, Position::handle(1))?;
        check(parent, Tpmi::DhObject, Position::handle(2))?;
        let object_handle = object.0;
        let parent_handle = parent.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<ObjectChangeAuth>([object, parent])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Enforce that target object handle is transient
        if object.handle_type() == Some(TpmHt::Persistent) {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        if object.handle_type() != Some(TpmHt::Transient) {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }

        // Ensure target object is not an active sequence
        if self.state().find_active_sequence(object_handle).is_some() {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }

        // Resolve target object
        let object = self.resolve_object(object_handle, Position::handle(1))?;

        // Resolve parent object or hierarchy seed and parameters
        let mut parent_seed_val = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mut parent_qn_buf = [0u8; Tpm2bName::CAP];
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
        let stripped = crate::util::strip_trailing_zeros(cmd.new_auth.as_slice());
        if stripped.len() > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        let mut adjusted_auth = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        adjusted_auth
            .get_mut(..stripped.len())
            .ok_or(TpmRc::FAILURE)?
            .copy_from_slice(stripped);
        let new_auth_padded = adjusted_auth
            .get(..digest_size)
            .and_then(Tpm2bAuth::new)
            .ok_or(TpmRc::FAILURE)?;

        // Construct new TpmtSensitive
        // PORTING: exp rebuilt the `TPMU_SENSITIVE_COMPOSITE` from the crypto provider's private
        // key blob (extracting the first RSA prime); the object now stores it directly.
        let tpmt_sensitive = TpmtSensitive {
            auth_value: new_auth_padded,
            seed_value: Tpm2bDigest::new(&object.seed).ok_or(TpmRc::FAILURE)?,
            sensitive: object.sensitive.as_tpmu(),
        };

        // Encrypt the sensitive area using parent seed and name algorithm
        let mut private_buf = [0u8; Tpm2bPrivate::CAP];
        let encrypted_len = self.encrypt_sensitive_area(
            &tpmt_sensitive,
            &parent_seed_val[..parent_info.seed_len],
            &object.name,
            parent_info.name_alg,
            parent_info.sym_bits,
            &mut private_buf,
        )?;

        let out_private = private_buf
            .get(..encrypted_len)
            .and_then(Tpm2bPrivate::new)
            .ok_or(TpmRc::FAILURE)?;
        let rsp = responses::ObjectChangeAuth { out_private };

        // Write the response
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
