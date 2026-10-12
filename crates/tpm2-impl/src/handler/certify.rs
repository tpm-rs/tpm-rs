use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedPublicParmsAndId, req_resp::RequestThenResponse};
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Certify, CertifyCreation, responses};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Ticket, Tpm2bName, TpmGenerated, TpmSt, TpmaObject, TpmsAttest, TpmsCertifyInfo,
    TpmsCreationInfo, TpmtSigScheme, TpmuAttest,
};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Certify] (`0x148`) command.
    ///
    /// # Description
    /// This command is used to prove the association between an object and a signing key.
    /// It generates an attestation signature over the Name and Qualified Name of the certified object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 18.1 (TPM2_Certify).
    ///
    /// # Relationships
    /// - The certified object (`object_handle`) must be created by [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs) and loaded.
    /// - The signing key (`sign_handle`) is used to sign the resulting attestation block.
    pub fn certify(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<Certify>()?;
        let [object_handle, sign_handle] = handles;
        check(object_handle, Tpmi::DhObject, Position::handle(1))?;
        check(sign_handle, Tpmi::DhObjectOrNull, Position::handle(2))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<Certify>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve certified object
        let certified_obj = self.resolve_object(object_handle.0, Position::handle(1))?;

        // 2. Resolve signer key
        let signer_obj_opt = if sign_handle == Handle::RH_NULL {
            None
        } else {
            let obj = self.resolve_object(sign_handle.0, Position::handle(2))?;
            if !obj
                .public
                .object_attributes
                .contains(TpmaObject::SIGN_ENCRYPT)
                || matches!(obj.public.parms_and_id, OwnedPublicParmsAndId::Sym(..))
            {
                return Err(TpmRc::KEY.to_rc());
            }
            Some(obj)
        };

        // 3. Verify authorizations
        let expected_sessions = if sign_handle == Handle::RH_NULL { 1 } else { 2 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 4. Construct attestation structure
        let clock_info = self.get_clock_info();

        // 5. Resolve signature scheme and verify consistency with public attributes
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt, cmd.in_scheme)?;

        let (qualified_signer, extra_data) = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let dynamic_q_name = self.get_dynamic_qualified_name(&certified_obj);
        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version: 0x00010001,
            attested: TpmuAttest::Certify(TpmsCertifyInfo {
                name: certified_obj.name.as_tpm2b(),
                qualified_name: if matches!(actual_in_scheme, Some(TpmtSigScheme::Ecdaa(_))) {
                    Tpm2bName::default()
                } else {
                    dynamic_q_name.as_tpm2b()
                },
            }),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);
        let attest_bytes = attest_buf.get(..attest_len).ok_or(TpmRc::FAILURE)?;

        // 6. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            attest_bytes,
            cmd.qualifying_data.as_slice(),
        )?;

        let rsp = responses::Certify {
            certify_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::CertifyCreation] (`0x14a`) command.
    ///
    /// # Description
    /// This command is used to prove that a specific object was created on this TPM with a particular
    /// set of creation parameters (represented by `creation_hash` and verified by `creation_ticket`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 18.2 (TPM2_CertifyCreation).
    ///
    /// # Relationships
    /// - Consumes a creation ticket produced during object creation by [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs).
    pub fn certify_creation(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<CertifyCreation>()?;
        let [sign_handle, object_handle] = handles;
        check(sign_handle, Tpmi::DhObjectOrNull, Position::handle(1))?;
        check(object_handle, Tpmi::DhObject, Position::handle(2))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<CertifyCreation>(handles)?;
        // PORTING: exp's typed `TPMT_TK_CREATION` unmarshal range-checked the ticket hierarchy
        // (`TPMI_RH_HIERARCHY+`).
        check(
            cmd.creation_ticket.hierarchy(),
            Tpmi::RhHierarchy,
            Position::parameter(4),
        )?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve certified object
        let certified_obj = self.resolve_object(object_handle.0, Position::handle(2))?;

        // 2. Resolve signer key
        let signer_obj_opt = if sign_handle == Handle::RH_NULL {
            None
        } else {
            let obj = self.resolve_object(sign_handle.0, Position::handle(1))?;
            if !obj
                .public
                .object_attributes
                .contains(TpmaObject::SIGN_ENCRYPT)
                || matches!(obj.public.parms_and_id, OwnedPublicParmsAndId::Sym(..))
            {
                return Err(TpmRc::KEY.to_rc());
            }
            Some(obj)
        };

        // 3. Verify ticket tag, hierarchy, and digest
        if cmd.creation_ticket.tag() != TpmSt::CREATION {
            return Err(TpmRc::TICKET.to_rc());
        }
        if cmd.creation_ticket.hierarchy().0 != certified_obj.hierarchy {
            return Err(TpmRc::TICKET.to_rc());
        }
        let expected_digest = self.compute_creation_ticket(
            certified_obj.hierarchy,
            &certified_obj.name,
            &cmd.creation_hash,
        )?;
        // PORTING: exp compared the ticket digest with `!=`; now constant time.
        if !crate::util::constant_time_eq(cmd.creation_ticket.digest().as_slice(), &expected_digest)
        {
            return Err(TpmRc::TICKET.to_rc());
        }

        // 4. Verify authorizations
        let expected_sessions = if sign_handle == Handle::RH_NULL { 0 } else { 1 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 5. Construct attestation structure
        let clock_info = self.get_clock_info();

        // 6. Resolve signature scheme and verify consistency with public attributes
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt, cmd.in_scheme)?;

        let (qualified_signer, extra_data) = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version: 0x00010001,
            attested: TpmuAttest::Creation(TpmsCreationInfo {
                object_name: certified_obj.name.as_tpm2b(),
                creation_hash: cmd.creation_hash,
            }),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);
        let attest_bytes = attest_buf.get(..attest_len).ok_or(TpmRc::FAILURE)?;

        // 7. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            attest_bytes,
            cmd.qualifying_data.as_slice(),
        )?;

        let rsp = responses::CertifyCreation {
            certify_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
