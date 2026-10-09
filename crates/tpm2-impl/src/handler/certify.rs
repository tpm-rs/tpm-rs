use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedName, req_resp::RequestThenResponse};
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmGenerated;
use tpm2::commands::responses;
use tpm2::commands::{Certify, CertifyCreation, CertifyCreationHandles, CertifyHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bName, TpmsAttest, TpmsCertifyInfo, TpmsCreationInfo, TpmtSigScheme, TpmuAttest};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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

        let handles = request.try_unmarshal::<CertifyHandles>()?;
        let object_handle = handles.object_handle;
        let sign_handle = handles.sign_handle;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<Certify>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve certified object
        let certified_obj = self.resolve_object(object_handle.0, Position::handle(1))?;

        // 2. Resolve signer key
        let signer_obj_opt = if sign_handle.0 == 0x40000007 {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(2))?)
        };

        let _auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        // 3. Verify authorizations
        let expected_sessions = if sign_handle.0 == 0x40000007 { 1 } else { 2 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 4. IsSigningObject() (TPM_RC_KEY + RC_Certify_signHandle) and CryptSelectSignScheme()
        //    (TPM_RC_SCHEME + RC_Certify_inScheme).
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme = self.resolve_attest_scheme(
            public_opt,
            cmd.in_scheme,
            Position::handle(2),
            Position::parameter(2),
        )?;

        // 5. Construct attestation structure
        let header = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let dynamic_q_name = self.get_dynamic_qualified_name(&certified_obj);
        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer: header.qualified_signer,
            extra_data: header.extra_data,
            clock_info: header.clock_info,
            firmware_version: header.firmware_version,
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

        // 6. Sign the attestation payload
        if let Some(TpmtSigScheme::Ecdaa(ecdaa_s)) = actual_in_scheme
            && let Ok((digest_buf, digest_len)) =
                self.compute_hash(ecdaa_s.hash_alg, &[&attest_buf[..attest_len]])
        {
            let mut ecdaa_digest = [0u8; 128];
            let q_len = cmd.qualifying_data.get_buffer().len().min(64);
            ecdaa_digest[..q_len].copy_from_slice(&cmd.qualifying_data.get_buffer()[..q_len]);
            ecdaa_digest[q_len..q_len + digest_len].copy_from_slice(&digest_buf[..digest_len]);
            let dlen = (q_len + digest_len).min(64);
            self.global_state.debug_provided_auth[..dlen].copy_from_slice(&ecdaa_digest[..dlen]);
            self.global_state.debug_provided_auth_len = dlen;
        }
        let owned_sig = self.sign_attestation_block(
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            &attest_buf[..attest_len],
            cmd.qualifying_data.get_buffer(),
        )?;

        let rsp = responses::Certify {
            certify_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Computes the HMAC-SHA256 creation ticket digest.
    pub fn compute_creation_ticket(
        &self,
        hierarchy: u32,
        name: &OwnedName,
        creation_hash: &tpm2::Tpm2bDigest,
    ) -> Result<[u8; 32], TpmRc> {
        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy);
        let proof = &proof_bytes[..proof_len];

        let tag_bytes = 0x8021u16.to_be_bytes();
        let name_bytes = name.get_buffer();
        let hash_bytes = creation_hash.get_buffer();

        let mut hmac_ctx =
            tpm2::crypto::HmacCtx::new(self.crypto(), tpm2::TpmiAlgHash::Sha256, proof)
                .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx.update(&tag_bytes).map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx.update(name_bytes).map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx.update(hash_bytes).map_err(|_| TpmRc::FAILURE)?;

        let mut mac_buf = [0u8; 64];
        let mac = hmac_ctx
            .finalize(&mut mac_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(mac.digest());
        Ok(out)
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

        let handles = request.try_unmarshal::<CertifyCreationHandles>()?;
        let sign_handle = handles.sign_handle;
        let object_handle = handles.object_handle;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<CertifyCreation>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve certified object
        let certified_obj = self.resolve_object(object_handle.0, Position::handle(2))?;

        // 2. Resolve signer key
        let signer_obj_opt = if sign_handle.0 == 0x40000007 {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(1))?)
        };

        let _auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        // 3. Verify authorizations
        let expected_sessions = if sign_handle.0 == 0x40000007 { 0 } else { 1 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 4. IsSigningObject() (TPM_RC_KEY + RC_CertifyCreation_signHandle) and
        //    CryptSelectSignScheme() (TPM_RC_SCHEME + RC_CertifyCreation_inScheme), which the
        //    reference implementation checks before the creation ticket.
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme = self.resolve_attest_scheme(
            public_opt,
            cmd.in_scheme,
            Position::handle(1),
            Position::parameter(3),
        )?;

        // 5. Verify the creation ticket (`TicketComputeCreation`). The ticket is recomputed for the
        //    hierarchy named in the ticket itself; its tag and hierarchy value were already
        //    validated when unmarshaling `TPMT_TK_CREATION`.
        let expected_digest = self.compute_creation_ticket(
            cmd.creation_ticket.hierarchy().0,
            &certified_obj.name,
            &cmd.creation_hash,
        )?;
        if cmd.creation_ticket.digest().get_buffer() != expected_digest {
            return Err(TpmRc::TICKET.with(Position::parameter(4)));
        }

        // 6. Construct attestation structure
        let header = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer: header.qualified_signer,
            extra_data: header.extra_data,
            clock_info: header.clock_info,
            firmware_version: header.firmware_version,
            attested: TpmuAttest::Creation(TpmsCreationInfo {
                object_name: certified_obj.name.as_tpm2b(),
                creation_hash: cmd.creation_hash,
            }),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);

        // 7. Sign the attestation payload
        if let Some(TpmtSigScheme::Ecdaa(ecdaa_s)) = actual_in_scheme
            && let Ok((digest_buf, digest_len)) =
                self.compute_hash(ecdaa_s.hash_alg, &[&attest_buf[..attest_len]])
        {
            let mut ecdaa_digest = [0u8; 128];
            let q_len = cmd.qualifying_data.get_buffer().len().min(64);
            ecdaa_digest[..q_len].copy_from_slice(&cmd.qualifying_data.get_buffer()[..q_len]);
            ecdaa_digest[q_len..q_len + digest_len].copy_from_slice(&digest_buf[..digest_len]);
            let dlen = (q_len + digest_len).min(64);
            self.global_state.debug_provided_auth[..dlen].copy_from_slice(&ecdaa_digest[..dlen]);
            self.global_state.debug_provided_auth_len = dlen;
        }
        let owned_sig = self.sign_attestation_block(
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            &attest_buf[..attest_len],
            cmd.qualifying_data.get_buffer(),
        )?;

        let rsp = responses::CertifyCreation {
            certify_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
