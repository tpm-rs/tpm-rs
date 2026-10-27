#[cfg(not(feature = "reference-rng"))]
use super::KeyDerivationArgs;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
#[cfg(not(feature = "reference-rng"))]
use tpm2::TpmaObject;
use tpm2::commands::Create;
use tpm2::commands::responses;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, Tpm2bDigest, Tpm2bName, TpmaLocality, TpmsCreationData, TpmtTkCreation};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::Create] (`0x18F`) command.
    ///
    /// # Description
    /// This command creates a child object (symmetric/asymmetric key or data object) under a designated parent key.
    /// It returns the public area (`out_public`) and an encrypted private area (`out_private`) representing the new key,
    /// along with creation data, creation hash, and a creation ticket.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.1 (TPM2_Create).
    ///
    /// # Relationships
    /// - The parent key (`parent_handle`) must be loaded in the TPM and have been created using [TpmCc::CreatePrimary](create_primary.rs)
    ///   or loaded using [TpmCc::Load](load.rs).
    /// - The output `out_private` and `out_public` can be loaded into the TPM using [TpmCc::Load](load.rs).
    /// - The creation ticket and creation hash can be certified using [TpmCc::CertifyCreation](certify.rs).
    pub fn create(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<Create>()?;
        let [parent_handle] = handles;
        check(parent_handle, Tpmi::DhObject, Position::handle(1))?;
        let parent_handle = parent_handle.0;

        if (0x40000000..=0x40FFFFFF).contains(&parent_handle) {
            // `parentHandle` is a `TPMI_DH_OBJECT`: permanent handles are invalid values.
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // The parameters are unmarshaled in order, with the TPM's profile, and the first error
        // is the response (TPM 2.0 Part 3, "Unmarshaling Errors": "When an error is encountered
        // while unmarshaling a command parameter, an error response code is returned, and no
        // command processing occurs."): e.g. reserved bits in `objectAttributes` are reported
        // before an invalid scheme in `parameters`, since `TPMT_PUBLIC` unmarshals `type`,
        // `nameAlg`, `objectAttributes`, `authPolicy` and `parameters` in that order (Part 2,
        // "Definition of TPMT_PUBLIC Structure").
        let cmd = request.try_unmarshal_command::<Create>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let in_sensitive_struct = cmd
            .in_sensitive
            .to_struct()
            .map_err(|e| e.in_parameter(1).to_rc())?;
        let raw_in_public_struct = cmd
            .in_public
            .to_struct()
            .map_err(|e| e.in_parameter(2).to_rc())?;
        let mut in_public_struct = crate::owned::OwnedPublic::from(raw_in_public_struct);

        // 1. Resolve parent object or hierarchy seed and parameters
        let mut parent_seed_val = [0u8; 64];
        let mut parent_qn_buf = [0u8; 66];
        let parent_info = self.resolve_parent_object_or_hierarchy(
            parent_handle,
            &mut parent_seed_val,
            &mut parent_qn_buf,
            false, // allow_derivation_parent
        )?;

        // A free object slot as scratch memory for the new object. TPM 2.0 Part 3, "Response
        // Code Details", TPM_RC_OBJECT_MEMORY: "This response code can be returned by any command
        // that causes the TPM to need an object 'slot'. [...] However, the TPM implementation is
        // allowed to use object slots for other reasons. In the Reference Code, the TPM copies a
        // referenced persistent object into RAM for the duration of the command. If all the slots
        // are previously occupied, the TPM may return this value. A TPM is allowed to use object
        // slots for other purposes and return this value." The specification leaves the slot use
        // of TPM2_Create to the implementation, so tpm-rs follows mstpm20, whose TPM2_Create takes
        // a free slot right after the parent check ("Get a slot for the creation":
        // `FindEmptyObjectSlot(NULL)`, else TPM_RC_OBJECT_MEMORY). The slot is only scratch
        // memory, so nothing is allocated; a persistent parent's RAM copy already counts in
        // `command_persistent_objects`.
        self.context.state.find_next_transient_handle()?;

        // 2. Validate template properties and attributes
        let (is_primary, is_derived) = self.validate_create_loaded_parameters(
            &in_public_struct.as_tpmt(),
            &in_sensitive_struct,
            parent_handle,
            parent_info.hierarchy_val,
            Some(parent_info.attributes),
            false,
            parent_info.scheme,
            false, // auth_size_first: after CreateChecks (C `Create.c`)
        )?;

        let name_alg = in_public_struct
            .name_alg
            .ok_or(TpmRc::HASH.with(Position::parameter(2)))?;
        if !crate::handler::capability::is_implemented_algorithm(tpm2::Alg::from(name_alg)) {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }

        let mut obj_seed = [0u8; 64];
        let mut actual_private_key = [0u8; 1536];
        // 3-4. Generate the seed, the key pair and the unique identifier. With `reference-rng`,
        // as the reference's `CryptCreateObject()` with the TPM's DRBG.
        #[cfg(feature = "reference-rng")]
        let (obj_seed_len, actual_private_key_len) = {
            let template = in_public_struct;
            self.reference_create_object(
                None,
                &template.as_tpmt(),
                in_sensitive_struct.data.get_buffer(),
                &mut in_public_struct.parms_and_id,
                &mut actual_private_key,
                &mut obj_seed,
            )?
        };
        #[cfg(not(feature = "reference-rng"))]
        let (obj_seed_len, actual_private_key_len) = {
            // 3. Derive/Generate the new object seed
            let obj_seed_len = self.derive_create_loaded_seed(
                is_primary,
                is_derived,
                &parent_seed_val[..parent_info.seed_len],
                parent_info.seed_len,
                &in_public_struct.as_tpmt(),
                &in_sensitive_struct,
                None,
                parent_info.name_alg,
                &mut obj_seed,
            )?;

            let gen_seed_arg = if is_primary || is_derived {
                Some(&obj_seed[..obj_seed_len])
            } else {
                None
            };

            // 4. Generate/Derive the key pairs and the unique identifier
            let is_sym_primary_or_derived = is_primary || is_derived;
            let get_random_fallback = !is_sym_primary_or_derived
                && (in_public_struct.object_attributes.0 & TpmaObject::SENSITIVE_DATA_ORIGIN.0)
                    != 0;
            let fallback_sensitive_data = if !is_sym_primary_or_derived
                && (in_public_struct.object_attributes.0 & TpmaObject::SENSITIVE_DATA_ORIGIN.0) == 0
            {
                Some(in_sensitive_struct.data.get_buffer())
            } else {
                None
            };
            let actual_private_key_len = self.generate_key_and_unique(
                name_alg,
                &mut in_public_struct.parms_and_id,
                KeyDerivationArgs {
                    gen_seed: gen_seed_arg,
                    obj_seed: &obj_seed[..obj_seed_len],
                    get_random_fallback,
                    fallback_sensitive_data,
                },
                &mut actual_private_key,
            )?;
            (obj_seed_len, actual_private_key_len)
        };

        let mut pub_buf = [0u8; tpm2::TpmtPublic::MAX_SIZE];
        let pub_len = in_public_struct.marshal(&mut pub_buf);
        let object_name = self.compute_name(in_public_struct.name_alg, &pub_buf[..pub_len])?;

        // 6. Build and encrypt the sensitive area (out_private)
        let mut private_buf = [0u8; 2048];
        let out_private = self.create_and_encrypt_private_area(
            &in_public_struct.as_tpmt(),
            &in_sensitive_struct,
            &actual_private_key[..actual_private_key_len],
            &obj_seed[..obj_seed_len],
            &parent_seed_val[..parent_info.seed_len],
            &object_name,
            is_primary,
            is_derived,
            parent_info.name_alg,
            parent_info.sym_bits,
            &mut private_buf,
        )?;

        let out_public = in_public_struct.as_tpm2b();

        // 7. Compute creation data and creation hash
        let parent_name = if parent_handle >> 24 == 0x80 {
            self.context
                .state
                .find_transient_object(parent_handle)
                .map(|obj| obj.name)
                .ok_or(TpmRc::REFERENCE_H0)?
        } else {
            self.context
                .load_persistent_object(parent_handle)
                .map(|obj| obj.name)
                .map_err(|_| TpmRc::REFERENCE_H0)?
        };
        let parent_qualified_name = Tpm2bName::from_bytes(&parent_qn_buf[..parent_info.qn_len])
            .map_err(|_| TpmRc::FAILURE)?;

        let pcr_digest = self.compute_pcr_digest(
            &cmd.creation_pcr,
            in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?,
        )?;

        let creation_data_struct = TpmsCreationData {
            // C `FillInCreationData`: the reported selection is the filtered one.
            pcr_select: self.filter_pcr_selection(&cmd.creation_pcr),
            pcr_digest: pcr_digest.as_tpm2b(),
            locality: TpmaLocality(if self.context.state.locality <= 4 {
                1 << self.context.state.locality
            } else {
                self.context.state.locality
            }),
            parent_name_alg: Alg::from(parent_info.name_alg),
            parent_name: parent_name.as_tpm2b(),
            parent_qualified_name,
            outside_info: cmd.outside_info,
        };

        let mut cd_buf = [0u8; TpmsCreationData::MAX_SIZE];
        let cd_len = creation_data_struct.marshal(&mut cd_buf);
        let creation_data = tpm2::Tpm2b(creation_data_struct);

        let (creation_hash_bytes, creation_hash_len) = self.compute_hash(
            in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?,
            &[&cd_buf[..cd_len]],
        )?;

        let creation_hash = Tpm2bDigest::from_bytes(&creation_hash_bytes[..creation_hash_len])
            .map_err(|_| TpmRc::FAILURE)?;

        let computed_digest =
            self.compute_creation_ticket(parent_info.hierarchy_val, &object_name, &creation_hash)?;
        let creation_ticket = TpmtTkCreation::Creation(
            Handle(parent_info.hierarchy_val),
            Tpm2bDigest::from_bytes(computed_digest.get_buffer()).unwrap(),
        );

        let rsp = responses::Create {
            out_private,
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
        };

        // 8. Write the response
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
