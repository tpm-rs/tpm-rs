use super::KeyDerivationArgs;
use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::object_helpers::null_name_alg_error;
use crate::owned::OwnedPublic;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Create, responses};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Handle, Marshal, Tpm2b, Tpm2bDigest, Tpm2bName, Tpm2bPrivate, Tpm2bSensitiveCreate, TpmHt,
    TpmaLocality, TpmaObject, TpmiAlgHash, TpmiAlgKdf, TpmsCreationData, TpmtPublic,
    TpmtTkCreation,
};

/// Recovers exp's specific response codes for a `TPM2_Create` whose parameters fail to
/// unmarshal.
///
/// exp re-scanned the raw `inPublic` bytes of a failed unmarshal and returned (at parameter 2)
/// `TPM_RC_TYPE` for an object type other than RSA, keyed-hash, ECC or symmetric cipher,
/// `TPM_RC_HASH` for an invalid `nameAlg` or keyed-hash scheme hash, or `TPM_RC_KDF` for an
/// invalid XOR KDF, instead of the unmarshal error. `params` is the parameter area; returns
/// `None` if exp kept the unmarshal error.
fn create_template_error(params: &[u8]) -> Option<TpmRc> {
    let read_u16 = |bytes: &[u8], offset: usize| -> Option<u16> {
        bytes
            .get(offset..)?
            .first_chunk::<2>()
            .map(|b| u16::from_be_bytes(*b))
    };
    let read_alg = |bytes: &[u8], offset: usize| read_u16(bytes, offset).map(Alg::from);
    let param_err = |rc: tpm2::errors::Fmt1| Some(rc.with(Position::parameter(2)));
    let is_hash = |alg: Alg| TpmiAlgHash::try_from(alg).is_ok();

    if params.len() < 6 {
        return None;
    }
    // inSensitive (TPM2B), then inPublic (TPM2B).
    let pub_offset = 2 + usize::from(read_u16(params, 0)?);
    if params.len() < pub_offset + 2 {
        return None;
    }
    let pub_size = usize::from(read_u16(params, pub_offset)?);
    let pub_bytes = params.get(pub_offset + 2..params.len().min(pub_offset + 2 + pub_size))?;

    if pub_bytes.len() >= 2 {
        let type_alg = read_alg(pub_bytes, 0)?;
        if !matches!(
            type_alg,
            Alg::RSA
                | Alg::KEYEDHASH
                | Alg::ECC
                | Alg::SYMCIPHER
                | Alg::MLDSA
                | Alg::HASH_MLDSA
                | Alg::MLKEM
        ) {
            return param_err(TpmRc::TYPE);
        }
    }
    if pub_bytes.len() >= 8 {
        // type | nameAlg | objectAttributes (u32) | authPolicy (TPM2B) | parameters
        let type_alg = read_alg(pub_bytes, 0)?;
        if !is_hash(read_alg(pub_bytes, 2)?) {
            return param_err(TpmRc::HASH);
        }
        if type_alg == Alg::KEYEDHASH {
            let mut offset = 8;
            if pub_bytes.len() >= offset + 2 {
                offset += 2 + usize::from(read_u16(pub_bytes, offset)?);
                if pub_bytes.len() >= offset + 4 {
                    let scheme_id = read_alg(pub_bytes, offset)?;
                    if scheme_id == Alg::HMAC {
                        if !is_hash(read_alg(pub_bytes, offset + 2)?) {
                            return param_err(TpmRc::HASH);
                        }
                    } else if scheme_id == Alg::XOR && pub_bytes.len() >= offset + 6 {
                        if !is_hash(read_alg(pub_bytes, offset + 2)?) {
                            return param_err(TpmRc::HASH);
                        }
                        let kdf_id = read_alg(pub_bytes, offset + 4)?;
                        if kdf_id != Alg::NULL
                            && (kdf_id == Alg::HKDF
                                || Option::<TpmiAlgKdf>::try_from(kdf_id).is_err())
                        {
                            return param_err(TpmRc::KDF);
                        }
                    }
                }
            }
        }
    }
    None
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Create] (`0x153`) command.
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

        let [parent] = request.try_unmarshal_handles::<Create>()?;
        check(parent, Tpmi::DhObject, Position::handle(1))?;
        let parent_handle = parent.0;

        if parent.handle_type() == Some(TpmHt::Permanent) {
            return Err(TpmRc::KEY.to_rc());
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let template_error = create_template_error(request.remaining_slice());
        let parsed = match null_name_alg_error::<Tpm2bSensitiveCreate>(
            request.remaining_slice(),
            Position::parameter(2),
        ) {
            Some(rc) => Err(rc),
            None => request.try_unmarshal_command::<Create>([parent]),
        };
        let cmd = parsed.map_err(|e| template_error.unwrap_or(e))?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let in_sensitive_struct = cmd.in_sensitive.0;
        let mut in_public_struct = OwnedPublic::from(cmd.in_public.0);

        // 1. Resolve parent object or hierarchy seed and parameters
        let mut parent_seed_val = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mut parent_qn_buf = [0u8; Tpm2bName::CAP];
        let parent_info = self.resolve_parent_object_or_hierarchy(
            parent_handle,
            &mut parent_seed_val,
            &mut parent_qn_buf,
            true, // expect_type_error
        )?;
        let parent_seed = &parent_seed_val[..parent_info.seed_len];

        // 2. Validate template properties and attributes
        let is_primary = self.validate_create_loaded_parameters(
            &in_public_struct.as_tpmt(),
            &in_sensitive_struct,
            parent_handle,
            parent_info.hierarchy_val,
            Some(parent_info.attributes),
        )?;

        // 3. Derive/Generate the new object seed
        let mut obj_seed = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let obj_seed_len = self.derive_create_loaded_seed(
            is_primary,
            parent_seed,
            &in_public_struct.as_tpmt(),
            parent_info.name_alg,
            &mut obj_seed,
        )?;
        let obj_seed = &obj_seed[..obj_seed_len];

        let gen_seed_arg = if is_primary { Some(obj_seed) } else { None };

        // 4. Generate/Derive the key pairs and the unique identifier
        let sensitive_data_origin = in_public_struct
            .object_attributes
            .contains(TpmaObject::SENSITIVE_DATA_ORIGIN);
        let get_random_fallback = !is_primary && sensitive_data_origin;
        let fallback_sensitive_data = if !is_primary && !sensitive_data_origin {
            Some(in_sensitive_struct.data.as_slice())
        } else {
            None
        };
        let name_alg = in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        if !matches!(
            name_alg,
            TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
        ) {
            return Err(TpmRc::VALUE.to_rc());
        }

        let sensitive = self.generate_key_and_unique(
            name_alg,
            &mut in_public_struct.parms_and_id,
            KeyDerivationArgs {
                gen_seed: gen_seed_arg,
                obj_seed,
                get_random_fallback,
                fallback_sensitive_data,
            },
        )?;

        let mut pub_buf = [0u8; TpmtPublic::MAX_SIZE];
        let pub_len = in_public_struct.marshal(&mut pub_buf);
        let object_name = self.compute_name(in_public_struct.name_alg, &pub_buf[..pub_len])?;

        // 6. Build and encrypt the sensitive area (out_private)
        let mut private_buf = [0u8; Tpm2bPrivate::CAP];
        let out_private = self.create_and_encrypt_private_area(
            &in_sensitive_struct,
            &sensitive,
            obj_seed,
            parent_seed,
            &object_name,
            is_primary,
            parent_info.name_alg,
            parent_info.sym_bits,
            &mut private_buf,
        )?;

        let out_public = in_public_struct.as_tpm2b();

        // 7. Compute creation data and creation hash
        let parent_name = if parent.handle_type() == Some(TpmHt::Transient) {
            self.global_state
                .find_transient_object(parent_handle)
                .map(|obj| obj.name)
                .ok_or(TpmRc::REFERENCE_H0)?
        } else {
            self.context
                .load_persistent_object(self.global_state, parent_handle)
                .map(|obj| obj.name)
                .map_err(|_| TpmRc::REFERENCE_H0)?
        };
        let parent_qualified_name =
            Tpm2bName::new(&parent_qn_buf[..parent_info.qn_len]).ok_or(TpmRc::FAILURE)?;

        let pcr_digest = self.compute_pcr_digest(&cmd.creation_pcr, name_alg)?;

        let locality = self.global_state.locality;
        let creation_data_struct = TpmsCreationData {
            pcr_select: cmd.creation_pcr,
            pcr_digest: pcr_digest.as_tpm2b(),
            locality: TpmaLocality(if locality <= 4 {
                1 << locality
            } else {
                locality
            }),
            parent_name_alg: Some(parent_info.name_alg),
            parent_name: parent_name.as_tpm2b(),
            parent_qualified_name,
            outside_info: cmd.outside_info,
        };

        let mut cd_buf = [0u8; TpmsCreationData::MAX_SIZE];
        let cd_len = creation_data_struct.marshal(&mut cd_buf);
        let creation_data = Tpm2b(creation_data_struct);

        let (creation_hash_bytes, creation_hash_len) =
            self.compute_hash(name_alg, &[&cd_buf[..cd_len]])?;

        let creation_hash = creation_hash_bytes
            .get(..creation_hash_len)
            .and_then(Tpm2bDigest::new)
            .ok_or(TpmRc::FAILURE)?;

        let computed_digest =
            self.compute_creation_ticket(parent_info.hierarchy_val, &object_name, &creation_hash)?;
        let creation_ticket = TpmtTkCreation::Creation(
            Handle(parent_info.hierarchy_val),
            Tpm2bDigest::new(&computed_digest).ok_or(TpmRc::FAILURE)?,
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
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
