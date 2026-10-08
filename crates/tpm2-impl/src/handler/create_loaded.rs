use super::{KeyDerivationArgs, ResolvedParentInfo, TransientObject};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Alg;
use tpm2::Handle;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::commands::responses;
use tpm2::commands::{CreateLoaded, CreateLoadedHandles, CreateLoadedRespHandles};
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    PublicParmsAndId, Tpm2bDigest, Tpm2bEccParameter, Tpm2bPrivate, Tpm2bPrivateKeyRsa,
    Tpm2bSensitiveData, Tpm2bSymKey, Tpm2bTemplate, TpmaObject, TpmiAlgHash, TpmiAlgSymMode,
    TpmsDerive, TpmsSensitiveCreate, TpmtEccScheme, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme,
    TpmtSensitive, TpmuSensitiveComposite,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::CreateLoaded] (`0x197`) command.
    ///
    /// # Description
    /// This command creates an object and loads it into the TPM's volatile memory in a single step.
    /// It can either create a new random key (like [TpmCc::Create] + [TpmCc::Load]) or derive a child key
    /// from a parent key using a KDF (derivation).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.9 (TPM2_CreateLoaded).
    ///
    /// # Relationships
    /// - Behaves as a combined [TpmCc::Create](create.rs)
    ///   and [TpmCc::Load](load.rs) sequence.
    /// - The parent key (`parent_handle`) can be a hierarchy root (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`, etc.) or a loaded Restricted Decryption Key.
    /// - Returns a loaded transient handle that can be used directly in signing or cryptographic operations.
    pub fn create_loaded(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        // 1. Unmarshal handles and command parameters from the request buffer.
        let (handles, in_sensitive_struct, in_public_template) =
            self.unmarshal_create_loaded_cmd(&mut request)?;
        let parent_handle = handles.parent_handle.0;
        let mut parent_seed_val = [0u8; 64];
        let mut parent_qn_buf = [0u8; 66];

        // 2. Resolve parent object or hierarchy seed and parameters
        let parent_info = self.resolve_parent_object_or_hierarchy(
            parent_handle,
            &mut parent_seed_val,
            &mut parent_qn_buf,
            false, // expect_type_error
        )?;

        // Ensure we actually have an empty slot in the transient object table
        let (index, handle) = self.global_state.find_empty_transient_slot(false)?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // 3. Unmarshal embedded template structure in action code (Part 2 Section 12.2.6 (Table 213))
        // and validate template properties and attributes.
        let (raw_in_public_struct, template_derive) = in_public_template
            .unmarshal_to_public(parent_info.is_derivation_parent)
            .map_err(|e| e.in_parameter(2).to_rc())?;
        let mut in_public_struct = crate::owned::OwnedPublic::from(raw_in_public_struct);
        let (is_primary, is_derived) = self.validate_create_loaded_parameters(
            &in_public_struct.as_tpmt(),
            &in_sensitive_struct,
            parent_handle,
            parent_info.hierarchy_val,
            Some(parent_info.attributes),
            parent_info.is_derivation_parent,
        )?;

        // 4. Derive/Generate the new object seed
        let mut obj_seed = [0u8; 64];
        let obj_seed_len = self.derive_create_loaded_seed(
            is_primary,
            is_derived,
            &parent_seed_val[..parent_info.seed_len],
            parent_info.seed_len,
            &in_public_struct.as_tpmt(),
            &in_sensitive_struct,
            template_derive,
            parent_info.name_alg,
            &mut obj_seed,
        )?;

        let gen_seed_arg = if is_primary || is_derived {
            Some(&obj_seed[..obj_seed_len])
        } else {
            None
        };

        // 5. Generate/Derive the key pairs and the unique identifier
        let mut actual_private_key = [0u8; 1536];
        let is_sym_primary_or_derived = is_primary || is_derived;
        let get_random_fallback = !is_sym_primary_or_derived
            && (in_public_struct.object_attributes.0 & TpmaObject::SENSITIVE_DATA_ORIGIN.0) != 0;
        let fallback_sensitive_data = if !is_sym_primary_or_derived
            && (in_public_struct.object_attributes.0 & TpmaObject::SENSITIVE_DATA_ORIGIN.0) == 0
        {
            Some(in_sensitive_struct.data.get_buffer())
        } else {
            None
        };
        let name_alg = in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        if name_alg != TpmiAlgHash::Sha1
            && name_alg != TpmiAlgHash::Sha256
            && name_alg != TpmiAlgHash::Sha384
            && name_alg != TpmiAlgHash::Sha512
        {
            return Err(TpmRc::VALUE.to_rc());
        }

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

        let mut pub_buf = [0u8; tpm2::TpmtPublic::MAX_SIZE];
        let pub_len = in_public_struct.marshal(&mut pub_buf);
        let object_name = self.compute_name(in_public_struct.name_alg, &pub_buf[..pub_len])?;

        let qualified_name = self.compute_qualified_name(
            in_public_struct.name_alg,
            &parent_qn_buf[..parent_info.qn_len],
            object_name.get_buffer(),
        )?;

        let resp_handles = CreateLoadedRespHandles {
            object_handle: Handle(handle),
        };

        let out_public = in_public_struct.as_tpm2b();

        // 7. Build and encrypt the sensitive area (out_private)
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

        let rsp = responses::CreateLoaded {
            name: object_name.as_tpm2b(),
            out_public,
            out_private,
        };

        // 9. Write the response buffers
        let response = request.into_response();
        self.write_response_all(
            response,
            &resp_handles,
            &rsp,
            &session_responses[..num_sessions],
        )?;

        // 10. Save the loaded object in the transient objects slot
        self.store_transient_object(
            index,
            handle,
            &obj_seed[..obj_seed_len],
            object_name,
            crate::owned::OwnedAuth::from(in_sensitive_struct.user_auth),
            in_public_struct,
            actual_private_key,
            actual_private_key_len,
            qualified_name,
            Some(parent_handle),
            parent_info.hierarchy_val,
            parent_info.has_st_clear,
        );

        Ok(())
    }

    /// Helper function to unmarshal command parameters and sensitive structure from request.
    fn unmarshal_create_loaded_cmd<'c>(
        &self,
        request: &mut RequestThenResponse<'_, 'c>,
    ) -> Result<
        (
            CreateLoadedHandles,
            TpmsSensitiveCreate<'c>,
            Tpm2bTemplate<'c>,
        ),
        TpmRc,
    > {
        let handles = request.try_unmarshal::<CreateLoadedHandles>()?;
        let cmd = request.try_unmarshal::<CreateLoaded>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let in_sensitive_struct = cmd
            .in_sensitive
            .to_struct()
            .map_err(|e| e.in_parameter(1).to_rc())?;

        Ok((handles, in_sensitive_struct, cmd.in_public))
    }

    /// Helper function to derive or generate the random seed for the newly created object.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn derive_create_loaded_seed(
        &self,
        is_primary: bool,
        is_derived: bool,
        parent_seed_val: &[u8],
        parent_seed_len: usize,
        in_public_struct: &TpmtPublic,
        in_sensitive_struct: &TpmsSensitiveCreate,
        template_derive: Option<TpmsDerive>,
        parent_name_alg: TpmiAlgHash,
        obj_seed: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        let digest_size = parent_name_alg.digest_size();
        let total_bits = (digest_size * 8) as u32;

        if is_primary {
            let mut unique_buf = [0u8; tpm2::TpmuPublicId::MAX_SIZE];
            let unique_len = match &in_public_struct.parms_and_id {
                PublicParmsAndId::KeyedHash(_, unique) => {
                    let b = unique.get_buffer();
                    unique_buf[..b.len()].copy_from_slice(b);
                    b.len()
                }
                PublicParmsAndId::Sym(_, unique) => {
                    let b = unique.get_buffer();
                    unique_buf[..b.len()].copy_from_slice(b);
                    b.len()
                }
                PublicParmsAndId::Rsa(_, unique) => {
                    let b = unique.get_buffer();
                    unique_buf[..b.len()].copy_from_slice(b);
                    b.len()
                }
                PublicParmsAndId::Ecc(_, point) => {
                    let x = point.x.get_buffer();
                    let y = point.y.get_buffer();
                    unique_buf[..x.len()].copy_from_slice(x);
                    unique_buf[x.len()..x.len() + y.len()].copy_from_slice(y);
                    x.len() + y.len()
                }
                PublicParmsAndId::Mldsa(_, unique) | PublicParmsAndId::HashMldsa(_, unique) => {
                    let b = unique.get_buffer();
                    unique_buf[..b.len()].copy_from_slice(b);
                    b.len()
                }
                PublicParmsAndId::Mlkem(_, unique) => {
                    let b = unique.get_buffer();
                    unique_buf[..b.len()].copy_from_slice(b);
                    b.len()
                }
            };
            let unique_slice = &unique_buf[..unique_len];
            kdfa(
                self.crypto(),
                parent_name_alg,
                &parent_seed_val[..parent_seed_len],
                b"Primary Object Creation",
                unique_slice,
                &[],
                total_bits,
                obj_seed,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            Ok(digest_size)
        } else if is_derived {
            let mut label_context = template_derive.ok_or(TpmRc::FAILURE)?;
            let data_buf = in_sensitive_struct.data.get_buffer();
            if !data_buf.is_empty() {
                let mut slice = data_buf;
                let sensitive_derive = TpmsDerive::unmarshal(&mut slice).map_err(|e| e.to_rc())?;
                if label_context.label.get_size() == 0 {
                    label_context.label = sensitive_derive.label;
                }
                if label_context.context.get_size() == 0 {
                    label_context.context = sensitive_derive.context;
                }
            }
            kdfa(
                self.crypto(),
                parent_name_alg,
                &parent_seed_val[..parent_seed_len],
                label_context.label.get_buffer(),
                label_context.context.get_buffer(),
                &[],
                total_bits,
                obj_seed,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            Ok(digest_size)
        } else {
            let seed_len = digest_size;
            self.crypto()
                .get_random(&mut obj_seed[..digest_size])
                .map_err(|_| TpmRc::FAILURE)?;
            Ok(seed_len)
        }
    }

    /// Helper function to format and store the transient object into the global state table.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_transient_object(
        &mut self,
        index: usize,
        handle: u32,
        obj_seed: &[u8],
        name: crate::owned::OwnedName,
        user_auth: crate::owned::OwnedAuth,
        public_struct: crate::owned::OwnedPublic,
        private_key: [u8; 1536],
        private_key_len: usize,
        qualified_name: crate::owned::OwnedName,
        parent_handle: Option<u32>,
        hierarchy: u32,
        st_clear: bool,
    ) {
        let mut stored_seed = [0u8; 32];
        let copy_len = core::cmp::min(32, obj_seed.len());
        if copy_len > 0 {
            stored_seed[..copy_len].copy_from_slice(&obj_seed[..copy_len]);
        }

        self.global_state.transient_parents[index] = parent_handle;
        self.global_state.transient_objects[index] = Some(TransientObject {
            handle,
            seed: stored_seed,
            name,
            auth: user_auth,
            public: public_struct,
            private: private_key,
            private_len: private_key_len,
            qualified_name,
            hierarchy,
            st_clear,
        });

        self.update_aliased_transient_objects(handle, &name, &qualified_name);
    }

    /// Resolves the parent object seed, hierarchy, qualified name, and auth requirement
    /// from the parent_handle argument.
    pub(crate) fn resolve_parent_object_or_hierarchy(
        &mut self,
        parent_handle: u32,
        parent_seed_val: &mut [u8; 64],
        parent_qn_buf: &mut [u8; 66],
        expect_type_error: bool,
    ) -> Result<ResolvedParentInfo, TpmRc> {
        if parent_handle == 0x40000001 {
            // TPM_RH_OWNER
            parent_qn_buf[..4].copy_from_slice(&parent_handle.to_be_bytes());
            let seed_len = self.global_state.sp_seed_size as usize;
            parent_seed_val[..seed_len].copy_from_slice(&self.global_state.sp_seed[..seed_len]);
            Ok(ResolvedParentInfo {
                req_auth: true,
                seed_len,
                qn_len: 4,
                hierarchy_val: parent_handle,
                has_st_clear: false,
                name_alg: TpmiAlgHash::Sha256,
                sym_bits: 128,
                attributes: TpmaObject(0),
                is_derivation_parent: false,
            })
        } else if parent_handle == 0x40000007 {
            // TPM_RH_NULL
            parent_qn_buf[..4].copy_from_slice(&parent_handle.to_be_bytes());
            Ok(ResolvedParentInfo {
                req_auth: true,
                seed_len: 0,
                qn_len: 4,
                hierarchy_val: parent_handle,
                has_st_clear: false,
                name_alg: TpmiAlgHash::Sha256,
                sym_bits: 128,
                attributes: TpmaObject(0),
                is_derivation_parent: false,
            })
        } else if parent_handle == 0x4000000C {
            // TPM_RH_PLATFORM
            parent_qn_buf[..4].copy_from_slice(&parent_handle.to_be_bytes());
            let seed_len = self.global_state.pp_seed_size as usize;
            parent_seed_val[..seed_len].copy_from_slice(&self.global_state.pp_seed[..seed_len]);
            Ok(ResolvedParentInfo {
                req_auth: true,
                seed_len,
                qn_len: 4,
                hierarchy_val: parent_handle,
                has_st_clear: false,
                name_alg: TpmiAlgHash::Sha256,
                sym_bits: 128,
                attributes: TpmaObject(0),
                is_derivation_parent: false,
            })
        } else if parent_handle == 0x4000000B {
            // TPM_RH_ENDORSEMENT
            parent_qn_buf[..4].copy_from_slice(&parent_handle.to_be_bytes());
            let seed_len = self.global_state.ep_seed_size as usize;
            parent_seed_val[..seed_len].copy_from_slice(&self.global_state.ep_seed[..seed_len]);
            Ok(ResolvedParentInfo {
                req_auth: true,
                seed_len,
                qn_len: 4,
                hierarchy_val: parent_handle,
                has_st_clear: false,
                name_alg: TpmiAlgHash::Sha256,
                sym_bits: 128,
                attributes: TpmaObject(0),
                is_derivation_parent: false,
            })
        } else if parent_handle >> 24 == 0x80 || parent_handle >> 24 == 0x81 {
            let obj = if parent_handle >> 24 == 0x80 {
                self.global_state
                    .find_transient_object(parent_handle)
                    .cloned()
                    .ok_or(TpmRc::REFERENCE_H0)?
            } else {
                self.context
                    .load_persistent_object(self.global_state, parent_handle)
                    .map_err(|_| TpmRc::REFERENCE_H0)?
            };
            let parent_has_st_clear =
                obj.st_clear || obj.public.object_attributes.contains(TpmaObject::ST_CLEAR);
            if (obj.public.object_attributes.0 & TpmaObject::DECRYPT.0) == 0
                || (obj.public.object_attributes.0 & TpmaObject::RESTRICTED.0) == 0
            {
                return Err(if expect_type_error {
                    TpmRc::TYPE.with(Position::handle(1))
                } else {
                    TpmRc::ATTRIBUTES.with(Position::handle(1))
                });
            }
            let is_derivation_parent = matches!(
                &obj.public.parms_and_id,
                crate::owned::OwnedPublicParmsAndId::KeyedHash(
                    Some(TpmtKeyedHashScheme::ExclusiveOr(_)),
                    _
                )
            );
            if expect_type_error && is_derivation_parent {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }
            let parent_req_auth =
                (obj.public.object_attributes.0 & TpmaObject::USER_WITH_AUTH.0) != 0;
            let dyn_qn = self.get_dynamic_qualified_name(&obj);
            let qn_buf = dyn_qn.get_buffer();
            let qn_len = qn_buf.len();
            parent_qn_buf[..qn_len].copy_from_slice(qn_buf);
            parent_seed_val[..32].copy_from_slice(&obj.seed);
            let mut sym_bits = match &obj.public.parms_and_id {
                crate::owned::OwnedPublicParmsAndId::Rsa(parms, _) => {
                    parms.symmetric.map(|s| s.key_bits() as u32).unwrap_or(128)
                }
                crate::owned::OwnedPublicParmsAndId::Ecc(parms, _) => {
                    parms.symmetric.map(|s| s.key_bits() as u32).unwrap_or(128)
                }
                _ => 128,
            };
            if sym_bits == 0 {
                sym_bits = 128;
            }
            let name_alg = obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
            let mut actual_seed_len = core::cmp::min(obj.seed.len(), name_alg.digest_size());
            while actual_seed_len > 0 && obj.seed[actual_seed_len - 1] == 0 {
                actual_seed_len -= 1;
            }
            if actual_seed_len == 0 {
                actual_seed_len = core::cmp::min(obj.seed.len(), name_alg.digest_size());
            }
            Ok(ResolvedParentInfo {
                req_auth: parent_req_auth,
                seed_len: actual_seed_len,
                qn_len,
                hierarchy_val: obj.hierarchy,
                has_st_clear: parent_has_st_clear,
                name_alg,
                sym_bits,
                attributes: obj.public.object_attributes,
                is_derivation_parent,
            })
        } else {
            Err(TpmRc::HANDLE.to_rc())
        }
    }

    /// Performs comprehensive structural and attribute validation on an object's public template (`TPMA_OBJECT`),
    /// checking scheme consistency and Table 31 requirements.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_object_attributes(
        &self,
        public_struct: &TpmtPublic,
        parent_handle: u32,
        parent_hierarchy_val: u32,
        parent_attributes: Option<TpmaObject>,
        is_import: bool,
        allow_null_name_alg: bool,
        error_pos: Position,
    ) -> Result<(), TpmRc> {
        let name_alg_opt = public_struct.name_alg;
        if !allow_null_name_alg && name_alg_opt.is_none() {
            return Err(TpmRc::HASH.with(error_pos));
        }

        // 2. If there is an authPolicy, it needs to be the size of the digest produced by nameAlg
        if public_struct.auth_policy.get_size() != 0 {
            if let Some(name_alg) = name_alg_opt {
                let digest_size = name_alg.digest_size();
                if public_struct.auth_policy.get_size() as usize != digest_size {
                    return Err(TpmRc::SIZE.with(error_pos));
                }
            } else if !allow_null_name_alg {
                return Err(TpmRc::HASH.with(error_pos));
            }
        }

        let attr = public_struct.object_attributes.0;
        let restricted = (attr & TpmaObject::RESTRICTED.0) != 0;
        let sign = (attr & TpmaObject::SIGN_ENCRYPT.0) != 0;
        let decrypt = (attr & TpmaObject::DECRYPT.0) != 0;
        let fixed_tpm = (attr & TpmaObject::FIXED_TPM.0) != 0;
        let fixed_parent = (attr & TpmaObject::FIXED_PARENT.0) != 0;
        let encrypted_duplication = (attr & TpmaObject::ENCRYPTED_DUPLICATION.0) != 0;

        let is_primary = parent_handle == 0x40000001
            || parent_handle == 0x40000007
            || parent_handle == 0x4000000C
            || parent_handle == 0x4000000B;

        // 3. Attribute hierarchy/parent consistency (Table 31 fixedTPM, fixedParent, encryptedDuplication)
        if is_import {
            // For TPM2_Import, fixedTPM and fixedParent SHALL be CLEAR in object_public
            if fixed_tpm || fixed_parent {
                return Err(TpmRc::ATTRIBUTES.with(error_pos));
            }
        } else if is_primary {
            // For a Primary Object, fixedTPM and fixedParent SHALL both be SET or both be CLEAR
            if fixed_tpm != fixed_parent {
                return Err(TpmRc::ATTRIBUTES.with(error_pos));
            }
        } else if parent_handle >> 24 == 0x80 || parent_handle >> 24 == 0x81 {
            // For an ordinary/derived object under a parent handle:
            let pattr = parent_attributes
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?
                .0;
            let parent_fixed_tpm = (pattr & TpmaObject::FIXED_TPM.0) != 0;
            let parent_encrypted_duplication = (pattr & TpmaObject::ENCRYPTED_DUPLICATION.0) != 0;

            // If fixedTPM is SET in the object's parent, then fixedTPM shall equal fixedParent.
            // If fixedTPM is CLEAR in the parent, fixedTPM shall also be CLEAR.
            if parent_fixed_tpm {
                if fixed_tpm != fixed_parent {
                    return Err(TpmRc::ATTRIBUTES.with(error_pos));
                }
            } else {
                if fixed_tpm {
                    return Err(TpmRc::ATTRIBUTES.with(error_pos));
                }
                // If parent fixedTPM is CLEAR, the child must have the same encryptedDuplication setting as its parent.
                if encrypted_duplication != parent_encrypted_duplication {
                    return Err(TpmRc::ATTRIBUTES.with(error_pos));
                }
            }
        }

        // If fixedTPM is SET, then fixedParent SHALL be SET (applies to ALL keys unless already checked above)
        if fixed_tpm && !fixed_parent {
            return Err(TpmRc::ATTRIBUTES.with(error_pos));
        }

        // For derived/ordinary objects in the Null hierarchy, fixedTPM and fixedParent MUST be CLEAR
        if !is_primary && parent_hierarchy_val == 0x40000007 && (fixed_tpm || fixed_parent) {
            return Err(TpmRc::ATTRIBUTES.with(error_pos));
        }

        // If the object can't be duplicated (directly or indirectly) then there is no justification for encryptedDuplication SET
        if fixed_tpm && encrypted_duplication {
            return Err(TpmRc::ATTRIBUTES.with(error_pos));
        }

        // firmwareLimited/svnLimited can only be set if fixedTPM is also set, and require a matching parent/hierarchy.
        let firmware_limited = (attr & TpmaObject::FIRMWARE_LIMITED.0) != 0;
        let svn_limited = (attr & TpmaObject::SVN_LIMITED.0) != 0;
        if (firmware_limited || svn_limited) && !fixed_tpm {
            return Err(TpmRc::ATTRIBUTES.with(error_pos));
        }
        if firmware_limited {
            if let Some(pattr) = parent_attributes {
                if !pattr.contains(TpmaObject::FIRMWARE_LIMITED) {
                    return Err(TpmRc::ATTRIBUTES.with(error_pos));
                }
            } else {
                // None of the standard hierarchies (Owner, Endorsement, Platform, Null) are firmware-limited.
                return Err(TpmRc::ATTRIBUTES.with(error_pos));
            }
        }
        if svn_limited {
            if let Some(pattr) = parent_attributes {
                if !pattr.contains(TpmaObject::SVN_LIMITED) {
                    return Err(TpmRc::ATTRIBUTES.with(error_pos));
                }
            } else {
                // None of the standard hierarchies are SVN-limited.
                return Err(TpmRc::ATTRIBUTES.with(error_pos));
            }
        }

        // 4. Sign and Decrypt attribute validation & scheme check
        if sign == decrypt {
            // A restricted key cannot have both SET or both CLEAR (`sign == decrypt`)
            if restricted {
                return Err(TpmRc::ATTRIBUTES.with(error_pos));
            }
            // Only a data object (`TPM_ALG_KEYEDHASH` with sign/decrypt clear) may have both sign and decrypt CLEAR.
            if !sign && public_struct.parms_and_id.algorithm() != Alg::KEYEDHASH {
                return Err(TpmRc::ATTRIBUTES.with(error_pos));
            }
        }

        // 5. Scheme checks per key type
        match &public_struct.parms_and_id {
            PublicParmsAndId::Rsa(parms, _) => {
                if !restricted && !decrypt && parms.symmetric.is_some() {
                    return Err(TpmRc::SYMMETRIC.with(error_pos));
                }
                if sign && !decrypt {
                    match &parms.scheme {
                        Some(TpmtRsaScheme::Rsapss(_)) | Some(TpmtRsaScheme::Rsassa(_)) => {}
                        None => {
                            if restricted {
                                return Err(TpmRc::SCHEME.with(error_pos));
                            }
                        }
                        _ => {
                            return Err(TpmRc::SCHEME.with(error_pos));
                        }
                    }
                }
                if decrypt && !sign {
                    if restricted && parms.scheme.is_some() {
                        return Err(TpmRc::SCHEME.with(error_pos));
                    }
                    if !restricted
                        && matches!(
                            parms.scheme,
                            Some(TpmtRsaScheme::Rsassa(_)) | Some(TpmtRsaScheme::Rsapss(_))
                        )
                    {
                        return Err(TpmRc::SCHEME.with(error_pos));
                    }
                }
                if parms.key_bits.0 != 1024
                    && parms.key_bits.0 != 2048
                    && parms.key_bits.0 != 3072
                    && parms.key_bits.0 != 4096
                {
                    return Err(TpmRc::VALUE.with(error_pos));
                }
                if parms.exponent != 0 && parms.exponent != 65537 {
                    return Err(TpmRc::VALUE.with(error_pos));
                }
            }
            PublicParmsAndId::Ecc(parms, _) => {
                if !restricted && !decrypt && parms.symmetric.is_some() {
                    return Err(TpmRc::SYMMETRIC.with(error_pos));
                }
                if parms.kdf.is_some() {
                    return Err(TpmRc::KDF.with(error_pos));
                }
                if sign && !decrypt {
                    match &parms.scheme {
                        Some(TpmtEccScheme::Ecdsa(_))
                        | Some(TpmtEccScheme::Ecdaa(_))
                        | Some(TpmtEccScheme::Sm2(_))
                        | Some(TpmtEccScheme::Ecschnorr(_)) => {}
                        None => {
                            if restricted {
                                return Err(TpmRc::SCHEME.with(error_pos));
                            }
                        }
                        _ => {
                            return Err(TpmRc::SCHEME.with(error_pos));
                        }
                    }
                }
                if decrypt && !sign {
                    if restricted && parms.scheme.is_some() {
                        return Err(TpmRc::SCHEME.with(error_pos));
                    }
                    if !restricted
                        && matches!(
                            parms.scheme,
                            Some(TpmtEccScheme::Ecdsa(_))
                                | Some(TpmtEccScheme::Ecdaa(_))
                                | Some(TpmtEccScheme::Ecschnorr(_))
                        )
                    {
                        return Err(TpmRc::SCHEME.with(error_pos));
                    }
                }
            }
            PublicParmsAndId::KeyedHash(scheme, _) => {
                if let Some(TpmtKeyedHashScheme::ExclusiveOr(s)) = scheme
                    && s.kdf == Some(tpm2::TpmiAlgKdf::Hkdf)
                {
                    return Err(TpmRc::KDF.with(error_pos));
                }
                if sign && decrypt && scheme.is_some() {
                    return Err(TpmRc::SCHEME.with(error_pos));
                }
                if sign && !decrypt && !matches!(scheme, Some(TpmtKeyedHashScheme::Hmac(_)) | None)
                {
                    return Err(TpmRc::SCHEME.with(error_pos));
                }
                if decrypt && !sign {
                    if !matches!(scheme, Some(TpmtKeyedHashScheme::ExclusiveOr(_)) | None) {
                        return Err(TpmRc::SCHEME.with(error_pos));
                    }
                    if let Some(TpmtKeyedHashScheme::ExclusiveOr(s)) = scheme
                        && restricted
                        && s.kdf != Some(tpm2::TpmiAlgKdf::Kdf1Sp800_108)
                    {
                        return Err(TpmRc::SCHEME.with(error_pos));
                    }
                }
            }
            PublicParmsAndId::Sym(sym, _) => {
                if sign && !decrypt {
                    return Err(TpmRc::ATTRIBUTES.with(error_pos));
                }
                if decrypt
                    && !matches!(
                        sym.mode(),
                        Some(
                            TpmiAlgSymMode::CTR
                                | TpmiAlgSymMode::OFB
                                | TpmiAlgSymMode::CBC
                                | TpmiAlgSymMode::CFB
                                | TpmiAlgSymMode::ECB
                        )
                    )
                {
                    return Err(TpmRc::SCHEME.with(error_pos));
                }
            }
            PublicParmsAndId::Mldsa(_, _)
            | PublicParmsAndId::HashMldsa(_, _)
            | PublicParmsAndId::Mlkem(_, _) => {}
        }

        Ok(())
    }

    /// Performs validation checks on the public and sensitive area parameters of the target object
    /// template to ensure cryptographic attributes consistency and spec requirements alignment.
    pub(crate) fn validate_create_loaded_parameters(
        &self,
        in_public_struct: &TpmtPublic,
        in_sensitive_struct: &TpmsSensitiveCreate,
        parent_handle: u32,
        parent_hierarchy_val: u32,
        parent_attributes: Option<TpmaObject>,
        is_derived: bool,
    ) -> Result<(bool, bool), TpmRc> {
        let is_primary = parent_handle == 0x40000001
            || parent_handle == 0x40000007
            || parent_handle == 0x4000000C
            || parent_handle == 0x4000000B;

        let alg = in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        let digest_size = alg.digest_size();

        if in_sensitive_struct.user_auth.get_size() as usize > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        let attr = in_public_struct.object_attributes.0;
        let sensitive_data_origin = (attr & TpmaObject::SENSITIVE_DATA_ORIGIN.0) != 0;

        if is_derived {
            if matches!(in_public_struct.parms_and_id, PublicParmsAndId::Rsa(_, _)) {
                return Err(TpmRc::TYPE.with(Position::parameter(2)));
            }
            if sensitive_data_origin {
                return Err(TpmRc::ATTRIBUTES.with(Position::parameter(2)));
            }
        }

        self.validate_object_attributes(
            in_public_struct,
            parent_handle,
            parent_hierarchy_val,
            parent_attributes,
            false, // is_import
            false, // allow_null_name_alg
            Position::parameter(2),
        )?;

        if !is_derived {
            if let PublicParmsAndId::Sym(sym, _) = &in_public_struct.parms_and_id {
                if sensitive_data_origin && in_sensitive_struct.data.get_size() != 0 {
                    return Err(TpmRc::ATTRIBUTES.with(Position::parameter(2)));
                }
                if !sensitive_data_origin {
                    let key_bytes = (sym.key_bits() as usize) / 8;
                    if key_bytes > 0 && in_sensitive_struct.data.get_size() as usize != key_bytes {
                        return Err(TpmRc::KEY_SIZE.with(Position::parameter(1)));
                    }
                }
            } else if (sensitive_data_origin && in_sensitive_struct.data.get_size() != 0)
                || (!sensitive_data_origin
                    && (matches!(in_public_struct.parms_and_id, PublicParmsAndId::Rsa(_, _))
                        || matches!(in_public_struct.parms_and_id, PublicParmsAndId::Ecc(_, _))))
            {
                return Err(TpmRc::ATTRIBUTES.with(Position::parameter(2)));
            } else if in_sensitive_struct.data.get_size() as usize
                > tpm2::TPM2_MAX_SYM_DATA as usize
            {
                return Err(TpmRc::SIZE.with(Position::parameter(1)));
            }
        }

        Ok((is_primary, is_derived))
    }

    /// Encrypts the sensitive area of the target object using storage seed and CFB mode,
    /// computes inner/outer integrity MAC hashes, and formats the output private buffer.
    pub(crate) fn encrypt_sensitive_area(
        &self,
        tpmt_sensitive: &TpmtSensitive<'_>,
        parent_seed_val: &[u8],
        object_name: &crate::owned::OwnedName,
        parent_name_alg: TpmiAlgHash,
        sym_key_bits: u32,
        private_buf: &mut [u8; 2048],
    ) -> Result<usize, TpmRc> {
        let mut tpm2b_sensitive_buf = [0u8; 2048];
        let sensitive_len = tpmt_sensitive.marshal(
            (&mut tpm2b_sensitive_buf[2..2 + tpm2::TpmtSensitive::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        tpm2b_sensitive_buf[0..2].copy_from_slice(&(sensitive_len as u16).to_be_bytes());

        // Inner integrity (empty)
        let inner_integrity_len = 2; // Tpm2bDigest size bytes (0)
        let inner_integrity_buf = [0u8; 2];

        let mut unencrypted_blob = [0u8; 2048];
        unencrypted_blob[0..inner_integrity_len].copy_from_slice(&inner_integrity_buf);
        unencrypted_blob[inner_integrity_len..inner_integrity_len + sensitive_len]
            .copy_from_slice(&tpm2b_sensitive_buf[2..2 + sensitive_len]);
        let unencrypted_len = inner_integrity_len + sensitive_len;

        let digest_size = parent_name_alg.digest_size();
        let total_bits = (digest_size * 8) as u32;

        // KDFA for symmetric key
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

        let mut iv = [0u8; 16];
        self.context
            .platform
            .rng
            .get_random(&mut iv)
            .map_err(|_| TpmRc::FAILURE)?;
        let orig_iv = iv;

        let sym_alg =
            tpm2::TpmtSymDefObject::aes_cfb(sym_key_bits as u16).map_err(|_| TpmRc::FAILURE)?;
        tpm2::crypto::encrypt(
            self.crypto(),
            sym_alg,
            &sym_key_buf[..sym_key_len],
            &mut iv,
            &mut unencrypted_blob[..unencrypted_len],
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let encrypted_blob = &unencrypted_blob[..unencrypted_len];

        // KDFA for MAC
        let mut mac_key = [0u8; 64];
        kdfa(
            self.crypto(),
            parent_name_alg,
            parent_seed_val,
            b"INTEGRITY",
            &[],
            &[],
            total_bits,
            &mut mac_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        private_buf[0..2].copy_from_slice(&(digest_size as u16).to_be_bytes());

        let iv_offset = 2 + digest_size;
        private_buf[iv_offset..iv_offset + 2].copy_from_slice(&16u16.to_be_bytes());
        private_buf[iv_offset + 2..iv_offset + 18].copy_from_slice(&orig_iv);
        let enc_offset = iv_offset + 18;
        private_buf[enc_offset..enc_offset + unencrypted_len].copy_from_slice(encrypted_blob);

        let mac_input = &private_buf[iv_offset..enc_offset + unencrypted_len];

        let mut mac_ctx =
            tpm2::crypto::HmacCtx::new(self.crypto(), parent_name_alg, &mac_key[..digest_size])
                .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx.update(mac_input).map_err(|_| TpmRc::FAILURE)?;
        mac_ctx
            .update(object_name.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        let mut mac_buf = [0u8; 64];
        let mac = mac_ctx.finalize(&mut mac_buf).map_err(|_| TpmRc::FAILURE)?;
        private_buf[2..2 + digest_size].copy_from_slice(mac.digest());

        Ok(enc_offset + unencrypted_len)
    }

    /// Helper function to build the sensitive struct and encrypt it into out_private.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_and_encrypt_private_area<'c>(
        &self,
        in_public_struct: &TpmtPublic<'_>,
        in_sensitive_struct: &TpmsSensitiveCreate<'_>,
        actual_private_key: &[u8],
        obj_seed: &[u8],
        parent_seed_val: &[u8],
        object_name: &crate::owned::OwnedName,
        is_primary: bool,
        is_derived: bool,
        parent_name_alg: TpmiAlgHash,
        sym_key_bits: u32,
        private_buf: &'c mut [u8; 2048],
    ) -> Result<Tpm2bPrivate<'c>, TpmRc> {
        let mut prime_p = [0u8; 256];
        let sensitive_comp = match in_public_struct.parms_and_id {
            PublicParmsAndId::Ecc(_, _) => TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::from_bytes(actual_private_key)
                    .expect("private key has valid size"),
            ),
            PublicParmsAndId::Rsa(_, _) => {
                let prime_p_len = match self
                    .crypto()
                    .rsa_private_key_to_prime_p(actual_private_key, &mut prime_p)
                {
                    Ok(len) => len,
                    Err(_) => {
                        if actual_private_key.len() <= prime_p.len() {
                            prime_p[..actual_private_key.len()].copy_from_slice(actual_private_key);
                            actual_private_key.len()
                        } else {
                            return Err(TpmRc::FAILURE);
                        }
                    }
                };
                TpmuSensitiveComposite::Rsa(
                    Tpm2bPrivateKeyRsa::from_bytes(&prime_p[..prime_p_len])
                        .expect("private key has valid size"),
                )
            }
            PublicParmsAndId::KeyedHash(_, _) => TpmuSensitiveComposite::KeyedHash(
                Tpm2bSensitiveData::from_bytes(actual_private_key)
                    .expect("private key has valid size"),
            ),
            PublicParmsAndId::Sym(_, _) => TpmuSensitiveComposite::Sym(
                Tpm2bSymKey::from_bytes(actual_private_key).expect("private key has valid size"),
            ),
            PublicParmsAndId::Mldsa(_, _) => TpmuSensitiveComposite::Mldsa(
                tpm2::Tpm2bPrivateKeyMldsa::from_bytes(actual_private_key)
                    .expect("private key has valid size"),
            ),
            PublicParmsAndId::HashMldsa(_, _) => TpmuSensitiveComposite::HashMldsa(
                tpm2::Tpm2bPrivateKeyMldsa::from_bytes(actual_private_key)
                    .expect("private key has valid size"),
            ),
            PublicParmsAndId::Mlkem(_, _) => TpmuSensitiveComposite::Mlkem(
                tpm2::Tpm2bPrivateKeyMlkem::from_bytes(actual_private_key)
                    .expect("private key has valid size"),
            ),
        };

        let tpmt_sensitive = TpmtSensitive {
            auth_value: in_sensitive_struct.user_auth,
            seed_value: Tpm2bDigest::from_bytes(obj_seed)
                .expect("generated object seed has valid size"),
            sensitive: sensitive_comp,
        };

        let final_private_len = self.encrypt_sensitive_area(
            &tpmt_sensitive,
            parent_seed_val,
            object_name,
            parent_name_alg,
            sym_key_bits,
            private_buf,
        )?;

        if !is_primary && !is_derived {
            Ok(Tpm2bPrivate::from_bytes(&private_buf[..final_private_len])
                .expect("marshalled private area has valid size"))
        } else {
            Ok(Tpm2bPrivate::default())
        }
    }
}
