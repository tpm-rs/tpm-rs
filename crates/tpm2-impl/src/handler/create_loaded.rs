use super::{KeyDerivationArgs, ParentSchemeInfo, ResolvedParentInfo, TransientObject};
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
    TpmsDerive, TpmsSensitiveCreate, TpmtKeyedHashScheme, TpmtPublic, TpmtSensitive,
    TpmuSensitiveComposite,
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
            true, // allow_derivation_parent
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
            parent_info.scheme,
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
        // A NULL or unimplemented nameAlg is rejected as `TPM_RC_HASH + RC_CreateLoaded_inPublic`.
        let name_alg = in_public_struct
            .name_alg
            .ok_or(TpmRc::HASH.with(Position::parameter(2)))?;
        if name_alg != TpmiAlgHash::Sha1
            && name_alg != TpmiAlgHash::Sha256
            && name_alg != TpmiAlgHash::Sha384
            && name_alg != TpmiAlgHash::Sha512
        {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
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
            Self::object_seed_value(&in_public_struct.as_tpmt(), &obj_seed[..obj_seed_len]),
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
        // The object's seedValue is sized to the object's own nameAlg (C `CryptCreateObject`);
        // the parent's nameAlg (or the derivation parent's XOR hash) only keys the KDF.
        let digest_size = in_public_struct
            .name_alg
            .ok_or(TpmRc::HASH.with(Position::parameter(2)))?
            .digest_size();
        let total_bits = (digest_size * 8) as u32;

        if is_primary {
            self.derive_primary_object_seed(
                &parent_seed_val[..parent_seed_len],
                in_public_struct,
                in_sensitive_struct.data.get_buffer(),
                obj_seed,
            )
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

    /// Derives the seed from which a Primary Object's key material and `seedValue` are
    /// generated.
    ///
    /// Mirrors C `CreatePrimary.c` / `CreateLoaded.c`, which seed the creation DRBG with the
    /// hierarchy primary seed, the label `"Primary Object Creation"`, the Name of the input
    /// template (`PublicMarshalAndComputeName(publicArea)`, binding nameAlg, attributes,
    /// authPolicy, parameters and unique) and `inSensitive.data`. Two templates that differ in
    /// any field therefore yield unrelated keys. Returns the seed length (the nameAlg digest
    /// size).
    pub(crate) fn derive_primary_object_seed(
        &self,
        primary_seed: &[u8],
        template: &TpmtPublic,
        sensitive_data: &[u8],
        obj_seed: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        let name_alg = template
            .name_alg
            .ok_or(TpmRc::HASH.with(Position::parameter(2)))?;
        let mut pub_buf = [0u8; TpmtPublic::MAX_SIZE];
        let pub_len = template.marshal(&mut pub_buf);
        let template_name = self.compute_name(Some(name_alg), &pub_buf[..pub_len])?;
        let digest_size = name_alg.digest_size();
        kdfa(
            self.crypto(),
            name_alg,
            primary_seed,
            b"Primary Object Creation",
            template_name.get_buffer(),
            sensitive_data,
            (digest_size * 8) as u32,
            obj_seed,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        Ok(digest_size)
    }

    /// Returns the `seedValue` that is kept in an object's sensitive area.
    ///
    /// C `CryptCreateObject` generates a nameAlg-sized `seedValue` for every object but
    /// discards it again for asymmetric keys that are not parents (`sign` SET or `restricted`
    /// CLEAR), so such keys carry an empty `seedValue`.
    pub(crate) fn object_seed_value<'s>(public: &TpmtPublic, seed: &'s [u8]) -> &'s [u8] {
        let attrs = public.object_attributes;
        let asymmetric = matches!(
            public.parms_and_id,
            PublicParmsAndId::Rsa(_, _) | PublicParmsAndId::Ecc(_, _)
        );
        if asymmetric
            && (attrs.contains(TpmaObject::SIGN_ENCRYPT) || !attrs.contains(TpmaObject::RESTRICTED))
        {
            &[]
        } else {
            seed
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
        let (stored_seed, seed_len) = TransientObject::seed_from_bytes(obj_seed);

        self.global_state.transient_parents[index] = parent_handle;
        self.global_state.transient_objects[index] = Some(TransientObject {
            handle,
            seed: stored_seed,
            seed_len,
            external: false,
            public_only: false,
            name,
            auth: user_auth,
            public: public_struct,
            private: private_key,
            private_len: private_key_len,
            qualified_name,
            hierarchy,
            st_clear,
        });
    }

    /// Resolves the parent object seed, hierarchy, qualified name, and auth requirement
    /// from the parent_handle argument.
    ///
    /// For object parents this mirrors C `ObjectIsParent` / `attributes.derivation`
    /// (`ObjectSetLoadedAttributes`): an object is an ordinary parent iff it is `restricted`,
    /// `decrypt`, has a sensitive area (not public-only), is not external, has a non-NULL
    /// `nameAlg` and is not a KEYEDHASH; restricted-decrypt KEYEDHASH objects are derivation
    /// parents. Sequence objects, non-parents and (unless `allow_derivation_parent`, used by
    /// `TPM2_CreateLoaded`) derivation parents are rejected with `TPM_RC_TYPE + RC_H1`.
    pub(crate) fn resolve_parent_object_or_hierarchy(
        &mut self,
        parent_handle: u32,
        parent_seed_val: &mut [u8; 64],
        parent_qn_buf: &mut [u8; 66],
        allow_derivation_parent: bool,
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
                scheme: None,
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
                scheme: None,
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
                scheme: None,
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
                scheme: None,
            })
        } else if parent_handle >> 24 == 0x80 || parent_handle >> 24 == 0x81 {
            // Sequence objects are never parents (C: `ObjectIsParent()` is FALSE).
            if parent_handle >> 24 == 0x80
                && self
                    .global_state
                    .find_active_sequence(parent_handle)
                    .is_some()
            {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }
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
            let attrs = obj.public.object_attributes;
            // C `ObjectSetLoadedAttributes`: only non-external objects with a sensitive area,
            // `restricted` and `decrypt` SET and a non-NULL nameAlg get `isParent` (or
            // `derivation` for KEYEDHASH).
            if !attrs.contains(TpmaObject::DECRYPT)
                || !attrs.contains(TpmaObject::RESTRICTED)
                || obj.external
                || obj.public_only
                || obj.public.name_alg.is_none()
            {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }
            let is_derivation_parent = matches!(
                &obj.public.parms_and_id,
                crate::owned::OwnedPublicParmsAndId::KeyedHash(_, _)
            );
            if !allow_derivation_parent && is_derivation_parent {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }
            Ok(self.parent_info_from_object(&obj, parent_seed_val, parent_qn_buf))
        } else {
            Err(TpmRc::HANDLE.to_rc())
        }
    }

    /// Builds the [`ResolvedParentInfo`] (protection seed, qualified name, nameAlg and
    /// symmetric key size) of a loaded parent object without any type checks.
    ///
    /// The protection seed is the parent's full `seedValue` (C `ComputeProtectionKeyParms`
    /// uses `protector->sensitive.seedValue` unmodified). For a derivation parent (KEYEDHASH)
    /// the derivation secret is the parent's `sensitive.bits` and the KDF hash is
    /// `scheme.details.xor.hashAlg` (C `CreateLoaded.c` `DRBG_InstantiateSeededKdf`).
    pub(crate) fn parent_info_from_object(
        &self,
        obj: &TransientObject,
        parent_seed_val: &mut [u8; 64],
        parent_qn_buf: &mut [u8; 66],
    ) -> ResolvedParentInfo {
        let attrs = obj.public.object_attributes;
        let parent_has_st_clear = obj.st_clear || attrs.contains(TpmaObject::ST_CLEAR);
        let dyn_qn = self.get_dynamic_qualified_name(obj);
        let qn_buf = dyn_qn.get_buffer();
        let qn_len = qn_buf.len();
        parent_qn_buf[..qn_len].copy_from_slice(qn_buf);
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
        let mut name_alg = obj.public.name_alg.unwrap_or(TpmiAlgHash::Sha256);
        let is_derivation_parent = matches!(
            &obj.public.parms_and_id,
            crate::owned::OwnedPublicParmsAndId::KeyedHash(_, _)
        ) && attrs.contains(TpmaObject::RESTRICTED)
            && attrs.contains(TpmaObject::DECRYPT);
        let seed_len = if is_derivation_parent {
            if let crate::owned::OwnedPublicParmsAndId::KeyedHash(
                Some(TpmtKeyedHashScheme::ExclusiveOr(xor)),
                _,
            ) = &obj.public.parms_and_id
            {
                name_alg = xor.hash_alg;
            }
            let len = core::cmp::min(obj.private_len, parent_seed_val.len());
            parent_seed_val[..len].copy_from_slice(&obj.private[..len]);
            len
        } else {
            let seed = obj.seed_bytes();
            parent_seed_val[..seed.len()].copy_from_slice(seed);
            seed.len()
        };
        ResolvedParentInfo {
            req_auth: attrs.contains(TpmaObject::USER_WITH_AUTH),
            seed_len,
            qn_len,
            hierarchy_val: obj.hierarchy,
            has_st_clear: parent_has_st_clear,
            name_alg,
            sym_bits,
            attributes: attrs,
            is_derivation_parent,
            scheme: Some(ParentSchemeInfo {
                name_alg: obj.public.name_alg,
                symmetric: match &obj.public.parms_and_id {
                    crate::owned::OwnedPublicParmsAndId::Rsa(parms, _) => parms.symmetric,
                    crate::owned::OwnedPublicParmsAndId::Ecc(parms, _) => parms.symmetric,
                    crate::owned::OwnedPublicParmsAndId::Sym(sym, _) => Some(*sym),
                    _ => None,
                },
                is_derivation: is_derivation_parent,
            }),
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
        parent_scheme: Option<ParentSchemeInfo>,
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

        // 5. Special checks for objects derived from a derivation parent.
        if let Some(parent) = parent_scheme
            && parent.is_derivation
        {
            let parent_fixed_tpm = parent_attributes
                .map(|a| a.contains(TpmaObject::FIXED_TPM))
                .unwrap_or(false);
            // A derived object has the same fixedTPM setting as its parent and must be
            // fixedParent.
            if fixed_tpm != parent_fixed_tpm || !fixed_parent {
                return Err(TpmRc::ATTRIBUTES.with(error_pos));
            }
        }

        // RSA key size and exponent sanity (unmarshal-time / `CryptValidateKeys` checks).
        if let PublicParmsAndId::Rsa(parms, _) = &public_struct.parms_and_id {
            if !matches!(parms.key_bits.0, 1024 | 2048 | 3072 | 4096) {
                return Err(TpmRc::VALUE.with(error_pos));
            }
            if parms.exponent != 0 && parms.exponent != 65537 {
                return Err(TpmRc::VALUE.with(error_pos));
            }
        }

        // 6. Scheme checks per key type (C `SchemeChecks`).
        Self::scheme_checks(public_struct, parent_scheme).map_err(|e| e.with_position(error_pos))
    }

    /// Validates the schemes in a public area (C `SchemeChecks`), returning unpositioned
    /// errors (callers add the public-area parameter position).
    ///
    /// - SYMCIPHER: a decryption key must use a block cipher mode or `TPM_ALG_NULL`; a signing
    ///   key may use any mode that unmarshaled.
    /// - KEYEDHASH: `sign == decrypt` (incl. sealed data) requires a NULL scheme, a signing key
    ///   requires HMAC, a decryption key requires XOR (with SP800-108 and a hash for
    ///   derivation parents).
    /// - RSA/ECC: dual-use keys need a NULL scheme; signing keys need a signing scheme (or NULL
    ///   if unrestricted); restricted decryption keys need a NULL scheme and unrestricted ones a
    ///   decryption scheme or NULL; non-parents must have a NULL symmetric; ECC KDF must be NULL.
    /// - Storage parents (`restricted` and `decrypt`) need a symmetric algorithm and, when
    ///   `fixedParent` is SET under a parent object, the parent's nameAlg and symmetric.
    pub(crate) fn scheme_checks(
        public_struct: &TpmtPublic,
        parent_scheme: Option<ParentSchemeInfo>,
    ) -> Result<(), TpmRc> {
        let attrs = public_struct.object_attributes;
        let restricted = attrs.contains(TpmaObject::RESTRICTED);
        let sign = attrs.contains(TpmaObject::SIGN_ENCRYPT);
        let decrypt = attrs.contains(TpmaObject::DECRYPT);
        // `None` = this type has no symmetric definition (KEYEDHASH); `Some(sym)` otherwise.
        let sym_algs: Option<Option<tpm2::TpmtSymDefObject>> = match &public_struct.parms_and_id {
            PublicParmsAndId::Sym(sym, _) => {
                if decrypt
                    && !matches!(
                        sym.mode(),
                        None | Some(
                            TpmiAlgSymMode::CTR
                                | TpmiAlgSymMode::OFB
                                | TpmiAlgSymMode::CBC
                                | TpmiAlgSymMode::CFB
                                | TpmiAlgSymMode::ECB
                        )
                    )
                {
                    return Err(TpmRc::SCHEME.to_rc());
                }
                Some(Some(*sym))
            }
            PublicParmsAndId::KeyedHash(scheme, _) => {
                if let Some(TpmtKeyedHashScheme::ExclusiveOr(s)) = scheme
                    && s.kdf == Some(tpm2::TpmiAlgKdf::Hkdf)
                {
                    return Err(TpmRc::KDF.to_rc());
                }
                if sign == decrypt {
                    if scheme.is_some() {
                        return Err(TpmRc::SCHEME.to_rc());
                    }
                } else if sign {
                    if !matches!(scheme, Some(TpmtKeyedHashScheme::Hmac(_))) {
                        return Err(TpmRc::SCHEME.to_rc());
                    }
                } else {
                    match scheme {
                        Some(TpmtKeyedHashScheme::ExclusiveOr(s)) => {
                            if restricted && s.kdf != Some(tpm2::TpmiAlgKdf::Kdf1Sp800_108) {
                                return Err(TpmRc::SCHEME.to_rc());
                            }
                        }
                        _ => return Err(TpmRc::SCHEME.to_rc()),
                    }
                }
                None
            }
            PublicParmsAndId::Rsa(parms, _) => {
                let scheme = parms.scheme.map(|s| s.scheme());
                let is_sign_scheme = matches!(scheme, Some(Alg::RSASSA) | Some(Alg::RSAPSS));
                let is_decrypt_scheme = matches!(scheme, Some(Alg::RSAES) | Some(Alg::OAEP));
                Self::asym_scheme_checks(
                    attrs,
                    scheme.is_some(),
                    is_sign_scheme,
                    is_decrypt_scheme,
                    parms.symmetric.is_some(),
                )?;
                Some(parms.symmetric)
            }
            PublicParmsAndId::Ecc(parms, _) => {
                let scheme = parms.scheme.map(|s| s.scheme());
                let is_sign_scheme = matches!(
                    scheme,
                    Some(Alg::ECDSA) | Some(Alg::ECDAA) | Some(Alg::ECSCHNORR) | Some(Alg::SM2)
                );
                let is_decrypt_scheme =
                    matches!(scheme, Some(Alg::ECDH) | Some(Alg::SM2) | Some(Alg::ECMQV));
                Self::asym_scheme_checks(
                    attrs,
                    scheme.is_some(),
                    is_sign_scheme,
                    is_decrypt_scheme,
                    parms.symmetric.is_some(),
                )?;
                if parms.kdf.is_some() {
                    return Err(TpmRc::KDF.to_rc());
                }
                Some(parms.symmetric)
            }
            PublicParmsAndId::Mldsa(_, _)
            | PublicParmsAndId::HashMldsa(_, _)
            | PublicParmsAndId::Mlkem(_, _) => return Ok(()),
        };

        // A restricted decryption key with symmetric algorithms is an ordinary parent: it needs
        // a symmetric algorithm and, if it is not duplicable, the parent's algorithms.
        if let Some(sym) = sym_algs
            && restricted
            && decrypt
        {
            let sym = sym.ok_or(TpmRc::SYMMETRIC.to_rc())?;
            if attrs.contains(TpmaObject::FIXED_PARENT)
                && let Some(parent) = parent_scheme
            {
                if public_struct.name_alg != parent.name_alg {
                    return Err(TpmRc::HASH.to_rc());
                }
                if parent.symmetric != Some(sym) {
                    return Err(TpmRc::SYMMETRIC.to_rc());
                }
            }
        }
        Ok(())
    }

    /// Asymmetric (RSA/ECC) part of [`Self::scheme_checks`].
    fn asym_scheme_checks(
        attrs: TpmaObject,
        has_scheme: bool,
        is_sign_scheme: bool,
        is_decrypt_scheme: bool,
        has_symmetric: bool,
    ) -> Result<(), TpmRc> {
        let restricted = attrs.contains(TpmaObject::RESTRICTED);
        let sign = attrs.contains(TpmaObject::SIGN_ENCRYPT);
        let decrypt = attrs.contains(TpmaObject::DECRYPT);
        if sign == decrypt {
            // There is no way to specify both a sign and a decrypt scheme.
            if has_scheme {
                return Err(TpmRc::SCHEME.to_rc());
            }
        } else if sign {
            // A signing key without a signing scheme is only OK if unrestricted and NULL.
            if !is_sign_scheme && (restricted || has_scheme) {
                return Err(TpmRc::SCHEME.to_rc());
            }
        } else if restricted {
            // A restricted decryption key (a parent) must have a NULL scheme.
            if has_scheme {
                return Err(TpmRc::SCHEME.to_rc());
            }
        } else if has_scheme && !is_decrypt_scheme {
            return Err(TpmRc::SCHEME.to_rc());
        }
        // An asymmetric key that is not a parent must have a NULL symmetric algorithm.
        if (!restricted || !decrypt) && has_symmetric {
            return Err(TpmRc::SYMMETRIC.to_rc());
        }
        Ok(())
    }

    /// Performs validation checks on the public and sensitive area parameters of the target object
    /// template to ensure cryptographic attributes consistency and spec requirements alignment.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_create_loaded_parameters(
        &self,
        in_public_struct: &TpmtPublic,
        in_sensitive_struct: &TpmsSensitiveCreate,
        parent_handle: u32,
        parent_hierarchy_val: u32,
        parent_attributes: Option<TpmaObject>,
        is_derived: bool,
        parent_scheme: Option<ParentSchemeInfo>,
    ) -> Result<(bool, bool), TpmRc> {
        let is_primary = parent_handle == 0x40000001
            || parent_handle == 0x40000007
            || parent_handle == 0x4000000C
            || parent_handle == 0x4000000B;

        // AdjustAuthSize: a NULL nameAlg allows `sizeof(TPMU_HA)` (64) bytes; the NULL nameAlg
        // itself is then rejected with `TPM_RC_HASH + RC_P2` by `validate_object_attributes`.
        let digest_size = in_public_struct
            .name_alg
            .map_or(64, |alg| alg.digest_size());

        if crate::util::strip_trailing_zeros(in_sensitive_struct.user_auth.get_buffer()).len()
            > digest_size
        {
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

        if !is_derived {
            self.create_checks(in_public_struct, in_sensitive_struct, is_primary)
                .map_err(|e| e.with_position(Position::parameter(2)))?;
        }

        self.validate_object_attributes(
            in_public_struct,
            parent_handle,
            parent_hierarchy_val,
            parent_attributes,
            false, // is_import
            false, // allow_null_name_alg
            Position::parameter(2),
            parent_scheme,
        )?;

        if !is_derived {
            if let PublicParmsAndId::Sym(sym, _) = &in_public_struct.parms_and_id {
                if !sensitive_data_origin {
                    let key_bytes = (sym.key_bits() as usize) / 8;
                    if key_bytes > 0 && in_sensitive_struct.data.get_size() as usize != key_bytes {
                        return Err(TpmRc::KEY_SIZE.with(Position::parameter(1)));
                    }
                }
            } else if in_sensitive_struct.data.get_size() as usize
                > tpm2::TPM2_MAX_SYM_DATA as usize
            {
                return Err(TpmRc::SIZE.with(Position::parameter(1)));
            }
        }

        Ok((is_primary, is_derived))
    }

    /// Attribute checks that are unique to object creation (C `CreateChecks`), returning
    /// unpositioned errors (callers add `RC_..._inPublic`):
    /// - if the caller supplies the sensitive data (`sensitiveDataOrigin` CLEAR) it must not be
    ///   empty, and an ordinary object may not get data when `sensitiveDataOrigin` is SET
    ///   (primary objects may: the data is extra KDF input);
    /// - a KEYEDHASH data object (`sign` and `decrypt` CLEAR) can not have
    ///   `sensitiveDataOrigin` SET;
    /// - a restricted SYMCIPHER/KEYEDHASH key needs `sensitiveDataOrigin` SET unless both
    ///   `fixedParent` and `fixedTPM` are CLEAR;
    /// - asymmetric keys can not have their sensitive part provided.
    pub(crate) fn create_checks(
        &self,
        in_public_struct: &TpmtPublic,
        in_sensitive_struct: &TpmsSensitiveCreate,
        is_primary: bool,
    ) -> Result<(), TpmRc> {
        let attrs = in_public_struct.object_attributes;
        let sdo = attrs.contains(TpmaObject::SENSITIVE_DATA_ORIGIN);
        let data_size = in_sensitive_struct.data.get_size();
        if !sdo && data_size == 0 {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }
        if !is_primary && sdo && data_size != 0 {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }
        let restricted_symmetric_without_sdo = attrs.contains(TpmaObject::RESTRICTED)
            && !sdo
            && (attrs.contains(TpmaObject::FIXED_PARENT) || attrs.contains(TpmaObject::FIXED_TPM));
        match &in_public_struct.parms_and_id {
            PublicParmsAndId::KeyedHash(_, _) => {
                if (!attrs.contains(TpmaObject::SIGN_ENCRYPT)
                    && !attrs.contains(TpmaObject::DECRYPT)
                    && sdo)
                    || restricted_symmetric_without_sdo
                {
                    return Err(TpmRc::ATTRIBUTES.to_rc());
                }
            }
            PublicParmsAndId::Sym(_, _) => {
                if restricted_symmetric_without_sdo {
                    return Err(TpmRc::ATTRIBUTES.to_rc());
                }
            }
            _ => {
                if !sdo {
                    return Err(TpmRc::ATTRIBUTES.to_rc());
                }
            }
        }
        Ok(())
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

        // C `MarshalSensitive`: the encrypted payload of an ordinary `TPM2B_PRIVATE` is a
        // `TPM2B_SENSITIVE`, i.e. the 2-byte size of the `TPMT_SENSITIVE` followed by it (there is
        // no inner wrapper outside of duplication blobs).
        let mut unencrypted_blob = [0u8; 2048];
        let unencrypted_len = 2 + sensitive_len;
        unencrypted_blob[..unencrypted_len]
            .copy_from_slice(&tpm2b_sensitive_buf[..unencrypted_len]);

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

        // MarshalSensitive: the authValue is zero-padded to the nameAlg digest size so that the
        // ciphertext length does not leak its length.
        let digest_size = in_public_struct.name_alg.map_or(0, |alg| alg.digest_size());
        let auth = crate::util::strip_trailing_zeros(in_sensitive_struct.user_auth.get_buffer());
        let mut padded_auth = [0u8; 64];
        padded_auth[..auth.len()].copy_from_slice(auth);
        let auth_len = core::cmp::max(auth.len(), digest_size);
        let tpmt_sensitive = TpmtSensitive {
            auth_value: tpm2::Tpm2bAuth::from_bytes(&padded_auth[..auth_len])
                .map_err(|_| TpmRc::FAILURE)?,
            seed_value: Tpm2bDigest::from_bytes(Self::object_seed_value(
                in_public_struct,
                obj_seed,
            ))
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
