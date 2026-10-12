//! Helpers shared by the object handlers ([`TpmCc::Create`](create.rs),
//! [`TpmCc::CreatePrimary`](create_primary.rs), [`TpmCc::Load`](load.rs),
//! [`TpmCc::ObjectChangeAuth`](object_change_auth.rs)) and `TPM2_Import` (`import.rs`).
//!
//! PORTING: exp defined these in `handler/create_loaded.rs` (and `compute_creation_ticket` in
//! `handler/certify.rs`). `TPM2_CreateLoaded` is dropped, and with it the creation of derived
//! objects (only `TPM2_CreateLoaded` could use a derivation parent), so the derivation-only
//! parameters of exp's helpers (`is_derived`, `template_derive`) are gone.

use super::{CommandHandler, ResolvedParentInfo, TransientObject};
use crate::Crypto;
use crate::owned::{
    OwnedAuth, OwnedDigest, OwnedName, OwnedPublic, OwnedPublicParmsAndId, OwnedSensitiveComposite,
};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::crypto::{HmacStream, ModeIv, SymmetricKey, encrypt, kdfa};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Handle, Marshal, PublicParmsAndId, Tpm2bDigest, Tpm2bName, Tpm2bPrivate,
    Tpm2bSensitiveData, TpmHt, TpmSt, TpmaObject, TpmiAlgHash, TpmiAlgKdf, TpmiAlgSymMode,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme,
    TpmtSensitive, Unmarshal,
};

/// `TPMA_OBJECT.firmwareLimited` (bit 8, Part 2, Section 8.3). Not provided by [`TpmaObject`].
const FIRMWARE_LIMITED: TpmaObject = TpmaObject(1 << 8);
/// `TPMA_OBJECT.svnLimited` (bit 9, Part 2, Section 8.3). Not provided by [`TpmaObject`].
const SVN_LIMITED: TpmaObject = TpmaObject(1 << 9);

/// Size of the empty inner integrity `TPM2B_DIGEST` that precedes the sensitive area in exp's
/// encrypted private blob.
const INNER_INTEGRITY_LEN: usize = 2;

/// Returns `true` for the hierarchy handles exp accepted as the parent of a primary object
/// (`TPM_RH_OWNER`, `TPM_RH_NULL`, `TPM_RH_PLATFORM` and `TPM_RH_ENDORSEMENT`).
fn is_primary_parent(handle: u32) -> bool {
    matches!(
        Handle(handle),
        Handle::RH_OWNER | Handle::RH_NULL | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT
    )
}

/// Returns the `unique` field of a public area as two byte slices whose concatenation is the
/// value exp fed to KDFa when deriving a primary object seed (`x || y` for an ECC point).
///
/// KDFa hashes `contextU || contextV`, so passing the two halves as `contextU` and `contextV`
/// is equivalent to exp's concatenated copy.
pub(crate) fn unique_parts(parms_and_id: PublicParmsAndId<'_>) -> (&[u8], &[u8]) {
    match parms_and_id {
        PublicParmsAndId::KeyedHash(_, unique) | PublicParmsAndId::Sym(_, unique) => {
            (unique.as_slice(), &[])
        }
        PublicParmsAndId::Rsa(_, unique) => (unique.as_slice(), &[]),
        PublicParmsAndId::Ecc(_, point) => (point.x.as_slice(), point.y.as_slice()),
        PublicParmsAndId::Mldsa(_, unique) | PublicParmsAndId::HashMldsa(_, unique) => {
            (unique.as_slice(), &[])
        }
        PublicParmsAndId::Mlkem(_, unique) => (unique.as_slice(), &[]),
    }
}

/// Returns `TPM_RC_HASH` at `pos` if the `TPM2B_PUBLIC` parameter that directly follows the
/// parameter `P` at the start of `params` has a `TPM_ALG_NULL` `nameAlg`.
///
/// PORTING: exp unmarshaled `TPM2B_PUBLIC` command parameters (other than the `TPM2B_PUBLIC+`
/// of `TPM2_LoadExternal`) with a strict `TPMT_PUBLIC` unmarshal: after a valid `type`, a
/// `TPM_ALG_NULL` `nameAlg` failed with `TPM_RC_HASH` before the rest of the structure (and any
/// later parameter) was read. The new [`TpmtPublic`] accepts it as `None`. Evaluate this on the
/// parameter area before `try_unmarshal_command` and return its error first.
pub(crate) fn null_name_alg_error<'a, P: Unmarshal<'a>>(
    mut params: &'a [u8],
    pos: Position,
) -> Option<TpmRc> {
    P::unmarshal(&mut params).ok()?;
    // TPM2B_PUBLIC: size (u16) | type (TPMI_ALG_PUBLIC) | nameAlg (TPMI_ALG_HASH) | ...
    // exp rejected a zero size before reading the structure, and read `type` / `nameAlg` even
    // when they extended past `size`.
    let (size, rest) = params.split_first_chunk::<2>()?;
    if u16::from_be_bytes(*size) == 0 {
        return None;
    }
    let (public_type, rest) = rest.split_first_chunk::<2>()?;
    let (name_alg, _) = rest.split_first_chunk::<2>()?;
    let is_public_type = matches!(
        Alg::from(u16::from_be_bytes(*public_type)),
        Alg::KEYEDHASH
            | Alg::SYMCIPHER
            | Alg::RSA
            | Alg::ECC
            | Alg::MLDSA
            | Alg::HASH_MLDSA
            | Alg::MLKEM
    );
    (is_public_type && Alg::from(u16::from_be_bytes(*name_alg)) == Alg::NULL)
        .then_some(TpmRc::HASH.with(pos))
}

/// Returns the AES-CFB key of exp's storage protection for `key` (`sym_key_bits` long).
///
/// exp always used AES (in CFB mode) with the parent's symmetric key size, regardless of the
/// parent's symmetric algorithm.
fn storage_key(sym_key_bits: u16, key: &[u8]) -> Result<SymmetricKey<'_>, TpmRc> {
    AlgSym::new(Alg::AES, sym_key_bits)
        .and_then(|alg| SymmetricKey::new(alg, key))
        .ok_or(TpmRc::FAILURE)
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Helper function to derive or generate the random seed for the newly created object.
    ///
    /// Primary objects derive the seed from the parent (hierarchy) seed and the template's
    /// `unique` field; ordinary objects get a random seed. Returns the seed length (the digest
    /// size of `parent_name_alg`).
    ///
    /// PORTING: exp's derived-object branch (`is_derived`, `template_derive`) is gone with
    /// `TPM2_CreateLoaded`; `parent_seed_len` is `parent_seed_val.len()`.
    pub(crate) fn derive_create_loaded_seed(
        &mut self,
        is_primary: bool,
        parent_seed_val: &[u8],
        in_public_struct: &TpmtPublic<'_>,
        parent_name_alg: TpmiAlgHash,
        obj_seed: &mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
    ) -> Result<usize, TpmRc> {
        let digest_size = parent_name_alg.digest_size();
        let seed = obj_seed.get_mut(..digest_size).ok_or(TpmRc::FAILURE)?;

        if is_primary {
            let (unique_u, unique_v) = unique_parts(in_public_struct.parms_and_id);
            kdfa(
                self.crypto(),
                parent_name_alg,
                parent_seed_val,
                c"Primary Object Creation",
                unique_u,
                unique_v,
                seed,
            )
            .map_err(|_| TpmRc::FAILURE)?;
        } else {
            self.fill_random(seed).map_err(|_| TpmRc::FAILURE)?;
        }
        Ok(digest_size)
    }

    /// Helper function to format and store the transient object into the global state table.
    ///
    /// PORTING: exp's `private_key` / `private_key_len` are now `sensitive`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_transient_object(
        &mut self,
        index: usize,
        handle: u32,
        seed: OwnedDigest,
        name: OwnedName,
        user_auth: OwnedAuth,
        public_struct: OwnedPublic,
        sensitive: OwnedSensitiveComposite,
        qualified_name: OwnedName,
        parent_handle: Option<u32>,
        hierarchy: u32,
        st_clear: bool,
    ) {
        self.global_state.transient_parents[index] = parent_handle;
        self.global_state.transient_objects[index] = Some(TransientObject {
            handle,
            seed,
            name,
            auth: user_auth,
            public: public_struct,
            sensitive,
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
        parent_seed_val: &mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
        parent_qn_buf: &mut [u8; Tpm2bName::CAP],
        expect_type_error: bool,
    ) -> Result<ResolvedParentInfo, TpmRc> {
        let state = &*self.global_state;
        let hierarchy_seed: Option<(&[u8], u16)> = match Handle(parent_handle) {
            Handle::RH_OWNER => Some((&state.sp_seed, state.sp_seed_size)),
            Handle::RH_NULL => Some((&[], 0)),
            Handle::RH_PLATFORM => Some((&state.pp_seed, state.pp_seed_size)),
            Handle::RH_ENDORSEMENT => Some((&state.ep_seed, state.ep_seed_size)),
            _ => None,
        };
        if let Some((seed, seed_size)) = hierarchy_seed {
            let seed_len = usize::from(seed_size);
            parent_qn_buf[..4].copy_from_slice(&parent_handle.to_be_bytes());
            parent_seed_val
                .get_mut(..seed_len)
                .ok_or(TpmRc::FAILURE)?
                .copy_from_slice(seed.get(..seed_len).ok_or(TpmRc::FAILURE)?);
            return Ok(ResolvedParentInfo {
                req_auth: true,
                seed_len,
                qn_len: 4,
                hierarchy_val: parent_handle,
                has_st_clear: false,
                name_alg: TpmiAlgHash::Sha256,
                sym_bits: 128,
                attributes: TpmaObject(0),
                is_derivation_parent: false,
            });
        }

        let parent_type = Handle(parent_handle).handle_type();
        if parent_type != Some(TpmHt::Transient) && parent_type != Some(TpmHt::Persistent) {
            return Err(TpmRc::HANDLE.to_rc());
        }
        let obj = if parent_type == Some(TpmHt::Transient) {
            self.global_state
                .find_transient_object(parent_handle)
                .cloned()
                .ok_or(TpmRc::REFERENCE_H0)?
        } else {
            self.context
                .load_persistent_object(self.global_state, parent_handle)
                .map_err(|_| TpmRc::REFERENCE_H0)?
        };
        let attributes = obj.public.object_attributes;
        let parent_has_st_clear = obj.st_clear || attributes.contains(TpmaObject::ST_CLEAR);
        if !attributes.contains(TpmaObject::DECRYPT) || !attributes.contains(TpmaObject::RESTRICTED)
        {
            return Err(if expect_type_error {
                TpmRc::TYPE.with(Position::handle(1))
            } else {
                TpmRc::ATTRIBUTES.with(Position::handle(1))
            });
        }
        let is_derivation_parent = matches!(
            &obj.public.parms_and_id,
            OwnedPublicParmsAndId::KeyedHash(Some(TpmtKeyedHashScheme::Xor(_)), _)
        );
        if expect_type_error && is_derivation_parent {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }
        let parent_req_auth = attributes.contains(TpmaObject::USER_WITH_AUTH);
        let dyn_qn = self.get_dynamic_qualified_name(&obj);
        let qn_buf = dyn_qn.get_buffer();
        let qn_len = qn_buf.len();
        parent_qn_buf
            .get_mut(..qn_len)
            .ok_or(TpmRc::FAILURE)?
            .copy_from_slice(qn_buf);
        let name_alg = obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        // Primary objects store a 32-byte seed whatever their nameAlg; children are protected
        // with at most a nameAlg digest of it.
        let seed = obj.seed.get_buffer();
        let seed = &seed[..seed.len().min(name_alg.digest_size())];
        parent_seed_val
            .get_mut(..seed.len())
            .ok_or(TpmRc::FAILURE)?
            .copy_from_slice(seed);
        let mut sym_bits = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, _) => {
                parms.symmetric.map_or(128, |s| s.alg.key_bits())
            }
            OwnedPublicParmsAndId::Ecc(parms, _) => {
                parms.symmetric.map_or(128, |s| s.alg.key_bits())
            }
            _ => 128,
        };
        if sym_bits == 0 {
            sym_bits = 128;
        }
        Ok(ResolvedParentInfo {
            req_auth: parent_req_auth,
            seed_len: seed.len(),
            qn_len,
            hierarchy_val: obj.hierarchy,
            has_st_clear: parent_has_st_clear,
            name_alg,
            sym_bits,
            attributes,
            is_derivation_parent,
        })
    }

    /// Performs comprehensive structural and attribute validation on an object's public template (`TPMA_OBJECT`),
    /// checking scheme consistency and Table 31 requirements.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_object_attributes(
        &self,
        public_struct: &TpmtPublic<'_>,
        parent_handle: u32,
        parent_hierarchy_val: u32,
        parent_attributes: Option<TpmaObject>,
        is_import: bool,
        allow_null_name_alg: bool,
        error_pos: Position,
    ) -> Result<(), TpmRc> {
        let attr_err = TpmRc::ATTRIBUTES.with(error_pos);
        let scheme_err = TpmRc::SCHEME.with(error_pos);

        let name_alg_opt = public_struct.name_alg;
        if !allow_null_name_alg && name_alg_opt.is_none() {
            return Err(TpmRc::HASH.with(error_pos));
        }

        // 2. If there is an authPolicy, it needs to be the size of the digest produced by nameAlg
        let auth_policy_len = public_struct.auth_policy.as_slice().len();
        if auth_policy_len != 0 {
            if let Some(name_alg) = name_alg_opt {
                if auth_policy_len != name_alg.digest_size() {
                    return Err(TpmRc::SIZE.with(error_pos));
                }
            } else if !allow_null_name_alg {
                return Err(TpmRc::HASH.with(error_pos));
            }
        }

        let attr = public_struct.object_attributes;
        if (attr.0 & 0xfff0_f009) != 0 {
            return Err(TpmRc::RESERVED_BITS.with(error_pos));
        }
        let restricted = attr.contains(TpmaObject::RESTRICTED);
        let sign = attr.contains(TpmaObject::SIGN_ENCRYPT);
        let decrypt = attr.contains(TpmaObject::DECRYPT);
        let fixed_tpm = attr.contains(TpmaObject::FIXED_TPM);
        let fixed_parent = attr.contains(TpmaObject::FIXED_PARENT);
        let encrypted_duplication = attr.contains(TpmaObject::ENCRYPTED_DUPLICATION);

        let is_primary = is_primary_parent(parent_handle);
        let parent_type = Handle(parent_handle).handle_type();

        // 3. Attribute hierarchy/parent consistency (Table 31 fixedTPM, fixedParent, encryptedDuplication)
        if is_import {
            // For TPM2_Import, fixedTPM and fixedParent SHALL be CLEAR in object_public
            if fixed_tpm || fixed_parent {
                return Err(attr_err);
            }
        } else if is_primary {
            // For a Primary Object, fixedTPM and fixedParent SHALL both be SET or both be CLEAR
            if fixed_tpm != fixed_parent {
                return Err(attr_err);
            }
        } else if parent_type == Some(TpmHt::Transient) || parent_type == Some(TpmHt::Persistent) {
            // For an ordinary/derived object under a parent handle:
            let pattr = parent_attributes.ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            let parent_fixed_tpm = pattr.contains(TpmaObject::FIXED_TPM);
            let parent_encrypted_duplication = pattr.contains(TpmaObject::ENCRYPTED_DUPLICATION);

            // If fixedTPM is SET in the object's parent, then fixedTPM shall equal fixedParent.
            // If fixedTPM is CLEAR in the parent, fixedTPM shall also be CLEAR.
            if parent_fixed_tpm {
                if fixed_tpm != fixed_parent {
                    return Err(attr_err);
                }
            } else {
                if fixed_tpm {
                    return Err(attr_err);
                }
                // If parent fixedTPM is CLEAR, the child must have the same encryptedDuplication setting as its parent.
                if encrypted_duplication != parent_encrypted_duplication {
                    return Err(attr_err);
                }
            }
        }

        // If fixedTPM is SET, then fixedParent SHALL be SET (applies to ALL keys unless already checked above)
        if fixed_tpm && !fixed_parent {
            return Err(attr_err);
        }

        // For derived/ordinary objects in the Null hierarchy, fixedTPM and fixedParent MUST be CLEAR
        if !is_primary && parent_hierarchy_val == Handle::RH_NULL.0 && (fixed_tpm || fixed_parent) {
            return Err(attr_err);
        }

        // If the object can't be duplicated (directly or indirectly) then there is no justification for encryptedDuplication SET
        if fixed_tpm && encrypted_duplication {
            return Err(attr_err);
        }

        // firmwareLimited/svnLimited can only be set if fixedTPM is also set, and require a matching parent/hierarchy.
        let firmware_limited = attr.contains(FIRMWARE_LIMITED);
        let svn_limited = attr.contains(SVN_LIMITED);
        if (firmware_limited || svn_limited) && !fixed_tpm {
            return Err(attr_err);
        }
        // None of the standard hierarchies (Owner, Endorsement, Platform, Null) are
        // firmware-limited or SVN-limited.
        if firmware_limited && !parent_attributes.is_some_and(|p| p.contains(FIRMWARE_LIMITED)) {
            return Err(attr_err);
        }
        if svn_limited && !parent_attributes.is_some_and(|p| p.contains(SVN_LIMITED)) {
            return Err(attr_err);
        }

        // 4. Sign and Decrypt attribute validation & scheme check
        if sign == decrypt {
            // A restricted key cannot have both SET or both CLEAR (`sign == decrypt`)
            if restricted {
                return Err(attr_err);
            }
            // Only a data object (`TPM_ALG_KEYEDHASH` with sign/decrypt clear) may have both sign and decrypt CLEAR.
            if !sign && public_struct.parms_and_id.algorithm() != Alg::KEYEDHASH {
                return Err(attr_err);
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
                                return Err(scheme_err);
                            }
                        }
                        _ => {
                            return Err(scheme_err);
                        }
                    }
                }
                if decrypt && !sign {
                    if restricted && parms.scheme.is_some() {
                        return Err(scheme_err);
                    }
                    if !restricted
                        && matches!(
                            parms.scheme,
                            Some(TpmtRsaScheme::Rsassa(_)) | Some(TpmtRsaScheme::Rsapss(_))
                        )
                    {
                        return Err(scheme_err);
                    }
                }
                let key_bits = u16::from(parms.key_bits);
                if key_bits != 1024 && key_bits != 2048 && key_bits != 3072 && key_bits != 4096 {
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
                                return Err(scheme_err);
                            }
                        }
                        _ => {
                            return Err(scheme_err);
                        }
                    }
                }
                if decrypt && !sign {
                    if restricted && parms.scheme.is_some() {
                        return Err(scheme_err);
                    }
                    if !restricted
                        && matches!(
                            parms.scheme,
                            Some(TpmtEccScheme::Ecdsa(_))
                                | Some(TpmtEccScheme::Ecdaa(_))
                                | Some(TpmtEccScheme::Ecschnorr(_))
                        )
                    {
                        return Err(scheme_err);
                    }
                }
            }
            PublicParmsAndId::KeyedHash(scheme, _) => {
                if let Some(TpmtKeyedHashScheme::Xor(s)) = scheme
                    && s.kdf == Some(TpmiAlgKdf::Hkdf)
                {
                    return Err(TpmRc::KDF.with(error_pos));
                }
                if sign && decrypt && scheme.is_some() {
                    return Err(scheme_err);
                }
                if sign && !decrypt && !matches!(scheme, Some(TpmtKeyedHashScheme::Hmac(_)) | None)
                {
                    return Err(scheme_err);
                }
                if decrypt && !sign {
                    if !matches!(scheme, Some(TpmtKeyedHashScheme::Xor(_)) | None) {
                        return Err(scheme_err);
                    }
                    if let Some(TpmtKeyedHashScheme::Xor(s)) = scheme
                        && restricted
                        && s.kdf != Some(TpmiAlgKdf::Kdf1Sp800_108)
                    {
                        return Err(scheme_err);
                    }
                }
            }
            PublicParmsAndId::Sym(sym, _) => {
                if sign && !decrypt {
                    return Err(attr_err);
                }
                // exp accepted the block cipher modes (CTR, OFB, CBC, CFB, ECB), i.e. any mode
                // except CMAC and NULL.
                if decrypt && !matches!(sym.mode, Some(TpmiAlgSymMode::Cipher(_))) {
                    return Err(scheme_err);
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
    ///
    /// Returns whether the object is a primary object (`parent_handle` is a hierarchy).
    ///
    /// PORTING: exp also took `is_derived` (always `false` outside `TPM2_CreateLoaded`) and
    /// returned `(is_primary, is_derived)`.
    pub(crate) fn validate_create_loaded_parameters(
        &self,
        in_public_struct: &TpmtPublic<'_>,
        in_sensitive_struct: &TpmsSensitiveCreate<'_>,
        parent_handle: u32,
        parent_hierarchy_val: u32,
        parent_attributes: Option<TpmaObject>,
    ) -> Result<bool, TpmRc> {
        let is_primary = is_primary_parent(parent_handle);

        let alg = in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        let digest_size = alg.digest_size();

        if in_sensitive_struct.user_auth.as_slice().len() > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        let sensitive_data_origin = in_public_struct
            .object_attributes
            .contains(TpmaObject::SENSITIVE_DATA_ORIGIN);

        self.validate_object_attributes(
            in_public_struct,
            parent_handle,
            parent_hierarchy_val,
            parent_attributes,
            false, // is_import
            false, // allow_null_name_alg
            Position::parameter(2),
        )?;

        let data_len = in_sensitive_struct.data.as_slice().len();
        if let PublicParmsAndId::Sym(sym, _) = &in_public_struct.parms_and_id {
            if sensitive_data_origin && data_len != 0 {
                return Err(TpmRc::ATTRIBUTES.with(Position::parameter(2)));
            }
            if !sensitive_data_origin {
                let key_bytes = usize::from(sym.alg.key_bits()) / 8;
                if key_bytes > 0 && data_len != key_bytes {
                    return Err(TpmRc::KEY_SIZE.with(Position::parameter(1)));
                }
            }
        } else if (sensitive_data_origin && data_len != 0)
            || (!sensitive_data_origin
                && matches!(
                    in_public_struct.parms_and_id,
                    PublicParmsAndId::Rsa(_, _) | PublicParmsAndId::Ecc(_, _)
                ))
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::parameter(2)));
        } else if data_len > Tpm2bSensitiveData::CAP {
            // `TPM2_MAX_SYM_DATA`
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        Ok(is_primary)
    }

    /// Encrypts the sensitive area of the target object using storage seed and CFB mode,
    /// computes inner/outer integrity MAC hashes, and formats the output private buffer.
    ///
    /// The blob is exp's format: `integrity (TPM2B_DIGEST) | iv (TPM2B, 16 bytes) |
    /// AES-CFB(00 00 | TPMT_SENSITIVE)`, where `integrity` is the HMAC (with the parent's
    /// `nameAlg`) over `iv (TPM2B) | encrypted data | object_name`. Returns its length.
    ///
    /// PORTING: takes `&mut self` (the IV is drawn from the global RNG).
    pub(crate) fn encrypt_sensitive_area(
        &mut self,
        tpmt_sensitive: &TpmtSensitive<'_>,
        parent_seed_val: &[u8],
        object_name: &OwnedName,
        parent_name_alg: TpmiAlgHash,
        sym_key_bits: u16,
        private_buf: &mut [u8; Tpm2bPrivate::CAP],
    ) -> Result<usize, TpmRc> {
        let mut sensitive_buf = [0u8; TpmtSensitive::MAX_SIZE];
        let sensitive_len = tpmt_sensitive.marshal(&mut sensitive_buf);
        let sensitive = sensitive_buf.get(..sensitive_len).ok_or(TpmRc::FAILURE)?;

        // Inner integrity (empty) followed by the sensitive area.
        let mut blob_buf = [0u8; INNER_INTEGRITY_LEN + TpmtSensitive::MAX_SIZE];
        let blob_len = INNER_INTEGRITY_LEN + sensitive_len;
        let blob = blob_buf.get_mut(..blob_len).ok_or(TpmRc::FAILURE)?;
        blob[INNER_INTEGRITY_LEN..].copy_from_slice(sensitive);

        let digest_size = parent_name_alg.digest_size();

        // KDFa for symmetric key
        let mut sym_key_buf = [0u8; AlgSym::MAX_KEY_BYTES];
        let sym_key_len = usize::from(sym_key_bits / 8);
        let sym_key = sym_key_buf.get_mut(..sym_key_len).ok_or(TpmRc::FAILURE)?;
        kdfa(
            self.crypto(),
            parent_name_alg,
            parent_seed_val,
            c"STORAGE",
            object_name.get_buffer(),
            &[],
            sym_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let mut iv = [0u8; AlgSym::BLOCK_SIZE];
        self.fill_random(&mut iv).map_err(|_| TpmRc::FAILURE)?;
        let orig_iv = iv;

        encrypt(
            self.crypto(),
            storage_key(sym_key_bits, sym_key)?,
            ModeIv::Cfb(&mut iv),
            blob,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        // KDFa for MAC
        let mut mac_key_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mac_key = mac_key_buf.get_mut(..digest_size).ok_or(TpmRc::FAILURE)?;
        kdfa(
            self.crypto(),
            parent_name_alg,
            parent_seed_val,
            c"INTEGRITY",
            &[],
            &[],
            mac_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let iv_offset = 2 + digest_size;
        let enc_offset = iv_offset + 2 + AlgSym::BLOCK_SIZE;
        let private_len = enc_offset + blob_len;
        let out = private_buf.get_mut(..private_len).ok_or(TpmRc::FAILURE)?;
        let digest_size_bytes = u16::try_from(digest_size).map_err(|_| TpmRc::FAILURE)?;
        let iv_size_bytes = u16::try_from(AlgSym::BLOCK_SIZE).map_err(|_| TpmRc::FAILURE)?;
        out[..2].copy_from_slice(&digest_size_bytes.to_be_bytes());
        out[iv_offset..iv_offset + 2].copy_from_slice(&iv_size_bytes.to_be_bytes());
        out[iv_offset + 2..enc_offset].copy_from_slice(&orig_iv);
        out[enc_offset..].copy_from_slice(blob);

        let mut mac_ctx =
            HmacStream::new(self.crypto(), parent_name_alg, mac_key).map_err(|_| TpmRc::FAILURE)?;
        mac_ctx
            .update(&out[iv_offset..])
            .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx
            .update(object_name.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        let mut mac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mac = mac_ctx
            .finalize(&mut mac_buf)
            .map_err(|_| TpmRc::FAILURE)?
            .digest();
        out.get_mut(2..2 + mac.len())
            .ok_or(TpmRc::FAILURE)?
            .copy_from_slice(mac);

        Ok(private_len)
    }

    /// Helper function to build the sensitive struct and encrypt it into out_private.
    ///
    /// The private area of a primary object is still computed (as in exp), but an empty
    /// `TPM2B_PRIVATE` is returned for it.
    ///
    /// PORTING: exp took the object's public area (to pick the `TPMU_SENSITIVE_COMPOSITE`
    /// member) and the crypto provider's private key blob; `sensitive` is now that member.
    /// exp's `is_derived` is gone with `TPM2_CreateLoaded`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_and_encrypt_private_area<'c>(
        &mut self,
        in_sensitive_struct: &TpmsSensitiveCreate<'_>,
        sensitive: &OwnedSensitiveComposite,
        obj_seed: &[u8],
        parent_seed_val: &[u8],
        object_name: &OwnedName,
        is_primary: bool,
        parent_name_alg: TpmiAlgHash,
        sym_key_bits: u16,
        private_buf: &'c mut [u8; Tpm2bPrivate::CAP],
    ) -> Result<Tpm2bPrivate<'c>, TpmRc> {
        let tpmt_sensitive = TpmtSensitive {
            auth_value: in_sensitive_struct.user_auth,
            seed_value: Tpm2bDigest::new(obj_seed).ok_or(TpmRc::FAILURE)?,
            sensitive: sensitive.as_tpmu(),
        };

        let final_private_len = self.encrypt_sensitive_area(
            &tpmt_sensitive,
            parent_seed_val,
            object_name,
            parent_name_alg,
            sym_key_bits,
            private_buf,
        )?;

        if is_primary {
            return Ok(Tpm2bPrivate::default());
        }
        let private_buf: &'c [u8; Tpm2bPrivate::CAP] = private_buf;
        private_buf
            .get(..final_private_len)
            .and_then(Tpm2bPrivate::new)
            .ok_or(TpmRc::FAILURE)
    }

    /// Computes the HMAC-SHA256 creation ticket digest.
    ///
    /// PORTING: moved here from exp's `handler/certify.rs` (shared with
    /// `TPM2_CertifyCreation`).
    pub(crate) fn compute_creation_ticket(
        &self,
        hierarchy: u32,
        name: &OwnedName,
        creation_hash: &Tpm2bDigest<'_>,
    ) -> Result<[u8; 32], TpmRc> {
        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy);
        let proof = proof_bytes.get(..proof_len).ok_or(TpmRc::FAILURE)?;

        let tag_bytes = u16::from(TpmSt::CREATION).to_be_bytes();

        let mut hmac_ctx = HmacStream::new(self.crypto(), TpmiAlgHash::Sha256, proof)
            .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx.update(&tag_bytes).map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(name.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx
            .update(creation_hash.as_slice())
            .map_err(|_| TpmRc::FAILURE)?;

        let mut mac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mac = hmac_ctx
            .finalize(&mut mac_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        <[u8; 32]>::try_from(mac.digest()).map_err(|_| TpmRc::FAILURE)
    }
}
