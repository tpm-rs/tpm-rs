use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::object_helpers::check_pqc_key_parameters;
use crate::handler::{CommandHandler, TransientObject};
use crate::owned::{
    OwnedAuth, OwnedDigest, OwnedEccParameter, OwnedPrivateKeyRsa, OwnedPublic,
    OwnedSensitiveComposite, OwnedSensitiveData, OwnedSymKey,
};
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{LoadExternal, responses};
use tpm2::crypto::{Ecc, Mldsa, Mlkem, Rsa};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2b, Tpm2bEccParameter, Tpm2bSensitive,
    Tpm2bSensitiveData, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsEccPoint, TpmtKeyedHashScheme,
    TpmtPublic, TpmtSensitive, TpmuSensitiveComposite,
};

/// Returns the size in bytes of a coordinate (and of the private scalar) of `curve`, for the
/// curves exp supported for loaded keys (`None`: `TPM_RC_ECC_POINT`).
fn ecc_param_size(curve: TpmEccCurve) -> Option<usize> {
    match curve {
        TpmEccCurve::NistP192
        | TpmEccCurve::NistP224
        | TpmEccCurve::NistP256
        | TpmEccCurve::BNP256
        | TpmEccCurve::NistP384
        | TpmEccCurve::NistP521 => Some(curve.key_bytes()),
        _ => None,
    }
}

/// Copies `src` right-aligned into `dst[..len]` (big-endian zero padding) and returns
/// `dst[..len]`, or `None` if `src` is longer than `len`.
fn left_pad<'d>(
    dst: &'d mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    src: &[u8],
    len: usize,
) -> Option<&'d [u8]> {
    let out = dst.get_mut(..len)?;
    let start = len.checked_sub(src.len())?;
    out.get_mut(start..)?.copy_from_slice(src);
    Some(out)
}

/// Returns the sensitive area stored for a public-only object (`TPM2_LoadExternal` without
/// `inPrivate`): the empty member of the object's type, or the (empty)
/// [`OwnedSensitiveComposite::default`] for ML-DSA / ML-KEM objects, whose fixed-size seed
/// members cannot be empty.
///
/// PORTING: exp stored `private_len == 0`; an object without a sensitive area now has
/// `sensitive.as_bytes().is_empty()`.
fn public_only_sensitive(public_struct: &TpmtPublic<'_>) -> OwnedSensitiveComposite {
    match public_struct.parms_and_id {
        PublicParmsAndId::KeyedHash(_, _) => {
            OwnedSensitiveComposite::KeyedHash(OwnedSensitiveData::empty())
        }
        PublicParmsAndId::Sym(_, _) => OwnedSensitiveComposite::Sym(OwnedSymKey::empty()),
        PublicParmsAndId::Rsa(_, _) => OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::empty()),
        PublicParmsAndId::Ecc(_, _) => OwnedSensitiveComposite::Ecc(OwnedEccParameter::empty()),
        PublicParmsAndId::Mldsa(_, _)
        | PublicParmsAndId::HashMldsa(_, _)
        | PublicParmsAndId::Mlkem(_, _) => OwnedSensitiveComposite::default(),
    }
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::LoadExternal] (`0x167`) command.
    ///
    /// # Description
    /// This command is used to load an object (either public-only or both public and private)
    /// that was created outside of the TPM into the TPM's volatile memory.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.3 (TPM2_LoadExternal).
    ///
    /// # Relationships
    /// - Bypasses parent-key decryption since it loads external key material directly.
    /// - If only the public portion is loaded, the resulting transient object can be used for signature verification (via [TpmCc::VerifySignature](crypt_ops.rs)).
    /// - If both public and private portions are loaded, it must be associated with the Null hierarchy (`TPM_RH_NULL`).
    pub fn load_external(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<LoadExternal>([])?;
        check(cmd.hierarchy, Tpmi::RhHierarchy, Position::parameter(3))?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // `inPublic` is a `TPM2B_PUBLIC+`: its nameAlg may be `TPM_ALG_NULL`.
        let in_private_present = cmd.in_private.is_some();
        let public_struct = cmd.in_public.0;

        // 1. Hierarchy and private key combination validation
        self.validate_load_external_hierarchy(cmd.hierarchy.0, in_private_present, &public_struct)?;

        let auth_policy_len = public_struct.auth_policy.as_slice().len();
        if auth_policy_len != 0
            && let Some(name_alg) = public_struct.name_alg
            && auth_policy_len != name_alg.digest_size()
        {
            return Err(TpmRc::SIZE.with(Position::parameter(2)));
        }

        if in_private_present && public_struct.name_alg.is_some() {
            self.validate_object_attributes(
                &public_struct,
                0,
                0,
                None,
                false, // is_import
                false, // allow_null_name_alg
                Position::parameter(2),
            )?;
        } else {
            let attr = public_struct.object_attributes;
            if (attr.0 & 0xfff0_f009) != 0 {
                return Err(TpmRc::RESERVED_BITS.with(Position::parameter(2)));
            }
            check_pqc_key_parameters(&public_struct, Position::parameter(2))?;
        }
        self.validate_public_parameters(&public_struct, false)?;

        // 2. Public-Private Consistency and Cryptographic Validation
        let sensitive =
            self.validate_load_external_public_private(&public_struct, cmd.in_private.as_ref())?;

        // 3. Name validation & computation
        if let Some(alg) = public_struct.name_alg
            && !matches!(
                alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
            )
        {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }

        let mut pub_buf = [0u8; TpmtPublic::MAX_SIZE];
        let pub_len = public_struct.marshal(&mut pub_buf);
        let name = self
            .compute_name(public_struct.name_alg, &pub_buf[..pub_len])
            .map_err(|_| TpmRc::HASH.with(Position::parameter(2)))?;

        // 4. Volatile storage allocation
        let (index, handle) = self.global_state.find_empty_transient_slot(false)?;

        // PORTING: exp used the first 32 bytes of the Name as the seed; the object now keeps
        // the `seedValue` of `inPrivate` (empty for a public-only load).
        let seed = match &cmd.in_private {
            Some(in_private) => OwnedDigest::from(in_private.0.seed_value),
            None => OwnedDigest::default(),
        };

        let auth_val = match &cmd.in_private {
            Some(in_private) => OwnedAuth::from(in_private.0.auth_value),
            None => OwnedAuth::default(),
        };

        let rsp = responses::LoadExternal {
            object_handle: Handle(handle),
            name: name.as_tpm2b(),
        };

        // 5. Write the response
        let response = request.into_response();
        self.write_response_all(
            response,
            &rsp.object_handle,
            &rsp,
            &session_responses[..num_sessions],
        )?;

        // 6. Apply object to transient objects storage

        let qualified_name = name;

        self.global_state.transient_parents[index] = Some(cmd.hierarchy.0);
        self.global_state.transient_objects[index] = Some(TransientObject {
            handle,
            seed,
            name,
            auth: auth_val,
            public: OwnedPublic::from(public_struct),
            sensitive,
            qualified_name,
            hierarchy: cmd.hierarchy.0,
            st_clear: false,
        });

        Ok(())
    }

    /// Validates the request hierarchy rules (Owner, Endorsement, Platform, or Null)
    /// and checks attribute constraints on loaded private parts.
    fn validate_load_external_hierarchy(
        &self,
        hierarchy: u32,
        in_private_present: bool,
        public_struct: &TpmtPublic<'_>,
    ) -> Result<(), TpmRc> {
        let param_err = TpmRc::HIERARCHY.with(Position::parameter(3));
        let enabled = match Handle(hierarchy) {
            Handle::RH_OWNER => self.global_state.sh_enable,
            Handle::RH_ENDORSEMENT => self.global_state.eh_enable,
            // Platform and Null hierarchies are always enabled.
            Handle::RH_PLATFORM | Handle::RH_NULL => true,
            _ => false,
        };
        if !enabled {
            return Err(param_err);
        }

        if in_private_present {
            if hierarchy != Handle::RH_NULL.0 {
                return Err(param_err);
            }
            let attrs = public_struct.object_attributes;
            if attrs.intersects(
                TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT | TpmaObject::RESTRICTED,
            ) {
                return Err(TpmRc::ATTRIBUTES.with(Position::parameter(2)));
            }
        }
        Ok(())
    }

    /// Performs consistency and structural validation checks on public/private
    /// components and returns the sensitive area to store for the loaded object.
    ///
    /// PORTING: exp imported RSA/ECC private keys into crypto provider blobs and returned
    /// their length.
    fn validate_load_external_public_private(
        &self,
        public_struct: &TpmtPublic<'_>,
        in_private: Option<&Tpm2bSensitive<'_>>,
    ) -> Result<OwnedSensitiveComposite, TpmRc> {
        if let Some(in_private) = in_private {
            self.validate_and_import_sensitive(
                public_struct,
                &in_private.0,
                Position::parameter(1),
                Position::parameter(2),
                false,
            )
        } else {
            self.validate_public_only(public_struct)?;
            Ok(public_only_sensitive(public_struct))
        }
    }

    /// Helper function to validate and import the sensitive area of the external object.
    ///
    /// Checks that `sensitive_struct` matches the type of `public_struct` and (for RSA / ECC
    /// keys with a non-null nameAlg, and symmetric / keyed-hash objects with a non-null
    /// nameAlg) that it is bound to the public area. Returns the sensitive area to store in
    /// [`TransientObject::sensitive`]: the first RSA prime, the ECC scalar (left-padded to the
    /// curve size), the symmetric key / keyed-hash data, or the ML-DSA / ML-KEM seed.
    ///
    /// PORTING: exp wrote the crypto provider's private key blob into an
    /// `actual_private_key` out-buffer and returned its length. The RSA / ECC binding checks
    /// now use [`Rsa::load_private`] / [`Ecc::load_private`] (exp:
    /// `rsa_import_private_key` / `point_multiply_generator`); any failure is still
    /// `TPM_RC_BINDING`.
    pub(crate) fn validate_and_import_sensitive(
        &self,
        public_struct: &TpmtPublic<'_>,
        sensitive_struct: &TpmtSensitive<'_>,
        pos_sensitive: Position,
        pos_public: Position,
        allow_empty_unique: bool,
    ) -> Result<OwnedSensitiveComposite, TpmRc> {
        let type_err = TpmRc::TYPE.with(pos_sensitive);
        let binding_err = TpmRc::BINDING.with(pos_sensitive);

        // Check sensitiveType matches public type
        if public_struct.parms_and_id.algorithm() != sensitive_struct.sensitive_type() {
            return Err(type_err);
        }

        // Check auth_value size
        let digest_size = public_struct.name_alg.map_or(0, |alg| alg.digest_size());
        if sensitive_struct.auth_value.as_slice().len() > digest_size && digest_size > 0 {
            return Err(TpmRc::SIZE.with(pos_sensitive));
        }

        let crypto = self.crypto();
        match &public_struct.parms_and_id {
            PublicParmsAndId::Rsa(rsa_parms, rsa_unique) => {
                let key_size_bytes = usize::from(u16::from(rsa_parms.key_bits)) / 8;
                let unique_len = rsa_unique.as_slice().len();
                if (!allow_empty_unique || unique_len > 0) && unique_len != key_size_bytes {
                    return Err(TpmRc::KEY.with(pos_public));
                }
                if rsa_parms.exponent != 0 && rsa_parms.exponent < 7 {
                    return Err(TpmRc::VALUE.with(pos_public));
                }

                let TpmuSensitiveComposite::Rsa(rsa_private) = sensitive_struct.sensitive else {
                    return Err(type_err);
                };
                let prime = rsa_private.as_slice();
                if prime.len() * 2 != key_size_bytes {
                    return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                }

                if prime.is_empty() || prime.iter().all(|&x| x == 0) {
                    return Err(TpmRc::VALUE.with(pos_sensitive));
                }

                if !allow_empty_unique || unique_len > 0 {
                    // `exponent == 0` selects the default exponent (65537).
                    let public = Rsa::load_public(
                        crypto,
                        rsa_parms.key_bits,
                        rsa_parms.exponent,
                        *rsa_unique,
                    )
                    .ok()
                    .flatten()
                    .ok_or(binding_err)?;
                    Rsa::load_private(crypto, public, rsa_private)
                        .ok()
                        .flatten()
                        .ok_or(binding_err)?;
                }
                OwnedPrivateKeyRsa::new(prime)
                    .map(OwnedSensitiveComposite::Rsa)
                    .ok_or(TpmRc::FAILURE)
            }
            PublicParmsAndId::Ecc(ecc_parms, point) => {
                let curve = ecc_parms.curve_id;
                let param_size = ecc_param_size(curve).ok_or(TpmRc::ECC_POINT.with(pos_public))?;
                let ecc_public = if public_struct.name_alg.is_some() {
                    let key_err = TpmRc::KEY.with(pos_public);
                    let (x, y) = (point.x.as_slice(), point.y.as_slice());
                    if (!allow_empty_unique || !x.is_empty())
                        && (x.len() != param_size || y.len() != param_size)
                    {
                        return Err(key_err);
                    }

                    // exp left-padded the coordinates to the curve size (only needed for an
                    // empty `x` with `allow_empty_unique`; exp panicked if `y` was then longer
                    // than the curve size).
                    let mut x_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
                    let mut y_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
                    let x = left_pad(&mut x_buf, x, param_size).ok_or(key_err)?;
                    let y = left_pad(&mut y_buf, y, param_size).ok_or(key_err)?;
                    let point = TpmsEccPoint {
                        x: Tpm2bEccParameter::new(x).ok_or(TpmRc::FAILURE)?,
                        y: Tpm2bEccParameter::new(y).ok_or(TpmRc::FAILURE)?,
                    };

                    let public = Ecc::load_public(crypto, curve, point)
                        .ok()
                        .flatten()
                        .ok_or(TpmRc::ECC_POINT.with(pos_public))?;
                    Some(public)
                } else {
                    None
                };

                let TpmuSensitiveComposite::Ecc(sensitive_ecc) = sensitive_struct.sensitive else {
                    return Err(type_err);
                };
                let mut scalar_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
                let scalar = left_pad(&mut scalar_buf, sensitive_ecc.as_slice(), param_size)
                    .ok_or(TpmRc::KEY_SIZE.with(pos_sensitive))?;

                if let Some(public) = ecc_public {
                    let scalar = Tpm2bEccParameter::new(scalar).ok_or(TpmRc::FAILURE)?;
                    Ecc::load_private(crypto, public, scalar)
                        .ok()
                        .flatten()
                        .ok_or(binding_err)?;
                }

                OwnedEccParameter::new(scalar)
                    .map(OwnedSensitiveComposite::Ecc)
                    .ok_or(TpmRc::FAILURE)
            }
            PublicParmsAndId::Sym(sym_def, sym_unique) => {
                let TpmuSensitiveComposite::Sym(sym_key) = sensitive_struct.sensitive else {
                    return Err(type_err);
                };
                let expected_bytes = usize::from(sym_def.alg.key_bits()) / 8;
                if sym_key.as_slice().len() != expected_bytes {
                    return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                }

                if let Some(name_alg) = public_struct.name_alg {
                    self.check_unique_binding(
                        name_alg,
                        sensitive_struct,
                        sym_key.as_slice(),
                        sym_unique.as_slice(),
                        binding_err,
                    )?;
                }

                OwnedSymKey::new(sym_key.as_slice())
                    .map(OwnedSensitiveComposite::Sym)
                    .ok_or(TpmRc::FAILURE)
            }
            PublicParmsAndId::KeyedHash(scheme_opt, kh_unique) => {
                let TpmuSensitiveComposite::KeyedHash(sensitive_data) = sensitive_struct.sensitive
                else {
                    return Err(type_err);
                };
                let max_size = match scheme_opt {
                    Some(TpmtKeyedHashScheme::Xor(scheme)) => scheme.hash_alg.block_size(),
                    Some(TpmtKeyedHashScheme::Hmac(hash_alg)) => hash_alg.block_size(),
                    // `TPM2_MAX_SYM_DATA`
                    None => Tpm2bSensitiveData::CAP,
                };
                if sensitive_data.as_slice().len() > max_size {
                    return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                }

                if let Some(name_alg) = public_struct.name_alg {
                    self.check_unique_binding(
                        name_alg,
                        sensitive_struct,
                        sensitive_data.as_slice(),
                        kh_unique.as_slice(),
                        binding_err,
                    )?;
                }

                OwnedSensitiveData::new(sensitive_data.as_slice())
                    .map(OwnedSensitiveComposite::KeyedHash)
                    .ok_or(TpmRc::FAILURE)
            }
            // The ML-DSA / ML-KEM private keys are their seeds (Part 1): 32 bytes for ML-DSA,
            // 64 bytes (`d || z`) for ML-KEM. Their sizes are checked by the unmarshal.
            PublicParmsAndId::Mldsa(parms, unique) => {
                let unique_len = unique.as_slice().len();
                if (!allow_empty_unique || unique_len > 0)
                    && unique_len != parms.parameter_set.pub_key_bytes()
                {
                    return Err(TpmRc::KEY.with(pos_public));
                }
                let TpmuSensitiveComposite::Mldsa(Tpm2b(seed)) = sensitive_struct.sensitive else {
                    return Err(type_err);
                };
                if (!allow_empty_unique || unique_len > 0) && public_struct.name_alg.is_some() {
                    let public = Mldsa::load_public(crypto, parms.parameter_set, *unique)
                        .ok()
                        .flatten()
                        .ok_or(TpmRc::KEY.with(pos_public))?;
                    Mldsa::load_private(crypto, public, Tpm2b(seed))
                        .ok()
                        .flatten()
                        .ok_or(binding_err)?;
                }
                Ok(OwnedSensitiveComposite::Mldsa(*seed))
            }
            PublicParmsAndId::HashMldsa(parms, unique) => {
                let unique_len = unique.as_slice().len();
                if (!allow_empty_unique || unique_len > 0)
                    && unique_len != parms.parameter_set.pub_key_bytes()
                {
                    return Err(TpmRc::KEY.with(pos_public));
                }
                let TpmuSensitiveComposite::HashMldsa(Tpm2b(seed)) = sensitive_struct.sensitive
                else {
                    return Err(type_err);
                };
                if (!allow_empty_unique || unique_len > 0) && public_struct.name_alg.is_some() {
                    let public = Mldsa::load_public(crypto, parms.parameter_set, *unique)
                        .ok()
                        .flatten()
                        .ok_or(TpmRc::KEY.with(pos_public))?;
                    Mldsa::load_private(crypto, public, Tpm2b(seed))
                        .ok()
                        .flatten()
                        .ok_or(binding_err)?;
                }
                Ok(OwnedSensitiveComposite::HashMldsa(*seed))
            }
            PublicParmsAndId::Mlkem(parms, unique) => {
                let unique_len = unique.as_slice().len();
                if (!allow_empty_unique || unique_len > 0)
                    && unique_len != parms.parameter_set.pub_key_bytes()
                {
                    return Err(TpmRc::KEY.with(pos_public));
                }
                let TpmuSensitiveComposite::Mlkem(Tpm2b(seed)) = sensitive_struct.sensitive else {
                    return Err(type_err);
                };
                if (!allow_empty_unique || unique_len > 0) && public_struct.name_alg.is_some() {
                    let public = Mlkem::load_public(crypto, parms.parameter_set, *unique)
                        .ok()
                        .flatten()
                        .ok_or(TpmRc::KEY.with(pos_public))?;
                    Mlkem::load_private(crypto, public, Tpm2b(seed))
                        .ok()
                        .flatten()
                        .ok_or(binding_err)?;
                }
                Ok(OwnedSensitiveComposite::Mlkem(*seed))
            }
        }
    }

    /// Checks that the `unique` field of a symmetric / keyed-hash object is
    /// `H_nameAlg(seedValue || key)`, returning `binding_err` otherwise.
    fn check_unique_binding(
        &self,
        name_alg: TpmiAlgHash,
        sensitive_struct: &TpmtSensitive<'_>,
        key: &[u8],
        unique: &[u8],
        binding_err: TpmRc,
    ) -> Result<(), TpmRc> {
        let (digest_bytes, digest_len) =
            self.compute_hash(name_alg, &[sensitive_struct.seed_value.as_slice(), key])?;
        if unique != digest_bytes.get(..digest_len).ok_or(TpmRc::FAILURE)? {
            return Err(binding_err);
        }
        Ok(())
    }

    /// Helper function to perform structural validation checks on public key parameters.
    pub(crate) fn validate_public_parameters(
        &self,
        public_struct: &TpmtPublic<'_>,
        allow_empty_unique: bool,
    ) -> Result<(), TpmRc> {
        let key_err = TpmRc::KEY.with(Position::parameter(2));
        let check_unique_size = |unique_len: usize, expected_size: usize| {
            if (!allow_empty_unique || unique_len > 0) && unique_len != expected_size {
                Err(key_err)
            } else {
                Ok(())
            }
        };
        let digest_size = public_struct.name_alg.map_or(0, |alg| alg.digest_size());

        match &public_struct.parms_and_id {
            PublicParmsAndId::Rsa(rsa_parms, rsa_unique) => {
                let kb = u16::from(rsa_parms.key_bits);
                if kb != 1024 && kb != 2048 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                check_unique_size(rsa_unique.as_slice().len(), usize::from(kb) / 8)?;
                if rsa_parms.exponent != 0 && rsa_parms.exponent < 7 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
            }
            PublicParmsAndId::Ecc(ecc_parms, point) => {
                let param_size = ecc_param_size(ecc_parms.curve_id)
                    .ok_or(TpmRc::ECC_POINT.with(Position::parameter(2)))?;
                let x_len = point.x.as_slice().len();
                if (!allow_empty_unique || x_len > 0)
                    && (x_len != param_size || point.y.as_slice().len() != param_size)
                {
                    return Err(key_err);
                }
            }
            PublicParmsAndId::Sym(sym_def, sym_unique) => {
                let kb = sym_def.alg.key_bits();
                if kb != 128 && kb != 256 && kb != 192 {
                    return Err(TpmRc::SYMMETRIC.with(Position::parameter(2)));
                }
                let unique_len = sym_unique.as_slice().len();
                if unique_len != 0 && unique_len != digest_size {
                    return Err(key_err);
                }
            }
            PublicParmsAndId::KeyedHash(_, kh_unique) => {
                let unique_len = kh_unique.as_slice().len();
                if unique_len != 0 && unique_len != digest_size {
                    return Err(key_err);
                }
            }
            PublicParmsAndId::Mldsa(parms, unique) => {
                check_unique_size(unique.as_slice().len(), parms.parameter_set.pub_key_bytes())?;
            }
            PublicParmsAndId::HashMldsa(parms, unique) => {
                check_unique_size(unique.as_slice().len(), parms.parameter_set.pub_key_bytes())?;
            }
            PublicParmsAndId::Mlkem(parms, unique) => {
                check_unique_size(unique.as_slice().len(), parms.parameter_set.pub_key_bytes())?;
            }
        }
        Ok(())
    }

    /// Helper function to perform validation checks on public-only key parameters.
    ///
    /// PORTING: the ECC point check now uses [`Ecc::load_public`] (exp: `validate_point`).
    pub(crate) fn validate_public_only(&self, public_struct: &TpmtPublic<'_>) -> Result<(), TpmRc> {
        self.validate_public_parameters(public_struct, false)?;

        // `validate_public_parameters` checked that the curve is supported and that both
        // coordinates have the curve size (exp left-padded them to it).
        if public_struct.name_alg.is_some() {
            match &public_struct.parms_and_id {
                PublicParmsAndId::Ecc(ecc_parms, point)
                    if !matches!(
                        Ecc::load_public(self.crypto(), ecc_parms.curve_id, *point),
                        Ok(Some(_))
                    ) =>
                {
                    return Err(TpmRc::ECC_POINT.with(Position::parameter(2)));
                }
                PublicParmsAndId::Mldsa(parms, unique)
                    if !matches!(
                        Mldsa::load_public(self.crypto(), parms.parameter_set, *unique),
                        Ok(Some(_))
                    ) =>
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
                PublicParmsAndId::HashMldsa(parms, unique)
                    if !matches!(
                        Mldsa::load_public(self.crypto(), parms.parameter_set, *unique),
                        Ok(Some(_))
                    ) =>
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
                PublicParmsAndId::Mlkem(parms, unique)
                    if !matches!(
                        Mlkem::load_public(self.crypto(), parms.parameter_set, *unique),
                        Ok(Some(_))
                    ) =>
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
