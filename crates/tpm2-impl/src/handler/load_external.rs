use crate::handler::{CommandHandler, TransientObject};
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use hex_literal::hex;
use tpm2::Handle;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{LoadExternal, LoadExternalRespHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    PublicParmsAndId, Tpm2bSensitive, TpmaObject, TpmiAlgHash, TpmtKeyedHashScheme, TpmtPublic,
    TpmtSensitive, TpmuSensitiveComposite,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::LoadExternal] (`0x131`) command.
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

        let cmd = request.try_unmarshal::<LoadExternal>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // C `LoadExternal.c`: `FindEmptyObjectSlot` is the first check of the action code.
        let (index, handle) = self.global_state.find_empty_transient_slot(false)?;

        let in_private_present = cmd.in_private.is_some();
        let public_struct = cmd
            .in_public
            .to_struct_nullable()
            .map_err(|e| e.in_parameter(2).to_rc())?;

        // 1. Hierarchy and private key combination validation
        self.validate_load_external_hierarchy(cmd.hierarchy.0, in_private_present, &public_struct)?;

        if public_struct.auth_policy.get_size() != 0
            && let Some(name_alg) = public_struct.name_alg
        {
            let digest_size = name_alg.digest_size();
            if public_struct.auth_policy.get_size() as usize != digest_size {
                return Err(TpmRc::SIZE.with(Position::parameter(2)));
            }
        }

        if in_private_present && public_struct.name_alg.is_some() {
            // ObjectLoad: the seedValue may not be larger than the nameAlg digest.
            if let Some(ref in_private) = cmd.in_private {
                let sensitive_struct = in_private
                    .to_struct()
                    .map_err(|e| e.in_parameter(1).to_rc())?;
                let digest_size = public_struct.name_alg.map_or(0, |a| a.digest_size());
                if sensitive_struct.seed_value.get_size() as usize > digest_size {
                    return Err(TpmRc::KEY_SIZE.with(Position::parameter(1)));
                }
            }
            self.validate_object_attributes(
                &public_struct,
                0,
                0,
                None,
                false, // is_import
                false, // allow_null_name_alg
                Position::parameter(2),
                None,
            )?;
        } else {
            // ObjectLoad: public-only and NULL-nameAlg objects still get `SchemeChecks`.
            Self::scheme_checks(&public_struct, None)
                .map_err(|e| e.with_position(Position::parameter(2)))?;
        }
        self.validate_public_parameters(&public_struct, false)?;

        // 2. Public-Private Consistency and Cryptographic Validation
        let mut actual_private_key = [0u8; 1536];
        let actual_private_key_len = self.validate_load_external_public_private(
            &public_struct,
            &cmd.in_private,
            &mut actual_private_key,
        )?;

        // 3. Name validation & computation
        if let Some(alg) = public_struct.name_alg
            && !matches!(
                alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
            )
        {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }

        let mut pub_buf = [0u8; tpm2::TpmtPublic::MAX_SIZE];
        let pub_len = public_struct.marshal(&mut pub_buf);
        let name = self
            .compute_name(public_struct.name_alg, &pub_buf[..pub_len])
            .map_err(|_| TpmRc::HASH.with(Position::parameter(2)))?;

        // 4. Keep the sensitive seedValue (if any). The public Name is never used as a seed:
        // external objects can not be parents.
        let (auth_val, (seed, seed_len)) = if let Some(ref in_private) = cmd.in_private {
            let sensitive_struct = in_private
                .to_struct()
                .map_err(|e| e.in_parameter(1).to_rc())?;
            (
                crate::owned::OwnedAuth::from(sensitive_struct.auth_value),
                TransientObject::seed_from_bytes(sensitive_struct.seed_value.get_buffer()),
            )
        } else {
            (crate::owned::OwnedAuth::default(), ([0u8; 64], 0))
        };

        let resp_handles = LoadExternalRespHandles {
            object_handle: Handle(handle),
        };
        let rsp = responses::LoadExternal {
            name: name.as_tpm2b(),
        };

        // 5. Write the response
        let response = request.into_response();
        self.write_response_all(
            response,
            &resp_handles,
            &rsp,
            &session_responses[..num_sessions],
        )?;

        // 6. Apply object to transient objects storage

        let qualified_name = name;

        self.global_state.transient_parents[index] = Some(cmd.hierarchy.0);
        self.global_state.transient_objects[index] = Some(TransientObject {
            handle,
            seed,
            seed_len,
            external: true,
            public_only: !in_private_present,
            name,
            auth: auth_val,
            public: crate::owned::OwnedPublic::from(public_struct),
            private: actual_private_key,
            private_len: actual_private_key_len,
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
        if hierarchy == Handle::RH_OWNER.0 {
            if !self.global_state.sh_enable {
                return Err(param_err);
            }
        } else if hierarchy == Handle::RH_ENDORSEMENT.0 {
            if !self.global_state.eh_enable {
                return Err(param_err);
            }
        } else if hierarchy == Handle::RH_PLATFORM.0 {
            // Platform hierarchy is always enabled.
        } else if hierarchy == Handle::RH_NULL.0 {
            // Null hierarchy is always enabled.
        } else {
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
    /// components, imports private RSA/ECC keys into core provider structures,
    /// and returns the decoded private key length.
    fn validate_load_external_public_private(
        &self,
        public_struct: &TpmtPublic<'_>,
        in_private: &Option<Tpm2bSensitive<'_>>,
        actual_private_key: &mut [u8; 1536],
    ) -> Result<usize, TpmRc> {
        if let Some(in_private) = in_private {
            let sensitive_struct = in_private
                .to_struct()
                .map_err(|e| e.in_parameter(1).to_rc())?;
            self.validate_and_import_sensitive(
                public_struct,
                &sensitive_struct,
                actual_private_key,
                Position::parameter(1),
                Position::parameter(2),
                false,
            )
        } else {
            self.validate_public_only(public_struct)?;
            Ok(0)
        }
    }

    /// Imports a sensitive area without `CryptValidateKeys` (C `ObjectLoad` skips key
    /// validation when the parent is fixedTPM: such blobs were produced by this TPM).
    ///
    /// Only the conversions needed to use the key remain: an RSA private exponent is still
    /// computed from the prime (`CryptRsaLoadPrivateExponent`, bare `TPM_RC_BINDING` on
    /// failure), and an ECC scalar is left-padded to the curve size. A sensitive type that does
    /// not match the public type is still rejected (`TPM_RC_TYPE`).
    pub(crate) fn import_sensitive_unvalidated(
        &self,
        public_struct: &TpmtPublic,
        sensitive_struct: &TpmtSensitive,
        actual_private_key: &mut [u8; 1536],
        pos_sensitive: Position,
    ) -> Result<usize, TpmRc> {
        if public_struct.parms_and_id.algorithm() != sensitive_struct.sensitive_type() {
            return Err(TpmRc::TYPE.with(pos_sensitive));
        }
        let copy = |bytes: &[u8], out: &mut [u8; 1536]| {
            out[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        };
        match (&public_struct.parms_and_id, &sensitive_struct.sensitive) {
            (PublicParmsAndId::Rsa(rsa_parms, rsa_unique), TpmuSensitiveComposite::Rsa(p)) => self
                .crypto()
                .rsa_import_private_key(
                    rsa_unique.get_buffer(),
                    p.get_buffer(),
                    if rsa_parms.exponent == 0 {
                        65537
                    } else {
                        rsa_parms.exponent
                    },
                    actual_private_key,
                )
                .map_err(|_| TpmRc::BINDING.to_rc()),
            (PublicParmsAndId::Ecc(ecc_parms, _), TpmuSensitiveComposite::Ecc(d)) => {
                let param_size = match ecc_parms.curve_id {
                    tpm2::TpmEccCurve::NistP192 => 24,
                    tpm2::TpmEccCurve::NistP224 => 28,
                    tpm2::TpmEccCurve::NistP256 | tpm2::TpmEccCurve::BNP256 => 32,
                    tpm2::TpmEccCurve::NistP384 => 48,
                    tpm2::TpmEccCurve::NistP521 => 66,
                    _ => return Err(TpmRc::CURVE.to_rc()),
                };
                let d = d.get_buffer();
                if d.len() > param_size {
                    return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                }
                actual_private_key[..param_size].fill(0);
                actual_private_key[param_size - d.len()..param_size].copy_from_slice(d);
                Ok(param_size)
            }
            (_, TpmuSensitiveComposite::Sym(k)) => copy(k.get_buffer(), actual_private_key),
            (_, TpmuSensitiveComposite::KeyedHash(k)) => copy(k.get_buffer(), actual_private_key),
            (_, TpmuSensitiveComposite::Mldsa(k)) | (_, TpmuSensitiveComposite::HashMldsa(k)) => {
                copy(k.get_buffer(), actual_private_key)
            }
            (_, TpmuSensitiveComposite::Mlkem(k)) => copy(k.get_buffer(), actual_private_key),
            _ => Err(TpmRc::TYPE.with(pos_sensitive)),
        }
    }

    /// Helper function to validate and import the sensitive area of the external object.
    pub(crate) fn validate_and_import_sensitive(
        &self,
        public_struct: &TpmtPublic,
        sensitive_struct: &TpmtSensitive,
        actual_private_key: &mut [u8; 1536],
        pos_sensitive: Position,
        pos_public: Position,
        allow_empty_unique: bool,
    ) -> Result<usize, TpmRc> {
        // Check sensitiveType matches public type
        if public_struct.parms_and_id.algorithm() != sensitive_struct.sensitive_type() {
            return Err(TpmRc::TYPE.with(pos_sensitive));
        }

        // Check auth_value size
        let digest_size = public_struct
            .name_alg
            .map(|alg| alg.digest_size())
            .unwrap_or(0) as u16;
        if sensitive_struct.auth_value.get_size() > digest_size && digest_size > 0 {
            return Err(TpmRc::SIZE.with(pos_sensitive));
        }

        match &public_struct.parms_and_id {
            PublicParmsAndId::Rsa(rsa_parms, rsa_unique) => {
                let key_size_bytes = (rsa_parms.key_bits.0 / 8) as usize;
                // The modulus must have the key size and its most significant bit SET.
                if (!allow_empty_unique || rsa_unique.get_size() > 0)
                    && (rsa_unique.get_size() as usize != key_size_bytes
                        || rsa_unique.get_buffer()[0] < 0x80)
                {
                    return Err(TpmRc::KEY.with(pos_public));
                }
                if rsa_parms.exponent != 0 && rsa_parms.exponent < 7 {
                    return Err(TpmRc::VALUE.with(pos_public));
                }

                if let TpmuSensitiveComposite::Rsa(rsa_private) = &sensitive_struct.sensitive {
                    // The prime must be half the key size with its most significant bit SET.
                    if (rsa_private.get_size() as usize * 2) != key_size_bytes
                        || rsa_private.get_buffer()[0] < 0x80
                    {
                        return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                    }

                    if rsa_private.get_size() == 0
                        || rsa_private.get_buffer().iter().all(|&x| x == 0)
                    {
                        return Err(TpmRc::VALUE.with(pos_sensitive));
                    }

                    if allow_empty_unique && rsa_unique.get_size() == 0 {
                        let buf = rsa_private.get_buffer();
                        actual_private_key[..buf.len()].copy_from_slice(buf);
                        Ok(buf.len())
                    } else {
                        self.crypto()
                            .rsa_import_private_key(
                                rsa_unique.get_buffer(),
                                rsa_private.get_buffer(),
                                if rsa_parms.exponent == 0 {
                                    65537
                                } else {
                                    rsa_parms.exponent
                                },
                                actual_private_key,
                            )
                            .map_err(|_| TpmRc::BINDING.to_rc())
                    }
                } else {
                    Err(TpmRc::TYPE.with(pos_sensitive))
                }
            }
            PublicParmsAndId::Ecc(ecc_parms, point) => {
                let curve = ecc_parms.curve_id;
                let param_size = match curve {
                    tpm2::TpmEccCurve::NistP192 => 24,
                    tpm2::TpmEccCurve::NistP224 => 28,
                    tpm2::TpmEccCurve::NistP256 | tpm2::TpmEccCurve::BNP256 => 32,
                    tpm2::TpmEccCurve::NistP384 => 48,
                    tpm2::TpmEccCurve::NistP521 => 66,
                    _ => return Err(TpmRc::ECC_POINT.with(pos_public)),
                };
                let mut ecc_pub_key = [0u8; 256];
                if public_struct.name_alg.is_some() {
                    // With a sensitive area C only compares the (zero-adjusted) public point
                    // with [d]G, so stripped leading zero bytes are fine.
                    if (!allow_empty_unique || point.x.get_size() > 0)
                        && (point.x.get_size() as usize > param_size
                            || point.y.get_size() as usize > param_size)
                    {
                        return Err(TpmRc::KEY.with(pos_public));
                    }

                    let px = point.x.get_buffer();
                    let py = point.y.get_buffer();
                    ecc_pub_key[param_size - px.len()..param_size].copy_from_slice(px);
                    ecc_pub_key[param_size * 2 - py.len()..param_size * 2].copy_from_slice(py);

                    self.crypto()
                        .validate_point(curve, &ecc_pub_key[..param_size * 2])
                        .map_err(|_| TpmRc::ECC_POINT.with(pos_public))?;
                }

                if let TpmuSensitiveComposite::Ecc(sensitive_ecc) = &sensitive_struct.sensitive {
                    if sensitive_ecc.get_size() as usize > param_size {
                        return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                    }

                    let mut scalar = [0u8; 128];
                    let scalar_bytes = sensitive_ecc.get_buffer();
                    scalar[param_size - scalar_bytes.len()..param_size]
                        .copy_from_slice(scalar_bytes);

                    // CryptEccIsValidPrivateKey: 0 < d < n, checked regardless of nameAlg
                    // (`TPM_RC_KEY_SIZE` without a position).
                    if !ecc_private_key_in_range(curve, &scalar[..param_size]) {
                        return Err(TpmRc::KEY_SIZE.to_rc());
                    }

                    if public_struct.name_alg.is_some() {
                        let mut computed_pub_key = [0u8; 256];
                        self.crypto()
                            .point_multiply_generator(
                                curve,
                                &scalar[..param_size],
                                &mut computed_pub_key,
                            )
                            .map_err(|_| TpmRc::BINDING.to_rc())?;

                        if computed_pub_key[..param_size * 2] != ecc_pub_key[..param_size * 2] {
                            return Err(TpmRc::BINDING.to_rc());
                        }
                    }

                    actual_private_key[..param_size].copy_from_slice(&scalar[..param_size]);
                    Ok(param_size)
                } else {
                    Err(TpmRc::TYPE.with(pos_sensitive))
                }
            }
            PublicParmsAndId::Sym(sym_def, sym_unique) => {
                if let TpmuSensitiveComposite::Sym(sym_key) = &sensitive_struct.sensitive {
                    let expected_bits = sym_def.key_bits();
                    if sym_key.get_size() != (expected_bits / 8) {
                        return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                    }

                    if let Some(name_alg) = public_struct.name_alg {
                        if sensitive_struct.seed_value.get_size() as usize != name_alg.digest_size()
                        {
                            return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                        }
                        let (digest_bytes, digest_len) = self.compute_hash(
                            name_alg,
                            &[
                                sensitive_struct.seed_value.get_buffer(),
                                sym_key.get_buffer(),
                            ],
                        )?;
                        if sym_unique.get_buffer() != &digest_bytes[..digest_len] {
                            return Err(TpmRc::BINDING.to_rc());
                        }
                    }

                    let key_bytes = sym_key.get_buffer();
                    actual_private_key[..key_bytes.len()].copy_from_slice(key_bytes);
                    Ok(key_bytes.len())
                } else {
                    Err(TpmRc::TYPE.with(pos_sensitive))
                }
            }
            PublicParmsAndId::KeyedHash(scheme_opt, kh_unique) => {
                if let TpmuSensitiveComposite::KeyedHash(sensitive_data) =
                    &sensitive_struct.sensitive
                {
                    let max_size = match scheme_opt {
                        Some(TpmtKeyedHashScheme::ExclusiveOr(scheme)) => {
                            scheme.hash_alg.block_size()
                        }
                        Some(TpmtKeyedHashScheme::Hmac(hash_alg)) => hash_alg.block_size(),
                        None => tpm2::TPM2_MAX_SYM_DATA as u16,
                    };
                    if sensitive_data.get_size() > max_size {
                        return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                    }

                    if let Some(name_alg) = public_struct.name_alg {
                        if sensitive_struct.seed_value.get_size() as usize != name_alg.digest_size()
                        {
                            return Err(TpmRc::KEY_SIZE.with(pos_sensitive));
                        }
                        let (digest_bytes, digest_len) = self.compute_hash(
                            name_alg,
                            &[
                                sensitive_struct.seed_value.get_buffer(),
                                sensitive_data.get_buffer(),
                            ],
                        )?;
                        if kh_unique.get_buffer() != &digest_bytes[..digest_len] {
                            return Err(TpmRc::BINDING.to_rc());
                        }
                    }

                    let key_bytes = sensitive_data.get_buffer();
                    actual_private_key[..key_bytes.len()].copy_from_slice(key_bytes);
                    Ok(key_bytes.len())
                } else {
                    Err(TpmRc::TYPE.with(pos_sensitive))
                }
            }
            PublicParmsAndId::Mldsa(_, _) => {
                if let TpmuSensitiveComposite::Mldsa(priv_key) = &sensitive_struct.sensitive {
                    let key_bytes = priv_key.get_buffer();
                    actual_private_key[..key_bytes.len()].copy_from_slice(key_bytes);
                    Ok(key_bytes.len())
                } else {
                    Err(TpmRc::TYPE.with(pos_sensitive))
                }
            }
            PublicParmsAndId::HashMldsa(_, _) => {
                if let TpmuSensitiveComposite::HashMldsa(priv_key) = &sensitive_struct.sensitive {
                    let key_bytes = priv_key.get_buffer();
                    actual_private_key[..key_bytes.len()].copy_from_slice(key_bytes);
                    Ok(key_bytes.len())
                } else {
                    Err(TpmRc::TYPE.with(pos_sensitive))
                }
            }
            PublicParmsAndId::Mlkem(_, _) => {
                if let TpmuSensitiveComposite::Mlkem(priv_key) = &sensitive_struct.sensitive {
                    let key_bytes = priv_key.get_buffer();
                    actual_private_key[..key_bytes.len()].copy_from_slice(key_bytes);
                    Ok(key_bytes.len())
                } else {
                    Err(TpmRc::TYPE.with(pos_sensitive))
                }
            }
        }
    }

    /// Helper function to perform structural validation checks on public key parameters.
    pub(crate) fn validate_public_parameters(
        &self,
        public_struct: &TpmtPublic,
        allow_empty_unique: bool,
    ) -> Result<(), TpmRc> {
        match &public_struct.parms_and_id {
            PublicParmsAndId::Rsa(rsa_parms, rsa_unique) => {
                let kb = rsa_parms.key_bits.0;
                if !matches!(kb, 1024 | 2048 | 3072 | 4096) {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                let key_size_bytes = (kb / 8) as usize;
                if (!allow_empty_unique || rsa_unique.get_size() > 0)
                    && (rsa_unique.get_size() as usize != key_size_bytes
                        || rsa_unique.get_buffer()[0] < 0x80)
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
                if rsa_parms.exponent != 0 && rsa_parms.exponent < 7 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
            }
            PublicParmsAndId::Ecc(ecc_parms, point) => {
                let curve = ecc_parms.curve_id;
                let param_size = match curve {
                    tpm2::TpmEccCurve::NistP192 => 24,
                    tpm2::TpmEccCurve::NistP224 => 28,
                    tpm2::TpmEccCurve::NistP256 | tpm2::TpmEccCurve::BNP256 => 32,
                    tpm2::TpmEccCurve::NistP384 => 48,
                    tpm2::TpmEccCurve::NistP521 => 66,
                    _ => return Err(TpmRc::ECC_POINT.with(Position::parameter(2))),
                };
                // Coordinates may have leading zero bytes stripped when a sensitive area is
                // present (C adjusts them before the binding check); only oversized
                // coordinates are invalid here. Public-only keys need exact sizes, which
                // `validate_public_only` checks.
                if point.x.get_size() as usize > param_size
                    || point.y.get_size() as usize > param_size
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
            }
            PublicParmsAndId::Sym(sym_def, sym_unique) => {
                let kb = sym_def.key_bits();
                if kb != 128 && kb != 256 && kb != 192 {
                    return Err(TpmRc::SYMMETRIC.with(Position::parameter(2)));
                }
                let digest_size = public_struct
                    .name_alg
                    .map(|alg| alg.digest_size())
                    .unwrap_or(0) as u16;
                if sym_unique.get_size() != 0 && sym_unique.get_size() != digest_size {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
            }
            PublicParmsAndId::KeyedHash(_, kh_unique) => {
                let digest_size = public_struct
                    .name_alg
                    .map(|alg| alg.digest_size())
                    .unwrap_or(0) as u16;
                if kh_unique.get_size() != 0 && kh_unique.get_size() != digest_size {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
            }
            PublicParmsAndId::Mldsa(parms, unique) => {
                let expected_size = parms.parameter_set.public_key_bytes();
                if (!allow_empty_unique || unique.get_size() > 0)
                    && unique.get_size() as usize != expected_size
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
            }
            PublicParmsAndId::HashMldsa(parms, unique) => {
                let expected_size = parms.parameter_set.public_key_bytes();
                if (!allow_empty_unique || unique.get_size() > 0)
                    && unique.get_size() as usize != expected_size
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
            }
            PublicParmsAndId::Mlkem(parms, unique) => {
                let expected_size = parms.parameter_set.public_key_bytes();
                if (!allow_empty_unique || unique.get_size() > 0)
                    && unique.get_size() as usize != expected_size
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
            }
        }
        Ok(())
    }

    /// Helper function to perform validation checks on public-only key parameters.
    pub(crate) fn validate_public_only(&self, public_struct: &TpmtPublic) -> Result<(), TpmRc> {
        self.validate_public_parameters(public_struct, false)?;

        // CryptValidateKeys without a sensitive area: a SYMCIPHER/KEYEDHASH `unique` must be
        // exactly the nameAlg digest size (empty for a NULL nameAlg), and ECC coordinates must
        // have exactly the key size.
        let digest_size = public_struct.name_alg.map_or(0, |a| a.digest_size());
        match &public_struct.parms_and_id {
            PublicParmsAndId::Ecc(ecc_parms, point) => {
                let key_size = match ecc_parms.curve_id {
                    tpm2::TpmEccCurve::NistP192 => 24,
                    tpm2::TpmEccCurve::NistP224 => 28,
                    tpm2::TpmEccCurve::NistP256 | tpm2::TpmEccCurve::BNP256 => 32,
                    tpm2::TpmEccCurve::NistP384 => 48,
                    tpm2::TpmEccCurve::NistP521 => 66,
                    _ => 0,
                };
                if point.x.get_size() as usize != key_size
                    || point.y.get_size() as usize != key_size
                {
                    return Err(TpmRc::KEY.with(Position::parameter(2)));
                }
            }
            PublicParmsAndId::Sym(_, unique) | PublicParmsAndId::KeyedHash(_, unique)
                if unique.get_size() as usize != digest_size =>
            {
                return Err(TpmRc::KEY.with(Position::parameter(2)));
            }
            _ => {}
        }

        if let PublicParmsAndId::Ecc(ecc_parms, point) = &public_struct.parms_and_id
            && public_struct.name_alg.is_some()
        {
            let curve = ecc_parms.curve_id;
            let param_size = match curve {
                tpm2::TpmEccCurve::NistP192 => 24,
                tpm2::TpmEccCurve::NistP224 => 28,
                tpm2::TpmEccCurve::NistP256 | tpm2::TpmEccCurve::BNP256 => 32,
                tpm2::TpmEccCurve::NistP384 => 48,
                tpm2::TpmEccCurve::NistP521 => 66,
                _ => return Err(TpmRc::ECC_POINT.with(Position::parameter(2))),
            };
            let mut ecc_pub_key = [0u8; 256];
            let px = point.x.get_buffer();
            let py = point.y.get_buffer();
            ecc_pub_key[param_size - px.len()..param_size].copy_from_slice(px);
            ecc_pub_key[param_size * 2 - py.len()..param_size * 2].copy_from_slice(py);

            self.crypto()
                .validate_point(curve, &ecc_pub_key[..param_size * 2])
                .map_err(|_| TpmRc::ECC_POINT.with(Position::parameter(2)))?;
        }
        Ok(())
    }
}

/// Returns the order `n` (big-endian) of the supported ECC curves.
fn ecc_curve_order(curve: tpm2::TpmEccCurve) -> Option<&'static [u8]> {
    match curve {
        tpm2::TpmEccCurve::NistP192 => {
            Some(&hex!("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"))
        }
        tpm2::TpmEccCurve::NistP224 => Some(&hex!(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"
        )),
        tpm2::TpmEccCurve::NistP256 => Some(&hex!(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
        )),
        tpm2::TpmEccCurve::BNP256 => Some(&hex!(
            "FFFFFFFFFFFCF0CD46E5F25EEE71A49E0CDC65FB1299921AF62D536CD10B500D"
        )),
        tpm2::TpmEccCurve::NistP384 => Some(&hex!(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
            "581A0DB248B0A77AECEC196ACCC52973"
        )),
        tpm2::TpmEccCurve::NistP521 => Some(&hex!(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA"
            "51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
        )),
        _ => None,
    }
}

/// C `CryptEccIsValidPrivateKey`: returns `true` iff `0 < d < n` for the curve's order `n`.
/// `scalar` is the big-endian private key left-padded to the curve's coordinate size.
/// Curves without a known order are not range-checked.
fn ecc_private_key_in_range(curve: tpm2::TpmEccCurve, scalar: &[u8]) -> bool {
    if scalar.iter().all(|&b| b == 0) {
        return false;
    }
    match ecc_curve_order(curve) {
        // Both are big-endian with equal length, so lexicographic order is numeric order.
        Some(order) if order.len() == scalar.len() => scalar < order,
        _ => true,
    }
}
