use crate::handler::CommandHandler;
use crate::owned::OwnedPublicParmsAndId;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Alg;
use tpm2::Handle;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmEccCurve;
use tpm2::commands::responses;
use tpm2::commands::{Duplicate, DuplicateHandles};
use tpm2::crypto::asymmetric::KeyParams;
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bPrivate,
    Tpm2bPrivateKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey, TpmaObject, TpmiAlgHash, TpmtSensitive,
    TpmuSensitiveComposite,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::Duplicate] (`0x14B`) command.
    ///
    /// # Description
    /// This command is used to copy a transient key from the current TPM to a new parent key
    /// (which may reside on another TPM), encrypting the key's sensitive area so that it can only
    /// be loaded under the new parent key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 13.1 (TPM2_Duplicate).
    ///
    /// # Relationships
    /// - The target object (`object_handle`) to duplicate must be transient and must NOT have the `fixedParent` or `fixedTPM` attributes set.
    /// - The output `duplicate` private blob and `out_sym_seed` are designed to be imported into the new parent key's TPM using [TpmCc::Import](import.rs).
    pub fn duplicate(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<DuplicateHandles>()?;
        let object_handle = handles.object_handle.0;
        let new_parent_handle = handles.new_parent_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<Duplicate>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Retrieve the target object to duplicate
        let target_obj = self
            .global_state
            .find_transient_object(object_handle)
            .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;

        // 2. Check fixedParent and fixedTPM attributes
        if target_obj
            .public
            .object_attributes
            .contains(TpmaObject::FIXED_PARENT)
            || target_obj
                .public
                .object_attributes
                .contains(TpmaObject::FIXED_TPM)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        if target_obj
            .public
            .object_attributes
            .contains(TpmaObject::ENCRYPTED_DUPLICATION)
        {
            if cmd.symmetric_alg.is_none() {
                return Err(TpmRc::SYMMETRIC.with(Position::parameter(2)));
            }
            if new_parent_handle == Handle::RH_NULL.0 {
                return Err(TpmRc::HIERARCHY.with(Position::handle(2)));
            }
        }

        // 3. Resolve the new parent key public key modulus/parameters
        let mut parent_pub_modulus = [0u8; 512];
        let mut parent_pub_modulus_len = 0;
        let mut parent_ecc_curve = None;
        let mut parent_ecc_pub_point = [0u8; 256];
        let mut parent_name_alg = TpmiAlgHash::Sha256;

        let mut parent_obj = None;

        if new_parent_handle != Handle::RH_NULL.0 {
            let obj = self
                .global_state
                .find_transient_object(new_parent_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(2)))?;
            if !obj
                .public
                .object_attributes
                .contains(tpm2::TpmaObject::DECRYPT)
                || !obj
                    .public
                    .object_attributes
                    .contains(tpm2::TpmaObject::RESTRICTED)
            {
                return Err(TpmRc::TYPE.with(Position::handle(2)));
            }

            // Parent must be an asymmetric key
            match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(_, unique) => {
                    parent_pub_modulus_len = unique.get_size() as usize;
                    parent_pub_modulus[..parent_pub_modulus_len]
                        .copy_from_slice(unique.get_buffer());
                    parent_name_alg = obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                }
                OwnedPublicParmsAndId::Ecc(parms, unique) => {
                    parent_name_alg = obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                    let curve = parms.curve_id;
                    parent_ecc_curve = Some(curve);
                    let param_size = match curve {
                        TpmEccCurve::NistP224 => 28,
                        TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
                        TpmEccCurve::NistP384 => 48,
                        TpmEccCurve::NistP521 => 66,
                        _ => return Err(TpmRc::VALUE.to_rc()),
                    };

                    let px_buf = unique.x.get_buffer();
                    let py_buf = unique.y.get_buffer();
                    if px_buf.len() > param_size || py_buf.len() > param_size {
                        return Err(TpmRc::VALUE.to_rc());
                    }
                    parent_ecc_pub_point[param_size - px_buf.len()..param_size]
                        .copy_from_slice(px_buf);
                    parent_ecc_pub_point[param_size * 2 - py_buf.len()..param_size * 2]
                        .copy_from_slice(py_buf);
                }
                _ => {
                    return Err(TpmRc::TYPE.with(Position::handle(2)));
                }
            }
            parent_obj = Some(obj);
        }

        let parent_symmetric_is_null = if new_parent_handle != Handle::RH_NULL.0 {
            match &parent_obj.as_ref().unwrap().public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, _) => parms.symmetric.is_none(),
                OwnedPublicParmsAndId::Ecc(parms, _) => parms.symmetric.is_none(),
                _ => true,
            }
        } else {
            true
        };

        // Reconstruct TpmtSensitive for target object
        let mut prime_p = [0u8; 256];
        let sensitive_comp = match target_obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(_, _) => TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::from_bytes(&target_obj.private[..target_obj.private_len])
                    .unwrap(),
            ),
            OwnedPublicParmsAndId::Rsa(_, _) => {
                let prime_p_len = self
                    .crypto()
                    .rsa_private_key_to_prime_p(
                        &target_obj.private[..target_obj.private_len],
                        &mut prime_p,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                TpmuSensitiveComposite::Rsa(
                    Tpm2bPrivateKeyRsa::from_bytes(&prime_p[..prime_p_len]).unwrap(),
                )
            }
            OwnedPublicParmsAndId::KeyedHash(_, _) => TpmuSensitiveComposite::KeyedHash(
                Tpm2bSensitiveData::from_bytes(&target_obj.private[..target_obj.private_len])
                    .unwrap(),
            ),
            OwnedPublicParmsAndId::Sym(_, _) => TpmuSensitiveComposite::Sym(
                Tpm2bSymKey::from_bytes(&target_obj.private[..target_obj.private_len]).unwrap(),
            ),
            OwnedPublicParmsAndId::Mldsa(_, _) => TpmuSensitiveComposite::Mldsa(
                tpm2::Tpm2bPrivateKeyMldsa::from_bytes(
                    &target_obj.private[..target_obj.private_len],
                )
                .unwrap(),
            ),
            OwnedPublicParmsAndId::HashMldsa(_, _) => TpmuSensitiveComposite::HashMldsa(
                tpm2::Tpm2bPrivateKeyMldsa::from_bytes(
                    &target_obj.private[..target_obj.private_len],
                )
                .unwrap(),
            ),
            OwnedPublicParmsAndId::Mlkem(_, _) => TpmuSensitiveComposite::Mlkem(
                tpm2::Tpm2bPrivateKeyMlkem::from_bytes(
                    &target_obj.private[..target_obj.private_len],
                )
                .unwrap(),
            ),
        };
        let tpmt_sensitive = TpmtSensitive {
            auth_value: target_obj.auth.as_tpm2b(),
            seed_value: Tpm2bDigest::from_bytes(&target_obj.seed).unwrap(),
            sensitive: sensitive_comp,
        };

        if let Some(sym_def) = cmd.symmetric_alg {
            let sym_key_len = sym_def.key_bits() as usize / 8;
            if cmd.encryption_key_in.get_size() != 0
                && cmd.encryption_key_in.get_size() as usize != sym_key_len
            {
                return Err(TpmRc::SIZE.with(Position::parameter(1)));
            }
        } else if cmd.encryption_key_in.get_size() != 0 {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // 4. Inner wrapper encryption
        let mut inner_blob = [0u8; 2048];
        let mut sym_key = [0u8; 32];
        let mut encryption_key_out = Tpm2bData::default();

        let inner_blob_len = if let Some(sym_def) = cmd.symmetric_alg {
            // Determine symmetric key
            let sym_key_len = sym_def.key_bits() as usize / 8;
            if cmd.encryption_key_in.get_size() > 0 {
                sym_key[..sym_key_len].copy_from_slice(cmd.encryption_key_in.get_buffer());
            } else {
                // Generate a random key
                self.crypto()
                    .get_random(&mut sym_key[..sym_key_len])
                    .map_err(|_| TpmRc::FAILURE)?;
                encryption_key_out = Tpm2bData::from_bytes(&sym_key[..sym_key_len]).unwrap();
            }

            // Marshal sensitive area
            let mut sens_buf = [0u8; 2048];
            let sens_len = tpmt_sensitive.marshal(
                (&mut sens_buf[2..2 + tpm2::TpmtSensitive::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            sens_buf[0..2].copy_from_slice(&(sens_len as u16).to_be_bytes());
            let total_sens_len = 2 + sens_len;

            // Inner integrity digest
            let name_alg = target_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
            let (hash_bytes, hash_len) = self.compute_hash(
                name_alg,
                &[&sens_buf[..total_sens_len], target_obj.name.get_buffer()],
            )?;
            let mut unencrypted_inner = [0u8; 2048];
            unencrypted_inner[0..2].copy_from_slice(&(hash_len as u16).to_be_bytes());
            unencrypted_inner[2..2 + hash_len].copy_from_slice(&hash_bytes[..hash_len]);
            unencrypted_inner[2 + hash_len..2 + hash_len + total_sens_len]
                .copy_from_slice(&sens_buf[..total_sens_len]);
            let unencrypted_inner_len = 2 + hash_len + total_sens_len;

            // Encrypt using CFB mode
            let mut iv = [0u8; 16];
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((sym_key_len * 8) as u16)
                .map_err(|_| TpmRc::FAILURE)?;
            tpm2::crypto::encrypt(
                self.crypto(),
                sym_alg,
                &sym_key[..sym_key_len],
                &mut iv,
                &mut unencrypted_inner[..unencrypted_inner_len],
            )
            .map_err(|_| TpmRc::FAILURE)?;

            inner_blob[..unencrypted_inner_len]
                .copy_from_slice(&unencrypted_inner[..unencrypted_inner_len]);
            unencrypted_inner_len
        } else {
            // No inner wrapper
            let sens_len = tpmt_sensitive.marshal(
                (&mut inner_blob[2..2 + tpm2::TpmtSensitive::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            inner_blob[0..2].copy_from_slice(&(sens_len as u16).to_be_bytes());
            2 + sens_len
        };

        // 5. Outer wrapper encryption
        let mut duplicate_buf = [0u8; 2048];
        let mut out_sym_seed_buf = [0u8; tpm2::TpmsEccPoint::MAX_SIZE];
        let mut encrypted_seed = [0u8; 512];
        let mut out_sym_seed = Tpm2bEncryptedSecret::default();

        let duplicate_len = if new_parent_handle != Handle::RH_NULL.0 && !parent_symmetric_is_null {
            // Generate seed
            let mut seed = [0u8; 64];
            let seed_len;

            if let Some(curve) = parent_ecc_curve {
                let param_size = match curve {
                    TpmEccCurve::NistP224 => 28,
                    TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
                    TpmEccCurve::NistP384 => 48,
                    TpmEccCurve::NistP521 => 66,
                    _ => return Err(TpmRc::VALUE.to_rc()),
                };
                // ECC seed encryption (ECDH point multiply and KDFe)
                // 1. Generate ephemeral ECC key pair
                let mut eph_pub = [0u8; 256];
                let mut eph_priv = [0u8; 128];
                let (_pub_len, priv_len) = self
                    .crypto()
                    .generate_key(
                        Alg::ECDH,
                        Some(KeyParams::Ecc(curve)),
                        &mut eph_pub,
                        &mut eph_priv,
                        None,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;

                // 2. Perform ECDH point multiplication
                let mut ecdh_point = [0u8; 256];
                self.crypto()
                    .point_multiply(
                        curve,
                        &eph_priv[..priv_len],
                        &parent_ecc_pub_point[..param_size * 2],
                        &mut ecdh_point,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;

                // 3. Reconstruct ephemeral public point as TpmsEccPoint
                let mut ex = [0u8; 128];
                ex[..param_size].copy_from_slice(&eph_pub[0..param_size]);
                let mut ey = [0u8; 128];
                ey[..param_size].copy_from_slice(&eph_pub[param_size..param_size * 2]);

                let eph_point = tpm2::TpmsEccPoint {
                    x: Tpm2bEccParameter::from_bytes(&ex[..param_size]).unwrap(),
                    y: Tpm2bEccParameter::from_bytes(&ey[..param_size]).unwrap(),
                };

                // Marshal ephemeral point as out_sym_seed
                let out_sym_seed_len = eph_point.marshal(&mut out_sym_seed_buf);
                out_sym_seed =
                    Tpm2bEncryptedSecret::from_bytes(&out_sym_seed_buf[..out_sym_seed_len])
                        .unwrap();

                // 4. KDFe to recover seed
                let digest_size = parent_name_alg.digest_size();
                let total_bits = (digest_size * 8) as u32;

                tpm2::crypto::kdf::kdfe(
                    self.crypto(),
                    parent_name_alg,
                    &ecdh_point[..param_size],
                    b"DUPLICATE",
                    &eph_pub[..param_size],
                    &parent_ecc_pub_point[..param_size],
                    total_bits,
                    &mut seed,
                )
                .map_err(|_| TpmRc::FAILURE)?;
                seed_len = digest_size;
            } else {
                // Generate a random seed
                self.crypto()
                    .get_random(&mut seed[..32])
                    .map_err(|_| TpmRc::FAILURE)?;

                // RSA seed encryption
                let encrypted_seed_len = self
                    .crypto()
                    .encrypt(
                        Alg::OAEP,
                        Alg::from(parent_name_alg),
                        &parent_pub_modulus[..parent_pub_modulus_len],
                        &seed[..32],
                        &mut encrypted_seed,
                        b"DUPLICATE\0",
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                out_sym_seed =
                    Tpm2bEncryptedSecret::from_bytes(&encrypted_seed[..encrypted_seed_len])
                        .unwrap();
                seed_len = 32;
            }

            let mut sym_key_bits = match &parent_obj.as_ref().unwrap().public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, _) => {
                    parms.symmetric.map(|s| s.key_bits() as u32).unwrap_or(128)
                }
                OwnedPublicParmsAndId::Ecc(parms, _) => {
                    parms.symmetric.map(|s| s.key_bits() as u32).unwrap_or(128)
                }
                _ => 128,
            };
            if sym_key_bits == 0 {
                sym_key_bits = 128;
            }
            let outer_key_len = (sym_key_bits / 8) as usize;
            let total_sym_bits = sym_key_bits;

            let mut sym_key_iv = [0u8; 64];
            let mut integrity_key = [0u8; 64];
            let mut hmac_bytes = [0u8; 64];

            // 1. Compute KDFs
            let target_name_alg = target_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
            let target_digest_size = target_name_alg.digest_size();
            let target_bits = (target_digest_size * 8) as u32;
            kdfa(
                self.crypto(),
                target_name_alg,
                &seed[..seed_len],
                b"STORAGE",
                target_obj.name.get_buffer(),
                &[],
                total_sym_bits,
                &mut sym_key_iv,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            kdfa(
                self.crypto(),
                target_name_alg,
                &seed[..seed_len],
                b"INTEGRITY",
                &[],
                &[],
                target_bits,
                &mut integrity_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;

            // 2. Encrypt inner blob using outer symmetric key
            let mut outer_key = [0u8; 32];
            outer_key[..outer_key_len].copy_from_slice(&sym_key_iv[..outer_key_len]);
            let mut outer_iv = [0u8; 16]; // IV is all zeros for CFB mode duplication

            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((outer_key_len * 8) as u16)
                .map_err(|_| TpmRc::FAILURE)?;
            tpm2::crypto::encrypt(
                self.crypto(),
                sym_alg,
                &outer_key[..outer_key_len],
                &mut outer_iv,
                &mut inner_blob[..inner_blob_len],
            )
            .map_err(|_| TpmRc::FAILURE)?;

            // 3. Compute outer HMAC dynamically over the ENCRYPTED inner_blob ciphertext
            let mut hmac_ctx = tpm2::crypto::HmacCtx::new(
                self.crypto(),
                target_name_alg,
                &integrity_key[..target_digest_size],
            )
            .map_err(|_| TpmRc::FAILURE)?;
            hmac_ctx
                .update(&inner_blob[..inner_blob_len])
                .map_err(|_| TpmRc::FAILURE)?;
            hmac_ctx
                .update(target_obj.name.get_buffer())
                .map_err(|_| TpmRc::FAILURE)?;
            let hmac_res = hmac_ctx
                .finalize(&mut hmac_bytes)
                .map_err(|_| TpmRc::FAILURE)?;
            let hmac_len = hmac_res.digest().len();

            // Format duplicate blob
            duplicate_buf[0..2].copy_from_slice(&(hmac_len as u16).to_be_bytes());
            duplicate_buf[2..2 + hmac_len].copy_from_slice(&hmac_bytes[..hmac_len]);
            let mac_total_len = 2 + hmac_len;
            duplicate_buf[mac_total_len..mac_total_len + inner_blob_len]
                .copy_from_slice(&inner_blob[..inner_blob_len]);
            mac_total_len + inner_blob_len
        } else {
            // No outer wrapper
            duplicate_buf[..inner_blob_len].copy_from_slice(&inner_blob[..inner_blob_len]);
            inner_blob_len
        };

        let duplicate = Tpm2bPrivate::from_bytes(&duplicate_buf[..duplicate_len]).unwrap();
        let rsp = responses::Duplicate {
            encryption_key_out,
            duplicate,
            out_sym_seed,
        };

        // Write response
        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
