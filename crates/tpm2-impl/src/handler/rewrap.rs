use super::encrypt_decrypt::{crypto_check, crypto_len};
use crate::handle_checks::{Tpmi, check};
use crate::handler::{CommandHandler, TransientObject};
use crate::owned::OwnedPublicParmsAndId;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Handle;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::commands::{Rewrap, responses};
#[cfg(not(feature = "reference-rng"))]
use tpm2::crypto::KeyParams;
use tpm2::crypto::kdf::kdfa_bits;
use tpm2::crypto::{CryptoProvider, Direction, HmacStream, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bPrivate, TpmEccCurve, TpmaObject,
    TpmsEccPoint,
};

/// Label used for the duplication protection seed (`DUPLICATE_STRING`).
const DUPLICATE_LABEL: &[u8] = b"DUPLICATE";

/// Builds the NUL-terminated RSA-OAEP label for `label` (e.g. `"DUPLICATE\0"`).
fn oaep_label(label: &[u8], buf: &mut [u8; 32]) -> usize {
    let len = core::cmp::min(label.len(), buf.len() - 1);
    buf[..len].copy_from_slice(&label[..len]);
    buf[len] = 0;
    len + 1
}

/// Returns the coordinate size in bytes of an ECC curve, or `None` if unsupported.
fn ecc_param_size(curve: TpmEccCurve) -> Option<usize> {
    match curve {
        TpmEccCurve::NistP192 => Some(24),
        TpmEccCurve::NistP224 => Some(28),
        TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => Some(32),
        TpmEccCurve::NistP384 => Some(48),
        TpmEccCurve::NistP521 => Some(66),
        _ => None,
    }
}

/// Left-pads an ECC coordinate to `param_size` bytes into `out`. Fails if it is larger.
fn pad_coordinate(coord: &[u8], param_size: usize, out: &mut [u8]) -> Result<(), TpmRc> {
    if coord.len() > param_size {
        return Err(TpmRc::ECC_POINT.to_rc());
    }
    out[..param_size - coord.len()].fill(0);
    out[param_size - coord.len()..param_size].copy_from_slice(coord);
    Ok(())
}

/// Returns `true` if `obj` is a storage key (C `ObjectIsStorage`): `restricted` and `decrypt`
/// SET, `sign` CLEAR, and an RSA or ECC key.
fn is_storage_object(obj: &TransientObject) -> bool {
    let attrs = obj.public.object_attributes;
    attrs.contains(TpmaObject::RESTRICTED)
        && attrs.contains(TpmaObject::DECRYPT)
        && !attrs.contains(TpmaObject::SIGN_ENCRYPT)
        && matches!(
            obj.public.parms_and_id,
            OwnedPublicParmsAndId::Rsa(_, _) | OwnedPublicParmsAndId::Ecc(_, _)
        )
}

/// Symmetric key size (bits) of a storage parent's outer wrapper (AES-CFB).
fn outer_sym_bits(obj: &TransientObject) -> u32 {
    let bits = match &obj.public.parms_and_id {
        OwnedPublicParmsAndId::Rsa(parms, _) => parms.symmetric.map(|s| s.key_bits() as u32),
        OwnedPublicParmsAndId::Ecc(parms, _) => parms.symmetric.map(|s| s.key_bits() as u32),
        _ => None,
    };
    match bits {
        Some(b) if b != 0 => b,
        _ => 128,
    }
}

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::Rewrap] (`0x152`) command.
    ///
    /// # Description
    /// This command allows the TPM to serve in the role of a Migration Authority (MA),
    /// changing the outer wrapper of a duplicate key from `old_parent` to `new_parent`.
    ///
    /// Mirrors C `Rewrap.c`: the old outer wrapper is removed with the seed recovered from
    /// `inSymSeed` (`CryptSecretDecrypt`, RSA-OAEP or ECDH+KDFe), and a new outer wrapper is
    /// produced with a fresh seed generated for and encrypted to `newParent`
    /// (`CryptSecretEncrypt`). Both parents must be storage keys (`ObjectIsStorage`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 13.2 (TPM2_Rewrap).
    pub fn rewrap(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<Rewrap>()?;
        let [old_parent, new_parent] = handles;
        check(old_parent, Tpmi::DhObjectOrNull, Position::handle(1))?;
        check(new_parent, Tpmi::DhObjectOrNull, Position::handle(2))?;
        let old_parent_handle = old_parent.0;
        let new_parent_handle = new_parent.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<Rewrap>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Input Validation: in_sym_seed consistency with old_parent
        if (cmd.in_sym_seed.get_size() == 0 && old_parent_handle != Handle::RH_NULL.0)
            || (cmd.in_sym_seed.get_size() != 0 && old_parent_handle == Handle::RH_NULL.0)
        {
            return Err(TpmRc::HANDLE.with(Position::handle(1)));
        }

        // The intermediate blob can be as large as a whole `TPM2B_PRIVATE`.
        let mut private_blob = [0u8; Tpm2bPrivate::CAP];
        let private_blob_len;

        // 1. Unwrap Outer using oldParent (if present)
        if old_parent_handle != Handle::RH_NULL.0 {
            let old_parent_obj = self.resolve_storage_parent(old_parent_handle, 1)?;

            // Decrypt input secret data. Any failure is reported as
            // `TPM_RC_VALUE + RC_Rewrap_inSymSeed`.
            let mut seed = [0u8; 64];
            let seed_len = self
                .crypt_secret_decrypt(
                    &old_parent_obj,
                    DUPLICATE_LABEL,
                    cmd.in_sym_seed.get_buffer(),
                    &mut seed,
                )
                .map_err(|_| TpmRc::VALUE.with(Position::parameter(3)))?;

            // UnwrapOuter: errors carry `RC_Rewrap_inDuplicate` (parameter 1).
            let duplicate_bytes = cmd.in_duplicate.get_buffer();
            if duplicate_bytes.len() < 2 {
                return Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)));
            }
            let mac_len = u16::from_be_bytes([duplicate_bytes[0], duplicate_bytes[1]]) as usize;
            if mac_len > 64 {
                return Err(TpmRc::SIZE.with(Position::parameter(1)));
            }
            if duplicate_bytes.len() < 2 + mac_len {
                return Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)));
            }
            let mac_bytes = &duplicate_bytes[2..2 + mac_len];
            let encrypted_blob = &duplicate_bytes[2 + mac_len..];

            let old_name_alg = old_parent_obj
                .public
                .name_alg
                .ok_or(TpmRc::TYPE.with(Position::handle(1)))?;
            let mut computed_mac = [0u8; tpm2::TpmiAlgHash::MAX_DIGEST_BYTES];
            let computed_mac_len = self.compute_outer_integrity(
                old_name_alg,
                &seed[..seed_len],
                encrypted_blob,
                cmd.name.get_buffer(),
                &mut computed_mac,
            )?;
            if mac_len != computed_mac_len
                || !crate::util::constant_time_eq(mac_bytes, &computed_mac[..computed_mac_len])
            {
                return Err(TpmRc::INTEGRITY.with(Position::parameter(1)));
            }

            private_blob_len = encrypted_blob.len();
            private_blob[..private_blob_len].copy_from_slice(encrypted_blob);
            self.outer_cfb(
                old_name_alg,
                outer_sym_bits(&old_parent_obj),
                &seed[..seed_len],
                cmd.name.get_buffer(),
                &mut private_blob[..private_blob_len],
                false,
            )?;
        } else {
            let dup_buf = cmd.in_duplicate.get_buffer();
            private_blob_len = dup_buf.len();
            private_blob[..private_blob_len].copy_from_slice(dup_buf);
        }

        // 2. Produce Outer Wrap using newParent (if present)
        let mut final_duplicate = [0u8; Tpm2bPrivate::CAP];
        let mut encrypted_secret = [0u8; 512];
        let out_sym_seed;
        let out_duplicate;

        if new_parent_handle != Handle::RH_NULL.0 {
            let new_parent_obj = self.resolve_storage_parent(new_parent_handle, 2)?;
            let new_name_alg = new_parent_obj
                .public
                .name_alg
                .ok_or(TpmRc::TYPE.with(Position::handle(2)))?;

            // Generate a fresh seed for the new parent and encrypt it to that parent.
            let mut seed = [0u8; 64];
            let (seed_len, secret_len) = self.crypt_secret_encrypt(
                &new_parent_obj,
                DUPLICATE_LABEL,
                &mut seed,
                &mut encrypted_secret,
            )?;
            out_sym_seed = Tpm2bEncryptedSecret::from_bytes(&encrypted_secret[..secret_len])
                .map_err(|_| TpmRc::FAILURE)?;

            // Make sure that the outer integrity digest still fits into the `outDuplicate` buffer
            // of this TPM's profile (`sizeof(out->outDuplicate.t.buffer)` in the C reference).
            // TPM 2.0 Part 2, Table "Definition of TPM2B_PRIVATE Structure":
            // "buffer[size] {:sizeof(_PRIVATE)} | BYTE | an encrypted private area".
            let hash_size = 2 + new_name_alg.digest_size();
            if private_blob_len + hash_size > Tpm2bPrivate::capacity() {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }

            let body = &mut final_duplicate[hash_size..hash_size + private_blob_len];
            body.copy_from_slice(&private_blob[..private_blob_len]);
            self.outer_cfb(
                new_name_alg,
                outer_sym_bits(&new_parent_obj),
                &seed[..seed_len],
                cmd.name.get_buffer(),
                body,
                true,
            )?;

            let mut outer_mac = [0u8; tpm2::TpmiAlgHash::MAX_DIGEST_BYTES];
            let outer_mac_len = self.compute_outer_integrity(
                new_name_alg,
                &seed[..seed_len],
                &final_duplicate[hash_size..hash_size + private_blob_len],
                cmd.name.get_buffer(),
                &mut outer_mac,
            )?;
            final_duplicate[..2].copy_from_slice(&(outer_mac_len as u16).to_be_bytes());
            final_duplicate[2..2 + outer_mac_len].copy_from_slice(&outer_mac[..outer_mac_len]);

            out_duplicate =
                Tpm2bPrivate::from_bytes(&final_duplicate[..hash_size + private_blob_len])
                    .map_err(|_| TpmRc::VALUE.with(Position::parameter(1)))?;
        } else {
            out_sym_seed = Tpm2bEncryptedSecret::default();
            out_duplicate = Tpm2bPrivate::from_bytes(&private_blob[..private_blob_len])
                .map_err(|_| TpmRc::VALUE.with(Position::parameter(1)))?;
        }

        let resp = responses::Rewrap {
            out_duplicate,
            out_sym_seed,
        };

        let response = request.into_response();
        self.write_response_message(response, &resp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Resolves a Rewrap parent handle (transient or persistent) and checks that it is a
    /// storage key (`TPM_RC_TYPE + RC_Hn` otherwise, including for sequence objects).
    fn resolve_storage_parent(&mut self, handle: u32, index: u8) -> Result<TransientObject, TpmRc> {
        let pos = Position::handle(index);
        if self.context.state.find_active_sequence(handle).is_some() {
            return Err(TpmRc::TYPE.with(pos));
        }
        let obj = self.resolve_object(handle, pos)?;
        if !is_storage_object(&obj) {
            return Err(TpmRc::TYPE.with(pos));
        }
        Ok(obj)
    }

    /// Computes the outer integrity HMAC (`ComputeOuterIntegrity`):
    /// `HMAC_hashAlg(KDFa(hashAlg, seed, "INTEGRITY", NULL, NULL, digestBits), data || name)`.
    /// Returns the digest length written to `out`.
    fn compute_outer_integrity(
        &self,
        hash_alg: tpm2::TpmiAlgHash,
        seed: &[u8],
        data: &[u8],
        name: &[u8],
        out: &mut [u8; tpm2::TpmiAlgHash::MAX_DIGEST_BYTES],
    ) -> Result<usize, TpmRc> {
        let digest_size = hash_alg.digest_size();
        let mut integrity_key = [0u8; 64];
        kdfa_bits(
            self.crypto(),
            hash_alg,
            seed,
            b"INTEGRITY",
            &[],
            &[],
            (digest_size * 8) as u32,
            &mut integrity_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let mut hmac_ctx = HmacStream::new(self.crypto(), hash_alg, &integrity_key[..digest_size])
            .map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx.update(data).map_err(|_| TpmRc::FAILURE)?;
        hmac_ctx.update(name).map_err(|_| TpmRc::FAILURE)?;
        let res = hmac_ctx.finalize(out).map_err(|_| TpmRc::FAILURE)?;
        Ok(res.digest().len())
    }

    /// Encrypts (or decrypts) `data` in place with the outer-wrapper key
    /// `KDFa(hashAlg, seed, "STORAGE", name, NULL, symBits)` in AES-CFB with a zero IV
    /// (duplication blobs do not carry an IV).
    fn outer_cfb(
        &self,
        hash_alg: tpm2::TpmiAlgHash,
        sym_bits: u32,
        seed: &[u8],
        name: &[u8],
        data: &mut [u8],
        encrypt: bool,
    ) -> Result<(), TpmRc> {
        let key_len = (sym_bits / 8) as usize;
        let mut key = [0u8; 32];
        kdfa_bits(
            self.crypto(),
            hash_alg,
            seed,
            b"STORAGE",
            name,
            &[],
            sym_bits,
            &mut key,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let mut iv = [0u8; 16];
        let sym_alg =
            tpm2::TpmtSymDefObject::aes_cfb(sym_bits as u16).map_err(|_| TpmRc::FAILURE)?;
        let direction = if encrypt {
            Direction::Encrypt
        } else {
            Direction::Decrypt
        };
        self.sym_encrypt_decrypt(sym_alg, &key[..key_len], &mut iv, direction, data)
            .map_err(|_| TpmRc::FAILURE)
    }

    /// Recovers a seed from `secret` with the private key of `parent` (C
    /// `CryptoCommon_SecretDecrypt()` with `label`, e.g. `DUPLICATE`, `IDENTITY` or `SECRET`):
    ///
    /// * RSA: RSAES-OAEP with the key's scheme hash, or `nameAlg` if its scheme is
    ///   `TPM_ALG_NULL` (`TPM_RC_SCHEME` for any other scheme); a ciphertext that is not as
    ///   long as the modulus, or whose value is not below the modulus, is `TPM_RC_SIZE`; a
    ///   decoding failure, or a seed longer than the scheme hash's digest, is `TPM_RC_VALUE`.
    /// * ECC: `KDFe(nameAlg, ([d]Qe).x, label, Qe.x, Qs.x, digestBits)` with `Qe` unmarshaled
    ///   from the front of `secret` (unmarshal errors; bytes after it are ignored), or
    ///   `TPM_RC_ECC_POINT` for a point that is not on the curve.
    ///
    /// TPM 2.0 Part 1, "RSAES_OAEP": "This encryption scheme is defined in RFC 8017
    /// [@{rfc8017}]. It is the only scheme used with an RSA-restricted decryption key." The
    /// specification assigns no response codes to the RFC 8017 decryption failures (RFC 8017,
    /// 7.1.2: "If the length of the ciphertext C is not k octets ... output 'decryption
    /// error'"; 5.1.2 RSADP: "If the ciphertext representative c is not between 0 and n - 1,
    /// output 'ciphertext representative out of range'"), nor to bytes after the ECC point, so
    /// they follow the TCG reference (`CryptoRsa_Decrypt()`: "Size is checked to make sure that
    /// the encrypted value is the right size", `TPM_RC_SIZE`).
    ///
    /// Returns the seed length. Errors carry no position; callers add the parameter position of
    /// `secret`.
    pub(crate) fn crypt_secret_decrypt(
        &self,
        parent: &TransientObject,
        label: &[u8],
        secret: &[u8],
        seed: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        let name_alg = parent.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        match &parent.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, unique) => {
                // "If the key scheme is TPM_ALG_NULL, set the scheme to OAEP and set the
                // algorithm to the name algorithm" (C).
                let hash = match parms.scheme {
                    None => name_alg,
                    Some(scheme) if scheme.scheme() == Alg::OAEP => {
                        scheme.hash_alg().ok_or(TpmRc::SCHEME.to_rc())?
                    }
                    Some(_) => return Err(TpmRc::SCHEME.to_rc()),
                };
                let digest_size = hash.digest_size();
                if digest_size == 0 {
                    return Err(TpmRc::SCHEME.to_rc());
                }
                let modulus = unique.get_buffer();
                if secret.len() != modulus.len() || secret >= modulus {
                    return Err(TpmRc::SIZE.to_rc());
                }
                let mut label_buf = [0u8; 32];
                let label_len = oaep_label(label, &mut label_buf);
                let mut plaintext = [0u8; 512];
                let len = crypto_len(
                    self.crypto().decrypt(
                        Alg::OAEP,
                        Alg::from(hash),
                        &parent.private[..parent.private_len],
                        secret,
                        &mut plaintext,
                        &label_buf[..label_len],
                    ),
                    TpmRc::VALUE.to_rc(),
                )?;
                // The recovered seed may not be larger than the scheme hash's digest.
                if len > digest_size || len > seed.len() {
                    return Err(TpmRc::VALUE.to_rc());
                }
                seed[..len].copy_from_slice(&plaintext[..len]);
                Ok(len)
            }
            OwnedPublicParmsAndId::Ecc(parms, unique) => {
                let curve = parms.curve_id;
                let param_size = ecc_param_size(curve).ok_or(TpmRc::CURVE.to_rc())?;
                // Bytes after the point are not examined (C unmarshals the point from the
                // front of the buffer and ignores the rest).
                let mut slice = secret;
                let eph_point = TpmsEccPoint::unmarshal(&mut slice).map_err(|e| e.to_rc())?;
                let mut eph = [0u8; 132];
                pad_coordinate(eph_point.x.get_buffer(), param_size, &mut eph[..param_size])?;
                pad_coordinate(
                    eph_point.y.get_buffer(),
                    param_size,
                    &mut eph[param_size..param_size * 2],
                )?;
                crypto_check(
                    self.crypto().validate_point(curve, &eph[..param_size * 2]),
                    TpmRc::ECC_POINT.to_rc(),
                )?;
                let mut z = [0u8; 256];
                crypto_len(
                    self.crypto().point_multiply(
                        curve,
                        &parent.private[..parent.private_len],
                        &eph[..param_size * 2],
                        &mut z,
                    ),
                    TpmRc::ECC_POINT.to_rc(),
                )?;
                let digest_size = name_alg.digest_size();
                tpm2::crypto::kdf::kdfe_bits(
                    self.crypto(),
                    name_alg,
                    &z[..param_size],
                    label,
                    eph_point.x.get_buffer(),
                    unique.x.get_buffer(),
                    (digest_size * 8) as u32,
                    seed,
                )
                .map_err(|_| TpmRc::FAILURE)?;
                Ok(digest_size)
            }
            _ => Err(TpmRc::TYPE.to_rc()),
        }
    }

    /// Generates a fresh seed for `parent` and encrypts it to that parent (C
    /// `CryptSecretEncrypt` with `label`): a random nameAlg-sized seed encrypted with RSA-OAEP,
    /// or for ECC an ephemeral key `Qe` with
    /// `seed = KDFe(nameAlg, ([de]Qs).x, label, Qe.x, Qs.x, digestBits)` and `Qe` as the
    /// secret (`TPM_RC_KEY` if the parent's public point is unusable). Returns
    /// `(seed_len, secret_len)`.
    pub(crate) fn crypt_secret_encrypt(
        &mut self,
        parent: &TransientObject,
        label: &[u8],
        seed: &mut [u8; 64],
        secret_out: &mut [u8; 512],
    ) -> Result<(usize, usize), TpmRc> {
        let name_alg = parent.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        let digest_size = name_alg.digest_size();
        match &parent.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(_, unique) => {
                self.context.random_crypto(&mut seed[..digest_size])?;
                let mut label_buf = [0u8; 32];
                let label_len = oaep_label(label, &mut label_buf);
                // With `reference-rng`, the OAEP seed is drawn from the TPM's DRBG as in the
                // reference (`OaepEncode()`).
                #[cfg(feature = "reference-rng")]
                let encrypted = {
                    let n_len = unique.get_size() as usize;
                    self.reference_rsa_encrypt(
                        Some(name_alg),
                        unique.get_buffer(),
                        &label_buf[..label_len],
                        &seed[..digest_size],
                        &mut secret_out[..n_len],
                    )
                    .map_err(|_| tpm2::crypto::CryptoError::Internal)
                };
                #[cfg(not(feature = "reference-rng"))]
                let encrypted = self.crypto().encrypt(
                    Alg::OAEP,
                    Alg::from(name_alg),
                    unique.get_buffer(),
                    &seed[..digest_size],
                    secret_out,
                    &label_buf[..label_len],
                );
                let secret_len = crypto_len(encrypted, TpmRc::VALUE.to_rc())?;
                Ok((digest_size, secret_len))
            }
            OwnedPublicParmsAndId::Ecc(parms, unique) => {
                let curve = parms.curve_id;
                let param_size = ecc_param_size(curve).ok_or(TpmRc::CURVE.to_rc())?;
                let mut parent_point = [0u8; 132];
                pad_coordinate(
                    unique.x.get_buffer(),
                    param_size,
                    &mut parent_point[..param_size],
                )
                .map_err(|_| TpmRc::KEY.to_rc())?;
                pad_coordinate(
                    unique.y.get_buffer(),
                    param_size,
                    &mut parent_point[param_size..param_size * 2],
                )
                .map_err(|_| TpmRc::KEY.to_rc())?;
                let mut eph_pub = [0u8; 256];
                let mut eph_priv = [0u8; 128];
                // `CryptEccNewKeyPair()`: with `reference-rng`, from the TPM's DRBG.
                #[cfg(feature = "reference-rng")]
                let priv_len =
                    self.reference_ecc_new_key_pair(curve, &mut eph_priv, &mut eph_pub)?;
                #[cfg(not(feature = "reference-rng"))]
                let (_, priv_len) = self
                    .crypto()
                    .generate_key(
                        Alg::ECDH,
                        Some(KeyParams::Ecc(curve)),
                        &mut eph_pub,
                        &mut eph_priv,
                        None,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                let mut z = [0u8; 256];
                crypto_len(
                    self.crypto().point_multiply(
                        curve,
                        &eph_priv[..priv_len],
                        &parent_point[..param_size * 2],
                        &mut z,
                    ),
                    TpmRc::KEY.to_rc(),
                )?;
                tpm2::crypto::kdf::kdfe_bits(
                    self.crypto(),
                    name_alg,
                    &z[..param_size],
                    label,
                    &eph_pub[..param_size],
                    unique.x.get_buffer(),
                    (digest_size * 8) as u32,
                    seed,
                )
                .map_err(|_| TpmRc::FAILURE)?;
                let eph_point = TpmsEccPoint {
                    x: Tpm2bEccParameter::from_bytes(&eph_pub[..param_size])
                        .map_err(|_| TpmRc::FAILURE)?,
                    y: Tpm2bEccParameter::from_bytes(&eph_pub[param_size..param_size * 2])
                        .map_err(|_| TpmRc::FAILURE)?,
                };
                let mut point_buf = [0u8; TpmsEccPoint::MAX_SIZE];
                let len = eph_point.marshal(&mut point_buf);
                secret_out[..len].copy_from_slice(&point_buf[..len]);
                Ok((digest_size, len))
            }
            _ => Err(TpmRc::TYPE.to_rc()),
        }
    }
}
