use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::owned::OwnedPublicParmsAndId;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Handle;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Duplicate, responses};
use tpm2::crypto::{Direction, Ecc, ModeIv, Rsa, RsaEncryptScheme, SymmetricKey, kdfa, kdfe};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Tpm2b, Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bSensitive, TpmaObject,
    TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmsEccPoint, TpmtSensitive,
};

use super::crypt_ops::{
    PaddedEccPoint, ecc_param_size, ecc_point_multiply, ecc_public_point, load_ecc_public,
    load_rsa_public,
};

/// OAEP label (including its terminating NUL) used to protect the seed of a duplication blob
/// (`TPM2_Duplicate`, `TPM2_Rewrap`, `TPM2_Import`).
pub(super) const DUPLICATE_LABEL: &[u8] = b"DUPLICATE\0";

/// Sequential writer over a fixed-size byte buffer, shared by the duplication, credential and
/// context handlers.
///
/// Every write fails with `TPM_RC_FAILURE` if it would overrun the buffer.
///
/// PORTING: replaces exp's manual `buf[offset..offset + n].copy_from_slice(..)` offset
/// arithmetic (which panicked on overrun).
pub(super) struct Writer<'w> {
    buf: &'w mut [u8],
    offset: usize,
}

impl<'w> Writer<'w> {
    /// Creates a writer that starts writing at the beginning of `buf`.
    pub(super) fn new(buf: &'w mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// Number of bytes written so far.
    pub(super) fn offset(&self) -> usize {
        self.offset
    }

    /// Reserves the next `n` bytes of the buffer and returns them for writing.
    pub(super) fn reserve(&mut self, n: usize) -> Result<&mut [u8], TpmRc> {
        let end = self.offset.checked_add(n).ok_or(TpmRc::FAILURE)?;
        let dst = self.buf.get_mut(self.offset..end).ok_or(TpmRc::FAILURE)?;
        self.offset = end;
        Ok(dst)
    }

    /// Appends `data`.
    pub(super) fn bytes(&mut self, data: &[u8]) -> Result<(), TpmRc> {
        self.reserve(data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// Appends `data` prefixed with its length as a big-endian `u16` (the `TPM2B` encoding).
    pub(super) fn sized(&mut self, data: &[u8]) -> Result<(), TpmRc> {
        let size = u16::try_from(data.len()).map_err(|_| TpmRc::FAILURE)?;
        self.bytes(&size.to_be_bytes())?;
        self.bytes(data)
    }

    /// Appends the marshaled form of `value`.
    pub(super) fn value<const N: usize>(
        &mut self,
        value: &impl Marshal<MaxBuffer = [u8; N]>,
    ) -> Result<(), TpmRc> {
        let mut tmp = [0u8; N];
        let len = value.marshal(&mut tmp);
        self.bytes(tmp.get(..len).ok_or(TpmRc::FAILURE)?)
    }
}

/// Encrypts or decrypts `data` in place with symmetric algorithm `alg` in `mode` under `key`,
/// starting from an all-zero IV.
///
/// Any failure (unsupported key size or mode, missing mode, data length not allowed by a block
/// mode, backend error) is `TPM_RC_FAILURE`, as exp mapped its `tpm2::crypto::{encrypt,
/// decrypt}` errors.
pub(super) fn zero_iv_crypt<C: Crypto>(
    crypto: &C,
    alg: AlgSym,
    mode: Option<TpmiAlgSymMode>,
    key: &[u8],
    dir: Direction,
    data: &mut [u8],
) -> Result<(), TpmRc> {
    let Some(TpmiAlgSymMode::Cipher(mode)) = mode else {
        return Err(TpmRc::FAILURE);
    };
    let key = SymmetricKey::new(alg, key).ok_or(TpmRc::FAILURE)?;
    let mut iv = [0u8; AlgSym::BLOCK_SIZE];
    let mode_iv = ModeIv::new(mode, &mut iv).ok_or(TpmRc::FAILURE)?;
    if !mode_iv.is_valid_data_len(data.len()) {
        return Err(TpmRc::FAILURE);
    }
    tpm2::crypto::encrypt_decrypt(crypto, key, mode_iv, dir, data).map_err(|_| TpmRc::FAILURE)
}

/// Encrypts or decrypts `data` in place with AES in CFB mode under `key` (16, 24 or 32 bytes),
/// starting from an all-zero IV.
///
/// exp uses AES-CFB for both the inner and the outer wrapper of duplication blobs, whatever the
/// symmetric algorithm of the (new) parent; only the key size follows it. Any failure is
/// `TPM_RC_FAILURE`.
pub(super) fn aes_cfb<C: Crypto>(
    crypto: &C,
    key: &[u8],
    dir: Direction,
    data: &mut [u8],
) -> Result<(), TpmRc> {
    let bits = u16::try_from(key.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(TpmRc::FAILURE)?;
    let alg = AlgSym::new(Alg::AES, bits).ok_or(TpmRc::FAILURE)?;
    let cfb = Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb));
    zero_iv_crypt(crypto, alg, cfb, key, dir, data)
}

/// Returns the key size (in bits) of the outer wrapper of a duplication blob protected by a
/// storage parent: the key size of the parent's symmetric algorithm, or 128 if it has none.
pub(super) fn outer_sym_key_bits(parms_and_id: &OwnedPublicParmsAndId) -> u16 {
    let symmetric = match parms_and_id {
        OwnedPublicParmsAndId::Rsa(parms, _) => parms.symmetric,
        OwnedPublicParmsAndId::Ecc(parms, _) => parms.symmetric,
        _ => None,
    };
    symmetric.map_or(128, |s| s.alg.key_bits())
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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

        let handles = request.try_unmarshal_handles::<Duplicate>()?;
        let [object_handle, new_parent_handle] = handles;
        check(object_handle, Tpmi::DhObject, Position::handle(1))?;
        check(new_parent_handle, Tpmi::DhObjectOrNull, Position::handle(2))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<Duplicate>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Retrieve the target object to duplicate
        let target_obj = self
            .global_state
            .find_transient_object(object_handle.0)
            .cloned()
            .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;

        // 2. Check fixedParent and fixedTPM attributes
        if target_obj
            .public
            .object_attributes
            .intersects(TpmaObject::FIXED_PARENT | TpmaObject::FIXED_TPM)
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
            if new_parent_handle == Handle::RH_NULL {
                return Err(TpmRc::HIERARCHY.with(Position::handle(2)));
            }
        }

        // 3. Resolve the new parent key public key modulus/parameters
        let mut parent_name_alg = TpmiAlgHash::Sha256;
        let mut parent_ecc = None;
        let mut parent_obj = None;

        if new_parent_handle != Handle::RH_NULL {
            let obj = self
                .global_state
                .find_transient_object(new_parent_handle.0)
                .cloned()
                .ok_or(TpmRc::HANDLE.with(Position::handle(2)))?;
            if !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
                || !obj
                    .public
                    .object_attributes
                    .contains(TpmaObject::RESTRICTED)
            {
                return Err(TpmRc::TYPE.with(Position::handle(2)));
            }

            // Parent must be an asymmetric key
            match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(_, _) => {
                    parent_name_alg = obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                }
                OwnedPublicParmsAndId::Ecc(parms, unique) => {
                    parent_name_alg = obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                    let curve = parms.curve_id;
                    let param_size = ecc_param_size(curve).ok_or(TpmRc::VALUE.to_rc())?;
                    let point = PaddedEccPoint::new(
                        unique.x.get_buffer(),
                        unique.y.get_buffer(),
                        param_size,
                    )
                    .ok_or(TpmRc::VALUE.to_rc())?;
                    parent_ecc = Some((curve, param_size, point));
                }
                _ => {
                    return Err(TpmRc::TYPE.with(Position::handle(2)));
                }
            }
            parent_obj = Some(obj);
        }

        let parent_parms = parent_obj.as_ref().map(|obj| &obj.public.parms_and_id);
        let parent_symmetric_is_null = match parent_parms {
            Some(OwnedPublicParmsAndId::Rsa(parms, _)) => parms.symmetric.is_none(),
            Some(OwnedPublicParmsAndId::Ecc(parms, _)) => parms.symmetric.is_none(),
            _ => true,
        };

        // Reconstruct TpmtSensitive for target object
        //
        // PORTING: exp rebuilt the `TPMU_SENSITIVE_COMPOSITE` from its opaque private-key blob
        // (converting RSA keys back to their first prime); `TransientObject::sensitive` now
        // holds it directly (ML-DSA / ML-KEM: the 32 / 64-byte private seed).
        let tpmt_sensitive = TpmtSensitive {
            auth_value: target_obj.auth.as_tpm2b(),
            seed_value: target_obj.seed.as_tpm2b(),
            sensitive: target_obj.sensitive.as_tpmu(),
        };

        let encryption_key_in = cmd.encryption_key_in.as_slice();
        if let Some(sym_def) = cmd.symmetric_alg {
            let sym_key_len = sym_def.alg.key_bytes();
            if !encryption_key_in.is_empty() && encryption_key_in.len() != sym_key_len {
                return Err(TpmRc::SIZE.with(Position::parameter(1)));
            }
        } else if !encryption_key_in.is_empty() {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // Marshal sensitive area (with its 2-byte size prefix)
        let mut sens_buf = [0u8; Tpm2bSensitive::MAX_SIZE];
        let total_sens_len = Tpm2b(tpmt_sensitive).marshal(&mut sens_buf);
        let sensitive_bytes = sens_buf.get(..total_sens_len).ok_or(TpmRc::FAILURE)?;

        // 4. Inner wrapper encryption
        let mut inner_blob = [0u8; Tpm2bPrivate::CAP];
        let mut sym_key = [0u8; AlgSym::MAX_KEY_BYTES];
        let mut encryption_key_out = Tpm2bData::default();

        let inner_blob_len = if let Some(sym_def) = cmd.symmetric_alg {
            // Determine symmetric key
            let sym_key_len = sym_def.alg.key_bytes();
            if encryption_key_in.is_empty() {
                // Generate a random key
                self.fill_random(sym_key.get_mut(..sym_key_len).ok_or(TpmRc::FAILURE)?)
                    .map_err(|_| TpmRc::FAILURE)?;
                encryption_key_out =
                    Tpm2bData::new(&sym_key[..sym_key_len]).ok_or(TpmRc::FAILURE)?;
            } else {
                Writer::new(&mut sym_key).bytes(encryption_key_in)?;
            }

            // Inner integrity digest
            let name_alg = target_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
            let (hash_bytes, hash_len) =
                self.compute_hash(name_alg, &[sensitive_bytes, target_obj.name.get_buffer()])?;
            let mut writer = Writer::new(&mut inner_blob);
            writer.sized(hash_bytes.get(..hash_len).ok_or(TpmRc::FAILURE)?)?;
            writer.bytes(sensitive_bytes)?;
            let unencrypted_inner_len = writer.offset();

            // Encrypt using CFB mode
            aes_cfb(
                self.crypto(),
                &sym_key[..sym_key_len],
                Direction::Encrypt,
                &mut inner_blob[..unencrypted_inner_len],
            )?;
            unencrypted_inner_len
        } else {
            // No inner wrapper
            let mut writer = Writer::new(&mut inner_blob);
            writer.bytes(sensitive_bytes)?;
            writer.offset()
        };

        // 5. Outer wrapper encryption
        let mut duplicate_buf = [0u8; Tpm2bPrivate::CAP];
        let mut out_sym_seed_buf = [0u8; TpmsEccPoint::MAX_SIZE];
        let mut encrypted_seed = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut out_sym_seed = Tpm2bEncryptedSecret::default();

        let duplicate_bytes: &[u8] = match (&parent_obj, parent_symmetric_is_null) {
            (Some(parent), false) => {
                // Generate seed
                let mut seed = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
                let seed_len;
                let crypto = self.crypto();

                if let Some((curve, param_size, parent_point)) = &parent_ecc {
                    // ECC seed encryption (ECDH point multiply and KDFe)
                    // 1. Generate ephemeral ECC key pair
                    let eph_key = Ecc::generate_key(crypto, &mut self.context.platform.rng, *curve)
                        .map_err(|_| TpmRc::FAILURE)?;

                    // 2. Perform ECDH point multiplication
                    let parent_pub =
                        load_ecc_public(crypto, *curve, parent_point).ok_or(TpmRc::FAILURE)?;
                    let ecdh_point = ecc_point_multiply(crypto, &eph_key, &parent_pub, *param_size)
                        .ok()
                        .flatten()
                        .ok_or(TpmRc::FAILURE)?;

                    // 3. Reconstruct ephemeral public point as TpmsEccPoint
                    let eph_point =
                        ecc_public_point::<C>(&eph_key, *param_size).ok_or(TpmRc::FAILURE)?;

                    // Marshal ephemeral point as out_sym_seed
                    let out_sym_seed_len = eph_point.as_tpms()?.marshal(&mut out_sym_seed_buf);
                    out_sym_seed = Tpm2bEncryptedSecret::new(&out_sym_seed_buf[..out_sym_seed_len])
                        .ok_or(TpmRc::FAILURE)?;

                    // 4. KDFe to recover seed
                    let digest_size = parent_name_alg.digest_size();
                    kdfe(
                        crypto,
                        parent_name_alg,
                        ecdh_point.x(),
                        c"DUPLICATE",
                        eph_point.x(),
                        parent_point.x(),
                        seed.get_mut(..digest_size).ok_or(TpmRc::FAILURE)?,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                    seed_len = digest_size;
                } else {
                    // Generate a random seed
                    self.fill_random(&mut seed[..32])
                        .map_err(|_| TpmRc::FAILURE)?;

                    // RSA seed encryption
                    //
                    // PORTING: exp passed the raw modulus to `encrypt`; the public key is now
                    // loaded first, and a key that fails to load is reported like a failing
                    // `encrypt`.
                    let OwnedPublicParmsAndId::Rsa(parms, modulus) = &parent.public.parms_and_id
                    else {
                        return Err(TpmRc::FAILURE);
                    };
                    let key = load_rsa_public(crypto, parms, modulus.get_buffer())
                        .ok_or(TpmRc::FAILURE)?;
                    let encrypted = Rsa::encrypt(
                        crypto,
                        &mut self.context.platform.rng,
                        &key,
                        RsaEncryptScheme::Oaep {
                            hash: parent_name_alg,
                            label: DUPLICATE_LABEL,
                        },
                        &seed[..32],
                        &mut encrypted_seed,
                    )
                    .ok()
                    .flatten()
                    .ok_or(TpmRc::FAILURE)?;
                    out_sym_seed =
                        Tpm2bEncryptedSecret::new(encrypted.as_slice()).ok_or(TpmRc::FAILURE)?;
                    seed_len = 32;
                }
                let seed = &seed[..seed_len];

                let sym_key_bits = outer_sym_key_bits(&parent.public.parms_and_id);
                let outer_key_len = usize::from(sym_key_bits / 8);

                let mut sym_key_iv = [0u8; AlgSym::MAX_KEY_BYTES];
                let mut integrity_key = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

                // 1. Compute KDFs
                let target_name_alg = target_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                let target_digest_size = target_name_alg.digest_size();
                let outer_key = sym_key_iv.get_mut(..outer_key_len).ok_or(TpmRc::FAILURE)?;
                kdfa(
                    crypto,
                    target_name_alg,
                    seed,
                    c"STORAGE",
                    target_obj.name.get_buffer(),
                    &[],
                    outer_key,
                )
                .map_err(|_| TpmRc::FAILURE)?;
                let integrity_key = integrity_key
                    .get_mut(..target_digest_size)
                    .ok_or(TpmRc::FAILURE)?;
                kdfa(
                    crypto,
                    target_name_alg,
                    seed,
                    c"INTEGRITY",
                    &[],
                    &[],
                    integrity_key,
                )
                .map_err(|_| TpmRc::FAILURE)?;

                // 2. Encrypt inner blob using outer symmetric key (IV is all zeros for CFB mode
                //    duplication)
                let inner_blob = &mut inner_blob[..inner_blob_len];
                aes_cfb(crypto, outer_key, Direction::Encrypt, inner_blob)?;

                // 3. Compute outer HMAC dynamically over the ENCRYPTED inner_blob ciphertext
                let (hmac_bytes, hmac_len) = self
                    .compute_hmac(
                        target_name_alg,
                        integrity_key,
                        &[inner_blob, target_obj.name.get_buffer()],
                    )
                    .map_err(|_| TpmRc::FAILURE)?;

                // Format duplicate blob
                let mut writer = Writer::new(&mut duplicate_buf);
                writer.sized(hmac_bytes.get(..hmac_len).ok_or(TpmRc::FAILURE)?)?;
                writer.bytes(inner_blob)?;
                let duplicate_len = writer.offset();
                &duplicate_buf[..duplicate_len]
            }
            // No outer wrapper
            _ => &inner_blob[..inner_blob_len],
        };

        let duplicate = Tpm2bPrivate::new(duplicate_bytes).ok_or(TpmRc::FAILURE)?;
        let rsp = responses::Duplicate {
            encryption_key_out,
            duplicate,
            out_sym_seed,
        };

        // Write response
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
