use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::{CommandHandler, TransientObject};
use crate::owned::OwnedPublicParmsAndId;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Rewrap, responses};
use tpm2::crypto::{Direction, Ecc, Rsa, RsaEncryptScheme, kdfa, kdfe};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Marshal, Tpm2bEncryptedSecret, Tpm2bPrivate, TpmHt, TpmaObject, TpmiAlgHash,
    TpmiRsaKeyBits, TpmsEccPoint, Unmarshal,
};

use super::crypt_ops::{
    PaddedEccPoint, ecc_param_size, ecc_point_multiply, ecc_public_point, load_ecc_private,
    load_ecc_public, load_rsa_private, load_rsa_public,
};
use super::duplicate::{DUPLICATE_LABEL, Writer, aes_cfb, outer_sym_key_bits};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Rewrap] (`0x152`) command.
    ///
    /// # Description
    /// This command allows the TPM to serve in the role of a Migration Authority (MA),
    /// changing the outer wrapper of a duplicate key from `old_parent` to `new_parent`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 13.2 (TPM2_Rewrap).
    pub fn rewrap(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<Rewrap>()?;
        let [old_parent_handle, new_parent_handle] = handles;
        check(old_parent_handle, Tpmi::DhObjectOrNull, Position::handle(1))?;
        check(new_parent_handle, Tpmi::DhObjectOrNull, Position::handle(2))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<Rewrap>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Input Validation: in_sym_seed consistency with old_parent
        let in_sym_seed = cmd.in_sym_seed.as_slice();
        if (in_sym_seed.is_empty() && old_parent_handle != Handle::RH_NULL)
            || (!in_sym_seed.is_empty() && old_parent_handle == Handle::RH_NULL)
        {
            return Err(TpmRc::HANDLE.with(Position::handle(1)));
        }

        let mut private_blob = [0u8; Tpm2bPrivate::CAP];
        let private_blob_len;

        // 1. Unwrap Outer using oldParent (if present)
        if old_parent_handle != Handle::RH_NULL {
            let old_parent_obj = self.rewrap_parent(old_parent_handle, Position::handle(1))?;

            // old_parent must be a storage object (decrypt + restricted)
            if !old_parent_obj
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
                || !old_parent_obj
                    .public
                    .object_attributes
                    .contains(TpmaObject::RESTRICTED)
            {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }

            // Decrypt in_sym_seed using old_parent private key
            //
            // PORTING: exp passed its opaque private-key blob to `decrypt`; the private key is
            // now loaded from the object's public and sensitive areas first, and a key that
            // fails to load is reported like a failing `decrypt`. exp only supported RSA parents.
            let mut seed = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
            let seed_len = match &old_parent_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, modulus) => {
                    let name_alg = old_parent_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                    let crypto = self.crypto();
                    let key = load_rsa_private(
                        crypto,
                        parms,
                        modulus.get_buffer(),
                        &old_parent_obj.sensitive,
                    )
                    .ok_or(TpmRc::VALUE.with(Position::parameter(3)))?;
                    let mut decrypted = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                    let plaintext = Rsa::decrypt(
                        crypto,
                        &key,
                        RsaEncryptScheme::Oaep {
                            hash: name_alg,
                            label: DUPLICATE_LABEL,
                        },
                        in_sym_seed,
                        &mut decrypted,
                    )
                    .ok()
                    .flatten()
                    .ok_or(TpmRc::VALUE.with(Position::parameter(3)))?;
                    let mut writer = Writer::new(&mut seed);
                    writer
                        .bytes(plaintext.as_slice())
                        .map_err(|_| TpmRc::VALUE.with(Position::parameter(3)))?;
                    writer.offset()
                }
                OwnedPublicParmsAndId::Ecc(parms, unique) => {
                    let value_err = TpmRc::VALUE.with(Position::parameter(3));
                    let mut slice = in_sym_seed;
                    let eph_point = TpmsEccPoint::unmarshal(&mut slice).map_err(|_| value_err)?;
                    if !slice.is_empty() {
                        return Err(value_err);
                    }
                    let curve = parms.curve_id;
                    let param_size = ecc_param_size(curve).ok_or(value_err)?;
                    let eph_pub =
                        PaddedEccPoint::from_tpms(&eph_point, param_size).ok_or(value_err)?;
                    let crypto = self.crypto();
                    let peer = load_ecc_public(crypto, curve, &eph_pub).ok_or(value_err)?;
                    let key = load_ecc_private(crypto, curve, unique, &old_parent_obj.sensitive)
                        .ok_or(value_err)?;
                    let ecdh_point = ecc_point_multiply(crypto, &key, &peer, param_size)
                        .ok()
                        .flatten()
                        .ok_or(value_err)?;
                    let parent_pub = PaddedEccPoint::new(
                        unique.x.get_buffer(),
                        unique.y.get_buffer(),
                        param_size,
                    )
                    .ok_or(value_err)?;
                    let name_alg = old_parent_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                    let digest_size = name_alg.digest_size();
                    kdfe(
                        crypto,
                        name_alg,
                        ecdh_point.x(),
                        c"DUPLICATE",
                        eph_pub.x(),
                        parent_pub.x(),
                        seed.get_mut(..digest_size).ok_or(TpmRc::FAILURE)?,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                    digest_size
                }
                _ => {
                    return Err(TpmRc::TYPE.with(Position::handle(1)));
                }
            };

            let duplicate_bytes = cmd.in_duplicate.as_slice();
            let (mac_size, rest) = duplicate_bytes
                .split_first_chunk::<2>()
                .ok_or(TpmRc::SIZE.to_rc())?;
            let mac_len = usize::from(u16::from_be_bytes(*mac_size));
            let (mac_bytes, encrypted_blob) =
                rest.split_at_checked(mac_len).ok_or(TpmRc::SIZE.to_rc())?;

            let sym_key_bits = outer_sym_key_bits(&old_parent_obj.public.parms_and_id);
            let outer_key_len = usize::from(sym_key_bits / 8);

            let mut sym_key_iv = [0u8; AlgSym::MAX_KEY_BYTES];
            let mut integrity_key = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

            let old_name_alg = old_parent_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
            let old_digest_size = old_name_alg.digest_size();
            let crypto = self.crypto();
            let integrity_key = integrity_key
                .get_mut(..old_digest_size)
                .ok_or(TpmRc::FAILURE)?;
            kdfa(
                crypto,
                old_name_alg,
                &seed[..seed_len],
                c"INTEGRITY",
                &[],
                &[],
                integrity_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            let outer_key = sym_key_iv.get_mut(..outer_key_len).ok_or(TpmRc::FAILURE)?;
            kdfa(
                crypto,
                old_name_alg,
                &seed[..seed_len],
                c"STORAGE",
                cmd.name.as_slice(),
                &[],
                outer_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;

            let (computed_mac_bytes, computed_mac_len) = self
                .compute_hmac(
                    old_name_alg,
                    integrity_key,
                    &[encrypted_blob, cmd.name.as_slice()],
                )
                .map_err(|_| TpmRc::FAILURE)?;

            if mac_len != computed_mac_len
                || !crate::util::constant_time_eq(
                    mac_bytes,
                    computed_mac_bytes
                        .get(..computed_mac_len)
                        .ok_or(TpmRc::FAILURE)?,
                )
            {
                return Err(TpmRc::INTEGRITY.to_rc());
            }

            // Decrypt outer layer using outer key (CFB mode)
            let mut writer = Writer::new(&mut private_blob);
            writer.bytes(encrypted_blob)?;
            private_blob_len = writer.offset();
            aes_cfb(
                crypto,
                outer_key,
                Direction::Decrypt,
                &mut private_blob[..private_blob_len],
            )?;
        } else {
            let mut writer = Writer::new(&mut private_blob);
            writer.bytes(cmd.in_duplicate.as_slice())?;
            private_blob_len = writer.offset();
        }
        let private_blob = &mut private_blob[..private_blob_len];

        // 2. Produce Outer Wrap using newParent (if present)
        let mut encrypted_secret = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut out_sym_seed_buf = [0u8; TpmsEccPoint::MAX_SIZE];
        let mut final_duplicate = [0u8; Tpm2bPrivate::CAP];
        let out_sym_seed;
        let out_duplicate;

        if new_parent_handle != Handle::RH_NULL {
            let new_parent_obj = self.rewrap_parent(new_parent_handle, Position::handle(2))?;

            // new_parent must be a storage object (decrypt + restricted)
            if !new_parent_obj
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
                || !new_parent_obj
                    .public
                    .object_attributes
                    .contains(TpmaObject::RESTRICTED)
            {
                return Err(TpmRc::TYPE.with(Position::handle(2)));
            }

            let new_name_alg = new_parent_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;

            // Protect a fresh seed to the new parent ("Secret Sharing" in TPM 2.0 Part 1;
            // `CryptSecretEncrypt` in the reference implementation).
            //
            // PORTING: exp re-encrypted the seed recovered from the old parent (an empty seed if
            // `oldParent` was TPM_RH_NULL) and only supported RSA parents. A public key that fails
            // to load is reported like a failing `encrypt`.
            let new_digest_size = new_name_alg.digest_size();
            let mut new_seed = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
            let new_seed = new_seed.get_mut(..new_digest_size).ok_or(TpmRc::FAILURE)?;
            out_sym_seed = match &new_parent_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, modulus) => {
                    self.fill_random(new_seed).map_err(|_| TpmRc::FAILURE)?;
                    let crypto = self.crypto();
                    let key = load_rsa_public(crypto, parms, modulus.get_buffer())
                        .ok_or(TpmRc::FAILURE)?;
                    let encrypted = Rsa::encrypt(
                        crypto,
                        &mut self.context.platform.rng,
                        &key,
                        RsaEncryptScheme::Oaep {
                            hash: new_name_alg,
                            label: DUPLICATE_LABEL,
                        },
                        new_seed,
                        &mut encrypted_secret,
                    )
                    .ok()
                    .flatten()
                    .ok_or(TpmRc::FAILURE)?;
                    Tpm2bEncryptedSecret::new(encrypted.as_slice()).ok_or(TpmRc::FAILURE)?
                }
                OwnedPublicParmsAndId::Ecc(parms, unique) => {
                    let crypto = self.crypto();
                    let curve = parms.curve_id;
                    let param_size = ecc_param_size(curve).ok_or(TpmRc::VALUE.to_rc())?;
                    let parent_point = PaddedEccPoint::new(
                        unique.x.get_buffer(),
                        unique.y.get_buffer(),
                        param_size,
                    )
                    .ok_or(TpmRc::VALUE.to_rc())?;
                    let eph_key = Ecc::generate_key(crypto, &mut self.context.platform.rng, curve)
                        .map_err(|_| TpmRc::FAILURE)?;
                    let parent_pub =
                        load_ecc_public(crypto, curve, &parent_point).ok_or(TpmRc::FAILURE)?;
                    let ecdh_point = ecc_point_multiply(crypto, &eph_key, &parent_pub, param_size)
                        .ok()
                        .flatten()
                        .ok_or(TpmRc::FAILURE)?;
                    let eph_point =
                        ecc_public_point::<C>(&eph_key, param_size).ok_or(TpmRc::FAILURE)?;
                    kdfe(
                        crypto,
                        new_name_alg,
                        ecdh_point.x(),
                        c"DUPLICATE",
                        eph_point.x(),
                        parent_point.x(),
                        new_seed,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                    let out_sym_seed_len = eph_point.as_tpms()?.marshal(&mut out_sym_seed_buf);
                    Tpm2bEncryptedSecret::new(&out_sym_seed_buf[..out_sym_seed_len])
                        .ok_or(TpmRc::FAILURE)?
                }
                _ => {
                    return Err(TpmRc::TYPE.with(Position::handle(2)));
                }
            };
            let crypto = self.crypto();

            // Derive outer symmetric key/IV and integrity key using newParent nameAlg
            let sym_key_bits = outer_sym_key_bits(&new_parent_obj.public.parms_and_id);
            let outer_key_len = usize::from(sym_key_bits / 8);

            let mut sym_key_iv = [0u8; AlgSym::MAX_KEY_BYTES];
            let mut integrity_key = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

            let outer_key = sym_key_iv.get_mut(..outer_key_len).ok_or(TpmRc::FAILURE)?;
            kdfa(
                crypto,
                new_name_alg,
                new_seed,
                c"STORAGE",
                cmd.name.as_slice(),
                &[],
                outer_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            let integrity_key = integrity_key
                .get_mut(..new_digest_size)
                .ok_or(TpmRc::FAILURE)?;
            kdfa(
                crypto,
                new_name_alg,
                new_seed,
                c"INTEGRITY",
                &[],
                &[],
                integrity_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;

            // Encrypt private_blob with outer key (CFB mode)
            aes_cfb(crypto, outer_key, Direction::Encrypt, private_blob)?;

            // Compute outer HMAC over ciphertext + name
            let (outer_mac, outer_mac_len) = self
                .compute_hmac(
                    new_name_alg,
                    integrity_key,
                    &[&*private_blob, cmd.name.as_slice()],
                )
                .map_err(|_| TpmRc::FAILURE)?;

            let mut writer = Writer::new(&mut final_duplicate);
            writer.sized(outer_mac.get(..outer_mac_len).ok_or(TpmRc::FAILURE)?)?;
            writer.bytes(private_blob)?;
            let final_len = writer.offset();

            out_duplicate =
                Tpm2bPrivate::new(&final_duplicate[..final_len]).ok_or(TpmRc::FAILURE)?;
        } else {
            out_sym_seed = Tpm2bEncryptedSecret::default();
            out_duplicate = Tpm2bPrivate::new(private_blob).ok_or(TpmRc::FAILURE)?;
        }

        let resp = responses::Rewrap {
            out_duplicate,
            out_sym_seed,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &resp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Looks up the old or new parent (`handle`, at handle position `pos`) of `TPM2_Rewrap`:
    /// a loaded transient object or a persistent object. Any lookup failure is
    /// `TPM_RC_HANDLE` at `pos`.
    fn rewrap_parent(&mut self, handle: Handle, pos: Position) -> Result<TransientObject, TpmRc> {
        match handle.handle_type() {
            Some(TpmHt::Transient) => self
                .global_state
                .find_transient_object(handle.0)
                .cloned()
                .ok_or(TpmRc::HANDLE.with(pos)),
            Some(TpmHt::Persistent) => self
                .context
                .load_persistent_object(self.global_state, handle.0)
                .map_err(|_| TpmRc::HANDLE.with(pos)),
            _ => Err(TpmRc::HANDLE.with(pos)),
        }
    }
}
