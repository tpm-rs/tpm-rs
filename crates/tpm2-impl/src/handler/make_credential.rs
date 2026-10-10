use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::owned::OwnedPublicParmsAndId;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{MakeCredential, responses};
use tpm2::crypto::{Direction, Ecc, Rsa, RsaEncryptScheme, kdfa, kdfe};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bIdObject, TpmEccCurve, TpmaObject, TpmiAlgHash,
    TpmiRsaKeyBits, TpmsEccPoint,
};

use super::crypt_ops::{
    PaddedEccPoint, ecc_param_size, ecc_point_multiply, ecc_public_point, load_ecc_public,
    load_rsa_public,
};
use super::duplicate::{Writer, zero_iv_crypt};

/// OAEP label (including its terminating NUL) used to protect the seed of a credential
/// (`TPM2_MakeCredential`, `TPM2_ActivateCredential`).
pub(super) const IDENTITY_LABEL: &[u8] = b"IDENTITY\0";

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::MakeCredential] (`0x168`) command.
    ///
    /// # Description
    /// This command is used to encrypt a credential (like a symmetric key or seed) under a loaded restricted decryption key
    /// and bind it to a target object name. The resulting credential blob and encrypted seed can only be decrypted by a TPM
    /// that possesses both the private key of the restricted decryption key and the private key of the target object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.6 (TPM2_MakeCredential).
    ///
    /// # Relationships
    /// - The outputs `credential_blob` and `secret` are designed to be sent to a target TPM that executes [TpmCc::ActivateCredential](activate_credential.rs)
    ///   to decrypt the credential.
    /// - The restricted decryption key (`handle`) must be loaded on the TPM executing this command.
    pub fn make_credential(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<MakeCredential>()?;
        let [handle] = handles;
        check(handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<MakeCredential>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve protector key
        let protector_obj = self.resolve_object(handle.0, Position::handle(1))?;

        // 2. The protector key must be a restricted decryption key
        if !protector_obj
            .public
            .object_attributes
            .contains(TpmaObject::DECRYPT)
            || !protector_obj
                .public
                .object_attributes
                .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }

        let name_alg = protector_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        let digest_size = name_alg.digest_size();

        // 3. Generate seed and encrypt it into secret
        //
        // PORTING: exp passed the raw public key to its crypto provider; the keys are now
        // loaded through `tpm2::crypto::{Rsa, Ecc}` first, and a key that fails to load is
        // reported like the failing operation (`TPM_RC_FAILURE`). The ephemeral ECC key is
        // drawn from the TPM's global RNG.
        let mut seed = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let seed = seed.get_mut(..digest_size).ok_or(TpmRc::FAILURE)?;
        let mut encrypted_seed = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut secret_buf = [0u8; TpmsEccPoint::MAX_SIZE];
        let secret = match &protector_obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, pub_key) => {
                // Generate a random seed
                self.fill_random(seed).map_err(|_| TpmRc::FAILURE)?;

                // RSA encrypt seed
                let crypto = self.crypto();
                let key =
                    load_rsa_public(crypto, parms, pub_key.get_buffer()).ok_or(TpmRc::FAILURE)?;
                let encrypted = Rsa::encrypt(
                    crypto,
                    &mut self.context.platform.rng,
                    &key,
                    RsaEncryptScheme::Oaep {
                        hash: name_alg,
                        label: IDENTITY_LABEL,
                    },
                    seed,
                    &mut encrypted_seed,
                )
                .ok()
                .flatten()
                .ok_or(TpmRc::FAILURE)?;
                Tpm2bEncryptedSecret::new(encrypted.as_slice()).ok_or(TpmRc::FAILURE)?
            }
            OwnedPublicParmsAndId::Ecc(parms, point) => {
                let curve = parms.curve_id;
                let param_size = match curve {
                    TpmEccCurve::NistP192 => curve.key_bytes(),
                    _ => ecc_param_size(curve).ok_or(TpmRc::VALUE.to_rc())?,
                };
                if point.x.get_buffer().len() != param_size
                    || point.y.get_buffer().len() != param_size
                {
                    return Err(TpmRc::VALUE.with(Position::handle(1)));
                }
                let parent_ecc_pub_point =
                    PaddedEccPoint::new(point.x.get_buffer(), point.y.get_buffer(), param_size)
                        .ok_or(TpmRc::FAILURE)?;

                // Generate ephemeral ECC key pair
                let crypto = self.crypto();
                let eph_key = Ecc::generate_key(crypto, &mut self.context.platform.rng, curve)
                    .map_err(|_| TpmRc::FAILURE)?;

                // Perform ECDH point multiplication
                let parent_pub =
                    load_ecc_public(crypto, curve, &parent_ecc_pub_point).ok_or(TpmRc::FAILURE)?;
                let ecdh_point = ecc_point_multiply(crypto, &eph_key, &parent_pub, param_size)
                    .ok()
                    .flatten()
                    .ok_or(TpmRc::FAILURE)?;

                // Reconstruct ephemeral public point as TpmsEccPoint
                let eph_point =
                    ecc_public_point::<C>(&eph_key, param_size).ok_or(TpmRc::FAILURE)?;

                // Marshal ephemeral point as secret
                let secret_len = eph_point.as_tpms()?.marshal(&mut secret_buf);
                let secret =
                    Tpm2bEncryptedSecret::new(&secret_buf[..secret_len]).ok_or(TpmRc::FAILURE)?;

                // KDFe to derive seed
                kdfe(
                    crypto,
                    name_alg,
                    ecdh_point.x(),
                    c"IDENTITY",
                    eph_point.x(),
                    parent_ecc_pub_point.x(),
                    seed,
                )
                .map_err(|_| TpmRc::FAILURE)?;
                secret
            }
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };

        // 4. Derive symmetric key and HMAC key using KDFa
        let sym_alg = match &protector_obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::ATTRIBUTES.with(Position::handle(1)))?,
            OwnedPublicParmsAndId::Ecc(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::ATTRIBUTES.with(Position::handle(1)))?,
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };
        let outer_key_len = sym_alg.alg.key_bytes();

        let mut sym_key_iv = [0u8; AlgSym::MAX_KEY_BYTES];
        let mut integrity_key = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

        let crypto = self.crypto();
        let sym_key = sym_key_iv.get_mut(..outer_key_len).ok_or(TpmRc::FAILURE)?;
        kdfa(
            crypto,
            name_alg,
            seed,
            c"STORAGE",
            cmd.object_name.as_slice(),
            &[],
            sym_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let integrity_key = integrity_key.get_mut(..digest_size).ok_or(TpmRc::FAILURE)?;
        kdfa(
            crypto,
            name_alg,
            seed,
            c"INTEGRITY",
            &[],
            &[],
            integrity_key,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        // 5. Marshal credential to encrypt (includes 2-byte size prefix)
        let mut credential_to_encrypt = [0u8; Tpm2bDigest::MAX_SIZE];
        let credential = cmd.credential.as_slice();
        if credential.len() > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        let mut writer = Writer::new(&mut credential_to_encrypt);
        writer.sized(credential)?;
        let encrypt_len = writer.offset();
        let enc_identity = &mut credential_to_encrypt[..encrypt_len];

        zero_iv_crypt(
            crypto,
            sym_alg.alg,
            sym_alg.mode,
            sym_key,
            Direction::Encrypt,
            enc_identity,
        )?;

        // 6. Compute integrity HMAC over the encrypted credential (includes encrypted size prefix)
        let (hmac_bytes, hmac_len) = self
            .compute_hmac(
                name_alg,
                integrity_key,
                &[&*enc_identity, cmd.object_name.as_slice()],
            )
            .map_err(|_| TpmRc::FAILURE)?;

        // 7. Assemble Tpm2bIdObject from TPMS_ID_OBJECT: integrityHMAC (TPM2B_DIGEST) followed by
        //    encIdentity (encrypted including its size field).
        //
        // PORTING: exp marshaled a `tpm2::TpmsIdObject`, which the new `tpm2` crate does not
        // have (`Tpm2bIdObject` is a plain sized buffer).
        let mut id_obj_buf = [0u8; Tpm2bIdObject::CAP];
        let mut writer = Writer::new(&mut id_obj_buf);
        writer.sized(hmac_bytes.get(..hmac_len).ok_or(TpmRc::FAILURE)?)?;
        writer.bytes(enc_identity)?;
        let id_obj_len = writer.offset();
        let credential_blob =
            Tpm2bIdObject::new(&id_obj_buf[..id_obj_len]).ok_or(TpmRc::FAILURE)?;

        let rsp = responses::MakeCredential {
            credential_blob,
            secret,
        };

        // 8. Write response
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
