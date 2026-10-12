use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::owned::OwnedPublicParmsAndId;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::commands::{ActivateCredential, responses};
use tpm2::crypto::{Direction, Rsa, RsaEncryptScheme, kdfa, kdfe};
use tpm2::errors::{Position, TpmRc};
use tpm2::{AlgSym, Tpm2bDigest, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsEccPoint};

use super::crypt_ops::{
    PaddedEccPoint, ecc_param_size, ecc_point_multiply, load_ecc_private, load_ecc_public,
    load_rsa_private,
};
use super::duplicate::{Writer, zero_iv_crypt};
use super::make_credential::IDENTITY_LABEL;

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::ActivateCredential] (`0x147`) command.
    ///
    /// # Description
    /// This command enables the association of a credential with an object in a way that ensures
    /// that the TPM has validated the parameters of the credentialed object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.5 (TPM2_ActivateCredential).
    ///
    /// # Relationships
    /// - Use [TpmCc::MakeCredential](make_credential.rs)
    ///   (usually executed off-TPM) to create the credential blob and encrypted secret.
    /// - The `activate_handle` must reference a loaded object created by [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs)
    ///   and loaded via [TpmCc::Load](load.rs).
    pub fn activate_credential(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<ActivateCredential>()?;
        let [activate_handle, key_handle] = handles;
        check(activate_handle, Tpmi::DhObject, Position::handle(1))?;
        check(key_handle, Tpmi::DhObject, Position::handle(2))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<ActivateCredential>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Retrieve target (activated) object
        let activate_obj = self.resolve_object(activate_handle.0, Position::handle(1))?;

        // 2. Retrieve decryption (protector) object
        let key_obj = self.resolve_object(key_handle.0, Position::handle(2))?;

        // 3. Decryption key must be a restricted decryption key
        if !key_obj
            .public
            .object_attributes
            .contains(TpmaObject::DECRYPT)
            || !key_obj
                .public
                .object_attributes
                .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        let name_alg = key_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        let digest_size = name_alg.digest_size();

        // 4. Decrypt secret to recover seed
        //
        // PORTING: exp passed its opaque private-key blob to its crypto provider; the private key
        // is now loaded from the object's public and sensitive areas first, and a key that fails
        // to load is reported like the failing operation (`TPM_RC_FAILURE`).
        let mut seed = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let crypto = self.crypto();

        let seed_len = match &key_obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, modulus) => {
                let key = load_rsa_private(crypto, parms, modulus.get_buffer(), &key_obj.sensitive)
                    .ok_or(TpmRc::FAILURE)?;
                let mut decrypted = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                let plaintext = Rsa::decrypt(
                    crypto,
                    &key,
                    RsaEncryptScheme::Oaep {
                        hash: name_alg,
                        label: IDENTITY_LABEL,
                    },
                    cmd.secret.as_slice(),
                    &mut decrypted,
                )
                .ok()
                .flatten()
                .ok_or(TpmRc::FAILURE)?;
                let mut writer = Writer::new(&mut seed);
                writer.bytes(plaintext.as_slice())?;
                let decrypted_len = writer.offset();
                if decrypted_len > digest_size {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                decrypted_len
            }
            OwnedPublicParmsAndId::Ecc(parms, point) => {
                let curve = parms.curve_id;
                let param_size = ecc_param_size(curve).ok_or(TpmRc::VALUE.to_rc())?;
                if point.x.get_buffer().len() != param_size
                    || point.y.get_buffer().len() != param_size
                {
                    return Err(TpmRc::VALUE.with(Position::handle(2)));
                }

                // Unmarshal ephemeral public key point from cmd.secret
                let mut slice = cmd.secret.as_slice();
                let eph_point =
                    TpmsEccPoint::unmarshal(&mut slice).map_err(|_| TpmRc::VALUE.to_rc())?;

                if eph_point.x.as_slice().len() != param_size
                    || eph_point.y.as_slice().len() != param_size
                {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                let eph_pub =
                    PaddedEccPoint::from_tpms(&eph_point, param_size).ok_or(TpmRc::FAILURE)?;

                // Perform ECDH point multiplication with key_obj private key
                let key = load_ecc_private(crypto, curve, point, &key_obj.sensitive)
                    .ok_or(TpmRc::FAILURE)?;
                let peer = load_ecc_public(crypto, curve, &eph_pub).ok_or(TpmRc::FAILURE)?;
                let ecdh_point = ecc_point_multiply(crypto, &key, &peer, param_size)
                    .ok()
                    .flatten()
                    .ok_or(TpmRc::FAILURE)?;

                // KDFe to derive seed
                kdfe(
                    crypto,
                    name_alg,
                    ecdh_point.x(),
                    c"IDENTITY",
                    eph_pub.x(),
                    point.x.get_buffer(),
                    seed.get_mut(..digest_size).ok_or(TpmRc::FAILURE)?,
                )
                .map_err(|_| TpmRc::FAILURE)?;
                digest_size
            }
            _ => return Err(TpmRc::TYPE.with(Position::handle(2))),
        };
        let seed = &seed[..seed_len];

        // 5. Derive symmetric key and HMAC key using KDFa
        let sym_alg = match &key_obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::ATTRIBUTES.with(Position::handle(2)))?,
            OwnedPublicParmsAndId::Ecc(parms, _) => parms
                .symmetric
                .ok_or(TpmRc::ATTRIBUTES.with(Position::handle(2)))?,
            _ => return Err(TpmRc::TYPE.with(Position::handle(2))),
        };
        let outer_key_len = sym_alg.alg.key_bytes();

        let mut sym_key_iv = [0u8; AlgSym::MAX_KEY_BYTES];
        let mut integrity_key = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];

        let sym_key = sym_key_iv.get_mut(..outer_key_len).ok_or(TpmRc::FAILURE)?;
        kdfa(
            crypto,
            name_alg,
            seed,
            c"STORAGE",
            activate_obj.name.get_buffer(),
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

        // 6. Unmarshal integrity_hmac and get the remaining encrypted slice
        let mut slice = cmd.credential_blob.as_slice();
        let integrity_hmac = Tpm2bDigest::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let encrypted_enc_identity = slice;

        // 7. Verify integrity HMAC
        let (hmac_bytes, hmac_len) = self
            .compute_hmac(
                name_alg,
                integrity_key,
                &[encrypted_enc_identity, activate_obj.name.get_buffer()],
            )
            .map_err(|_| TpmRc::FAILURE)?;
        let expected_hmac = hmac_bytes.get(..hmac_len).ok_or(TpmRc::FAILURE)?;

        if !crate::util::constant_time_eq(integrity_hmac.as_slice(), expected_hmac) {
            return Err(TpmRc::INTEGRITY.to_rc());
        }

        // 8. Decrypt credential
        //
        // The buffer size (68 bytes) is exp's: larger encIdentity values fail with TPM_RC_SIZE.
        let mut decrypted_enc_identity = [0u8; 68];
        let encrypt_len = encrypted_enc_identity.len();
        if encrypt_len > decrypted_enc_identity.len() {
            return Err(TpmRc::SIZE.to_rc());
        }
        let enc_identity = &mut decrypted_enc_identity[..encrypt_len];
        enc_identity.copy_from_slice(encrypted_enc_identity);

        zero_iv_crypt(
            crypto,
            sym_alg.alg,
            sym_alg.mode,
            sym_key,
            Direction::Decrypt,
            enc_identity,
        )?;

        let mut slice = &*enc_identity;
        let cert_info = Tpm2bDigest::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let rsp = responses::ActivateCredential { cert_info };

        // 9. Write response
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
