//! ECC encryption: `TPM2_ECC_Encrypt` (`cc-ecc-encrypt`) and `TPM2_ECC_Decrypt`
//! (`cc-ecc-decrypt`), TPM 2.0 Part 1, "SM2 Encryption and Decryption" with the key derivation
//! function KDF2 (the only one the note of Part 1 allows: "Currently, only KDF2 (`TPM_ALG_KDF2`)
//! is supported").

use super::ecc_key_exchange::MAX_COORDINATE_SIZE;
use crate::handle_checks::{Tpmi, check};
use crate::owned::OwnedPublicParmsAndId;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::crypto::{Crypto, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmiAlgHash, TpmtKdfScheme};

/// Selects the KDF scheme of `TPM2_ECC_Encrypt`/`TPM2_ECC_Decrypt` from the `kdf` of the key
/// and `inScheme` (Part 3: "If the default key scheme is `TPM_ALG_NULL`, an appropriate
/// *inScheme* is required. If the default key scheme is not `TPM_ALG_NULL`, the key scheme and
/// *inScheme* must be the same"): `inScheme` `TPM_ALG_NULL` selects the key's scheme, a key
/// scheme `TPM_ALG_NULL` selects `inScheme`, and otherwise both must be the same KDF with the
/// same hash (`Err(())`, `TPM_RC_SCHEME` at `inScheme`). The result may be `TPM_ALG_NULL`
/// (`None`), which the encryption rejects as an unsupported scheme (like `tcgtpm` version 185,
/// `CryptoCommon_EccSelectScheme()`).
fn select_kdf_scheme(
    key_scheme: Option<TpmtKdfScheme>,
    in_scheme: Option<TpmtKdfScheme>,
) -> Result<Option<TpmtKdfScheme>, ()> {
    match (key_scheme, in_scheme) {
        (key, None) => Ok(key),
        (None, scheme) => Ok(scheme),
        (Some(key), Some(scheme)) if key == scheme && !matches!(scheme, TpmtKdfScheme::Hkdf(_)) => {
            Ok(Some(scheme))
        }
        _ => Err(()),
    }
}

/// The hash of a selected KDF scheme, which must be KDF2 (`TPM_RC_SCHEME`, without a position,
/// as the references' `CryptEccEncrypt()`/`CryptEccDecrypt()` return it).
fn kdf2_hash(scheme: Option<TpmtKdfScheme>) -> Result<TpmiAlgHash, TpmRc> {
    match scheme {
        Some(TpmtKdfScheme::Kdf2(hash)) => Ok(hash),
        _ => Err(TpmRc::SCHEME.to_rc()),
    }
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// KDF2 (ISO/IEC 18033-2, the references' `CryptMGF_KDF()` with the counter starting at 1):
    /// fills `mask` with `H(z || 1) || H(z || 2) || ...`.
    fn kdf2(&self, hash: TpmiAlgHash, z: &[u8], mask: &mut [u8]) -> Result<(), TpmRc> {
        let digest_size = hash.digest_size();
        for (i, chunk) in mask.chunks_mut(digest_size).enumerate() {
            let counter = (i as u32 + 1).to_be_bytes();
            let (digest, _) = self.compute_hash(hash, &[z, &counter])?;
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
        Ok(())
    }

    /// Handles the [TpmCc::ECCEncrypt] (`0x199`) command.
    ///
    /// # Description
    /// Encrypts `plainText` with the public key `P_B` of `keyHandle` (Part 1, "Encryption"):
    /// with a random `k`, `C1 := [k]G` and `(x2, y2) := [k]P_B`; `C2 := M ⊕ KDF2(x2 || y2)`;
    /// `C3 := H(x2 || M || y2)`. The TPM does not check the attributes of the key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, TPM2_ECC_Encrypt; Part 1, "SM2
    /// Encryption and Decryption".
    #[cfg(feature = "cc-ecc-encrypt")]
    pub fn ecc_encrypt(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        use super::ecc_key_exchange::{pad_point, response_point};
        use tpm2::commands::{ECCEncrypt, responses};
        use tpm2::{Tpm2bDigest, Tpm2bMaxBuffer};

        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<ECCEncrypt>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<ECCEncrypt>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        let (curve, key_kdf, public_point) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(parms, point) => (parms.curve_id, parms.kdf, point),
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };
        let scheme = select_kdf_scheme(key_kdf, cmd.in_scheme)
            .map_err(|()| TpmRc::SCHEME.with(Position::parameter(2)))?;
        let hash = kdf2_hash(scheme)?;
        let size = crate::ecc_curves::curve_params(curve)
            .ok_or(TpmRc::CURVE.with(Position::handle(1)))?
            .p
            .len();

        // 1-2. A random k (1 <= k <= n - 1) and C1 := (x1, y1) := [k]G.
        let mut k = [0u8; MAX_COORDINATE_SIZE];
        let mut c1 = [0u8; 2 * MAX_COORDINATE_SIZE];
        // `TpmEcc_GenerateKeyPair()`: with `reference-rng`, from the TPM's DRBG as in the
        // reference.
        #[cfg(feature = "reference-rng")]
        let k_len = self.reference_ecc_new_key_pair(curve, &mut k, &mut c1)?;
        #[cfg(not(feature = "reference-rng"))]
        let k_len = {
            self.do_self_test(tpm2::Alg::ECDH)?;
            super::ecdh::generate_ecc_key_pair::<C>(
                &mut self.context.crypto_rng,
                curve,
                &mut k,
                &mut c1,
            )
            .map_err(|_| TpmRc::NO_RESULT)?
            .1
        };

        // 3. P2 := (x2, y2) := [k]P_B.
        let mut pb = [0u8; 2 * MAX_COORDINATE_SIZE];
        if !pad_point(&public_point.as_tpms(), size, &mut pb) {
            return Err(TpmRc::NO_RESULT);
        }
        let mut p2 = [0u8; 2 * MAX_COORDINATE_SIZE];
        if !matches!(
            self.crypto()
                .point_multiply(curve, &k[..k_len], &pb[..2 * size], &mut p2[..2 * size]),
            Ok(Some(_))
        ) {
            return Err(TpmRc::NO_RESULT);
        }
        let (x2, y2) = p2[..2 * size].split_at(size);

        // C3 := H(x2 || M || y2).
        let plain_text = cmd.plain_text.get_buffer();
        let (c3, c3_len) = self.compute_hash(hash, &[x2, plain_text, y2])?;

        // C2 := M ⊕ KDF2(x2 || y2).
        let mut c2 = [0u8; Tpm2bMaxBuffer::CAP];
        let c2 = &mut c2[..plain_text.len()];
        self.kdf2(hash, &p2[..2 * size], c2)?;
        for (c, m) in c2.iter_mut().zip(plain_text) {
            *c ^= m;
        }

        let rsp = responses::ECCEncrypt {
            c1: response_point(Some(&c1), size)?,
            c2: Tpm2bMaxBuffer::from_bytes(c2).map_err(|_| TpmRc::FAILURE)?,
            c3: Tpm2bDigest::from_bytes(&c3[..c3_len]).map_err(|_| TpmRc::FAILURE)?,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::ECCDecrypt] (`0x19A`) command.
    ///
    /// # Description
    /// Decrypts `C1`, `C2`, `C3` with the private key `d_B` of `keyHandle`, an unrestricted ECC
    /// decryption key (Part 1, "Decryption"): `(x2, y2) := [d_B]C1`;
    /// `M := C2 ⊕ KDF2(x2 || y2)`; `H(x2 || M || y2)` must equal `C3` (`TPM_RC_VALUE`).
    ///
    /// `C1` must be a point on the curve of the key (`TPM_RC_ECC_POINT`), as the decryption of
    /// GB/T 32918.4-2016 (B1) requires.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, TPM2_ECC_Decrypt; Part 1, "SM2
    /// Encryption and Decryption".
    #[cfg(feature = "cc-ecc-decrypt")]
    pub fn ecc_decrypt(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        use super::ecc_key_exchange::{pad_point, pad_scalar};
        use tpm2::Tpm2bMaxBuffer;
        use tpm2::TpmaObject;
        use tpm2::commands::{ECCDecrypt, responses};

        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<ECCDecrypt>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<ECCDecrypt>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        // An ECC key (`TPM_RC_KEY`) with `restricted` CLEAR and `decrypt` SET
        // (`TPM_RC_ATTRIBUTES`).
        let (curve, key_kdf) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(parms, _) => (parms.curve_id, parms.kdf),
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };
        let attributes = obj.public.object_attributes;
        if attributes.contains(TpmaObject::RESTRICTED) || !attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        let scheme = select_kdf_scheme(key_kdf, cmd.in_scheme)
            .map_err(|()| TpmRc::SCHEME.with(Position::parameter(4)))?;
        // Defense in depth: a public-only key cannot be authorized (its USER role needs the
        // authValue or authPolicy), so it never gets here.
        if obj.private_len == 0 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        let params =
            crate::ecc_curves::curve_params(curve).ok_or(TpmRc::CURVE.with(Position::handle(1)))?;
        let size = params.p.len();

        // 1. P1 := (x1, y1) from C1, which must be on the curve.
        let mut c1 = [0u8; 2 * MAX_COORDINATE_SIZE];
        let on_curve = cmd
            .c1
            .to_struct()
            .is_ok_and(|p| pad_point(&p, size, &mut c1))
            && matches!(
                crate::ecc_curves::validate_point::<C>(curve, &c1[..2 * size]),
                Ok(true)
            );
        if !on_curve {
            return Err(TpmRc::ECC_POINT.with(Position::parameter(1)));
        }
        let hash = kdf2_hash(scheme)?;

        // 2. P2 := (x2, y2) := [d_B]P1.
        let mut d = [0u8; MAX_COORDINATE_SIZE];
        let n_len = params.n.len();
        if !pad_scalar(&obj.private[..obj.private_len], &mut d[..n_len]) {
            return Err(TpmRc::FAILURE);
        }
        let mut p2 = [0u8; 2 * MAX_COORDINATE_SIZE];
        match self
            .crypto()
            .point_multiply(curve, &d[..n_len], &c1[..2 * size], &mut p2[..2 * size])
        {
            Ok(Some(_)) => {}
            Ok(None) => return Err(TpmRc::NO_RESULT),
            Err(_) => return Err(TpmRc::FAILURE),
        }
        let (x2, y2) = p2[..2 * size].split_at(size);

        // 3-4. M := C2 ⊕ KDF2(x2 || y2).
        let c2 = cmd.c2.get_buffer();
        let mut plain_text = [0u8; Tpm2bMaxBuffer::CAP];
        let plain_text = &mut plain_text[..c2.len()];
        self.kdf2(hash, &p2[..2 * size], plain_text)?;
        for (m, c) in plain_text.iter_mut().zip(c2) {
            *m ^= c;
        }

        // 5-6. H(x2 || M || y2) must be C3.
        let (check_value, check_len) = self.compute_hash(hash, &[x2, plain_text, y2])?;
        // (`C3` is public: it is an input of the command.)
        if check_value[..check_len] != *cmd.c3.get_buffer() {
            return Err(TpmRc::VALUE.to_rc());
        }

        let rsp = responses::ECCDecrypt {
            plain_text: Tpm2bMaxBuffer::from_bytes(plain_text).map_err(|_| TpmRc::FAILURE)?,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
