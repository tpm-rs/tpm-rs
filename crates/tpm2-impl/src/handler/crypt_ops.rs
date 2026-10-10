use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::owned::{OwnedEccPoint, OwnedPublicParmsAndId, OwnedSensitiveComposite};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmEccCurve;
#[allow(deprecated)]
use tpm2::commands::{ECDHZGen, HMAC, RSADecrypt, RSAEncrypt, Sign, VerifySignature, responses};
use tpm2::crypto::{
    CryptoError, Ecc, EccPrivateKey, EccPublicKey, Rsa, RsaEncryptScheme, SignatureBuffer,
    SigningKey, VerifyingKey,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Tpm2b, Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmHt, TpmaObject, TpmiAlgHash,
    TpmiRsaKeyBits, TpmsEccPoint, TpmsRsaParms, TpmsSignatureEcc, TpmsSignatureRsa, TpmtEccScheme,
    TpmtHa, TpmtKeyedHashScheme, TpmtRsaDecrypt, TpmtRsaScheme, TpmtSigScheme, TpmtSignature,
    TpmtTkVerified,
};
use tpm2::{Ticket, crypto};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

/// Returns the coordinate / scalar size (in bytes) of the ECC curves supported by the crypto
/// handlers (`TPM_ECC_NIST_P224`, `TPM_ECC_NIST_P256`, `TPM_ECC_BN_P256`, `TPM_ECC_NIST_P384`
/// and `TPM_ECC_NIST_P521`), or `None` for any other curve.
///
/// PORTING: replaces exp's inline `match curve { NistP224 => 28, NistP256 | BNP256 => 32, .. }`
/// tables.
pub(super) const fn ecc_param_size(curve: TpmEccCurve) -> Option<usize> {
    match curve {
        TpmEccCurve::NistP224
        | TpmEccCurve::NistP256
        | TpmEccCurve::BNP256
        | TpmEccCurve::NistP384
        | TpmEccCurve::NistP521 => Some(curve.key_bytes()),
        _ => None,
    }
}

/// Copies `src` right-aligned into `dst[..size]` (i.e. left-pads it with zeros to `size` bytes).
///
/// Returns `None` if `src` is longer than `size` or `size` exceeds `dst.len()`.
pub(super) fn left_pad(dst: &mut [u8], src: &[u8], size: usize) -> Option<()> {
    let dst = dst.get_mut(..size)?;
    let offset = size.checked_sub(src.len())?;
    dst.get_mut(offset..)?.copy_from_slice(src);
    Some(())
}

/// An affine ECC point whose coordinates are left-padded with zeros to a fixed size.
///
/// PORTING: replaces exp's raw `x || y` scratch buffers (`[u8; 256]`) that were passed to the old
/// `validate_point` / `point_multiply` crypto APIs.
pub(super) struct PaddedEccPoint {
    x: [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    y: [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    size: usize,
}

impl PaddedEccPoint {
    /// Left-pads `x` and `y` to `size` bytes each.
    ///
    /// Returns `None` if either coordinate is longer than `size`, or if `size` exceeds
    /// [`TpmEccCurve::MAX_ECC_KEY_BYTES`].
    pub(super) fn new(x: &[u8], y: &[u8], size: usize) -> Option<Self> {
        let mut point = Self {
            x: [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
            y: [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
            size,
        };
        left_pad(&mut point.x, x, size)?;
        left_pad(&mut point.y, y, size)?;
        Some(point)
    }

    /// Left-pads the coordinates of `point` to `size` bytes each (see [`Self::new`]).
    pub(super) fn from_tpms(point: &TpmsEccPoint<'_>, size: usize) -> Option<Self> {
        Self::new(point.x.as_slice(), point.y.as_slice(), size)
    }

    /// The padded `x` coordinate.
    pub(super) fn x(&self) -> &[u8] {
        self.x.get(..self.size).unwrap_or_default()
    }

    /// The padded `y` coordinate.
    pub(super) fn y(&self) -> &[u8] {
        self.y.get(..self.size).unwrap_or_default()
    }

    /// Borrows the point as a [`TpmsEccPoint`].
    pub(super) fn as_tpms(&self) -> Result<TpmsEccPoint<'_>, TpmRc> {
        Ok(TpmsEccPoint {
            x: Tpm2bEccParameter::new(self.x()).ok_or(TpmRc::FAILURE)?,
            y: Tpm2bEccParameter::new(self.y()).ok_or(TpmRc::FAILURE)?,
        })
    }
}

/// Loads the RSA public key described by `parms` and `modulus`.
///
/// The modulus is left-padded with zeros to `keyBits / 8` bytes (as exp did when reconstructing
/// RSA public keys). Returns `None` if the modulus is too long or the backend rejects the key.
pub(super) fn load_rsa_public<C: Crypto>(
    crypto: &C,
    parms: &TpmsRsaParms,
    modulus: &[u8],
) -> Option<<C as Rsa>::PublicKey> {
    let key_size = usize::from(parms.key_bits.as_u16() / 8);
    let mut buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    left_pad(&mut buf, modulus, key_size)?;
    let modulus = Tpm2bPublicKeyRsa::new(buf.get(..key_size)?)?;
    Rsa::load_public(crypto, parms.key_bits, parms.exponent, modulus).ok()?
}

/// Loads the RSA private key of a loaded object from its public `parms` / `modulus` and the
/// first prime factor `p` held in its `sensitive` area.
///
/// Returns `None` if `sensitive` is not an RSA private key or the backend rejects the key.
///
/// PORTING: exp passed its opaque `TransientObject::private` blob to the crypto provider.
pub(super) fn load_rsa_private<C: Crypto>(
    crypto: &C,
    parms: &TpmsRsaParms,
    modulus: &[u8],
    sensitive: &OwnedSensitiveComposite,
) -> Option<<C as Rsa>::PrivateKey> {
    let OwnedSensitiveComposite::Rsa(prime_p) = sensitive else {
        return None;
    };
    let public = load_rsa_public(crypto, parms, modulus)?;
    Rsa::load_private(crypto, public, prime_p.as_tpm2b()).ok()?
}

/// Loads (and thereby validates) the ECC public key `point` on `curve`.
///
/// Returns `None` if `point` is not a valid point on `curve` (exp's `validate_point` failing).
pub(super) fn load_ecc_public<C: Crypto>(
    crypto: &C,
    curve: TpmEccCurve,
    point: &PaddedEccPoint,
) -> Option<<C as Ecc>::PublicKey> {
    Ecc::load_public(crypto, curve, point.as_tpms().ok()?).ok()?
}

/// Loads the ECC private key of a loaded object from its public `point` on `curve` and the
/// secret scalar `d` held in its `sensitive` area.
///
/// Returns `None` if `curve` is unsupported (see [`ecc_param_size`]), `sensitive` is not an ECC
/// private key, or the backend rejects the key.
///
/// PORTING: exp passed its opaque `TransientObject::private` blob to the crypto provider.
pub(super) fn load_ecc_private<C: Crypto>(
    crypto: &C,
    curve: TpmEccCurve,
    point: &OwnedEccPoint,
    sensitive: &OwnedSensitiveComposite,
) -> Option<<C as Ecc>::PrivateKey> {
    let OwnedSensitiveComposite::Ecc(scalar) = sensitive else {
        return None;
    };
    let size = ecc_param_size(curve)?;
    let point = PaddedEccPoint::new(point.x.get_buffer(), point.y.get_buffer(), size)?;
    let public = load_ecc_public(crypto, curve, &point)?;
    Ecc::load_private(crypto, public, scalar.as_tpm2b()).ok()?
}

/// Computes `[d]Q` (`d` = `private`, `Q` = `peer`) with the backend's ECDH primitive, with the
/// coordinates of the result left-padded to `size` bytes.
///
/// Returns `Ok(None)` if the result is the point at infinity.
///
/// PORTING: replaces exp's `point_multiply(curve, scalar, point, out)`.
pub(super) fn ecc_point_multiply<C: Crypto>(
    crypto: &C,
    private: &<C as Ecc>::PrivateKey,
    peer: &<C as Ecc>::PublicKey,
    size: usize,
) -> Result<Option<PaddedEccPoint>, CryptoError> {
    let mut x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let Some(point) = Ecc::ecdh(crypto, private, peer, &mut x, &mut y)? else {
        return Ok(None);
    };
    PaddedEccPoint::from_tpms(&point, size)
        .map(Some)
        .ok_or(CryptoError::Internal)
}

/// Returns the public point `[d]G` of `private`, with its coordinates left-padded to `size` bytes.
///
/// PORTING: replaces exp's `point_multiply_generator(curve, scalar, out)`.
pub(super) fn ecc_public_point<C: Crypto>(
    private: &<C as Ecc>::PrivateKey,
    size: usize,
) -> Option<PaddedEccPoint> {
    let mut x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let point = private.public_key().point(&mut x, &mut y).ok()?;
    PaddedEccPoint::from_tpms(&point, size)
}

/// Returns the hash algorithm of a signature scheme, or `None` for schemes without one.
///
/// PORTING: replaces exp's `TpmtSigScheme::hash_alg()`.
fn sig_scheme_hash_alg(scheme: &TpmtSigScheme) -> Option<TpmiAlgHash> {
    match *scheme {
        TpmtSigScheme::Hmac(h)
        | TpmtSigScheme::Rsassa(h)
        | TpmtSigScheme::Rsapss(h)
        | TpmtSigScheme::Ecdsa(h)
        | TpmtSigScheme::Sm2(h)
        | TpmtSigScheme::Ecschnorr(h) => Some(h),
        TpmtSigScheme::Ecdaa(s) => Some(s.hash_alg),
        TpmtSigScheme::Eddsa
        | TpmtSigScheme::HashEddsa
        | TpmtSigScheme::Mldsa
        | TpmtSigScheme::HashMldsa => None,
    }
}

/// Returns `true` for the hash algorithms the signing commands accept
/// (SHA-1, SHA-256, SHA-384, SHA-512 and SM3-256).
fn is_signing_hash(hash_alg: TpmiAlgHash) -> bool {
    matches!(
        hash_alg,
        TpmiAlgHash::Sha1
            | TpmiAlgHash::Sha256
            | TpmiAlgHash::Sha384
            | TpmiAlgHash::Sha512
            | TpmiAlgHash::Sm3_256
    )
}

/// Left-pads both components of an ECC signature to `size` bytes.
///
/// PORTING: exp's crypto provider always produced fixed-size `r` / `s` values.
fn pad_ecc_signature<'s>(
    sig: &TpmsSignatureEcc<'_>,
    size: usize,
    r_buf: &'s mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    s_buf: &'s mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Option<TpmsSignatureEcc<'s>> {
    left_pad(r_buf, sig.signature_r.as_slice(), size)?;
    left_pad(s_buf, sig.signature_s.as_slice(), size)?;
    Some(TpmsSignatureEcc {
        hash: sig.hash,
        signature_r: Tpm2bEccParameter::new(r_buf.get(..size)?)?,
        signature_s: Tpm2bEccParameter::new(s_buf.get(..size)?)?,
    })
}

/// Builds the [`RsaEncryptScheme`] for a scheme resolved by
/// [`CommandHandler::resolve_rsa_scheme`] (`None` is raw RSA, `TPM_ALG_NULL`).
fn rsa_encrypt_scheme(scheme: Option<TpmtRsaDecrypt>, label: &[u8]) -> RsaEncryptScheme<'_> {
    match scheme {
        None => RsaEncryptScheme::Raw,
        Some(TpmtRsaDecrypt::Rsaes) => RsaEncryptScheme::Rsaes,
        Some(TpmtRsaDecrypt::Oaep(hash)) => RsaEncryptScheme::Oaep { hash, label },
    }
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::VerifySignature] (`0x177`) command.
    ///
    /// # Description
    /// This command uses a loaded public key to verify a signature on a message digest.
    /// If the verification succeeds, the TPM can generate a verification ticket (`TpmtTkVerified`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 20.2 (TPM2_VerifySignature).
    ///
    /// # Relationships
    /// - The ticket produced by this command can be consumed by [TpmCc::PolicySigned](policy_signed.rs)
    ///   or [TpmCc::PolicyTicket] to validate authorizations.
    /// - The key used for verification must be loaded in the TPM (created by [TpmCc::Create] or [TpmCc::CreatePrimary] and loaded).
    #[allow(deprecated)]
    pub fn verify_signature(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<VerifySignature>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<VerifySignature>(handles)?;

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        if !obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if !matches!(
            obj.public.parms_and_id,
            OwnedPublicParmsAndId::Rsa(..)
                | OwnedPublicParmsAndId::Ecc(..)
                | OwnedPublicParmsAndId::KeyedHash(..)
        ) {
            return Err(TpmRc::TYPE.to_rc());
        }

        if matches!(
            obj.public.parms_and_id,
            OwnedPublicParmsAndId::KeyedHash(..)
        ) && obj.sensitive.as_bytes().is_empty()
        {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // Validate scheme and digest consistency against key parameters
        match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, _) => match &parms.scheme {
                Some(TpmtRsaScheme::Rsassa(expected_hash)) => {
                    let sig_rsa = match &cmd.signature {
                        TpmtSignature::Rsassa(sig) => sig,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if sig_rsa.hash != *expected_hash {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                Some(TpmtRsaScheme::Rsapss(expected_hash)) => {
                    let sig_rsa = match &cmd.signature {
                        TpmtSignature::Rsapss(sig) => sig,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if sig_rsa.hash != *expected_hash {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                None => match &cmd.signature {
                    TpmtSignature::Rsassa(_) | TpmtSignature::Rsapss(_) => {}
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                _ => {
                    return Err(TpmRc::KEY.with(Position::handle(1)));
                }
            },
            OwnedPublicParmsAndId::Ecc(parms, _) => match &parms.scheme {
                Some(TpmtEccScheme::Ecdsa(expected_hash)) => {
                    let sig_ecc = match &cmd.signature {
                        TpmtSignature::Ecdsa(sig) => sig,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if sig_ecc.hash != *expected_hash {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                Some(TpmtEccScheme::Ecdaa(s)) => {
                    let sig_ecc = match &cmd.signature {
                        TpmtSignature::Ecdaa(sig) => sig,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if sig_ecc.hash != s.hash_alg {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                None => match &cmd.signature {
                    TpmtSignature::Ecdsa(_)
                    | TpmtSignature::Ecdaa(_)
                    | TpmtSignature::Ecschnorr(_) => {}
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                _ => {
                    return Err(TpmRc::KEY.with(Position::handle(1)));
                }
            },
            OwnedPublicParmsAndId::KeyedHash(scheme, _) => {
                let ha = match scheme {
                    Some(TpmtKeyedHashScheme::Hmac(expected_hash)) => {
                        let ha = match &cmd.signature {
                            TpmtSignature::Hmac(h) => h,
                            _ => return Err(TpmRc::SIGNATURE.to_rc()),
                        };
                        if ha.hash_alg() != *expected_hash {
                            return Err(TpmRc::SIGNATURE.to_rc());
                        }
                        ha
                    }
                    None => match &cmd.signature {
                        TpmtSignature::Hmac(ha) => ha,
                        _ => return Err(TpmRc::SCHEME.to_rc()),
                    },
                    _ => {
                        return Err(TpmRc::KEY.with(Position::handle(1)));
                    }
                };
                let (hmac_bytes, hmac_len) = self.compute_hmac(
                    ha.hash_alg(),
                    obj.sensitive.as_bytes(),
                    &[cmd.digest.as_slice()],
                )?;
                if !hmac_bytes
                    .get(..hmac_len)
                    .is_some_and(|hmac| crate::util::constant_time_eq(ha.digest(), hmac))
                {
                    return Err(TpmRc::SIGNATURE.to_rc());
                }
                let hierarchy = if obj.hierarchy == Handle::RH_NULL.0 {
                    Handle::RH_NULL
                } else {
                    Handle(obj.hierarchy)
                };
                let rsp = responses::VerifySignature {
                    validation: TpmtTkVerified::Verified(hierarchy, cmd.digest),
                };
                let response = request.into_response();
                self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
                return Ok(());
            }
            _ => return Err(TpmRc::TYPE.to_rc()),
        }

        // Check the public key and extract the signature, left-padding both to the key size.
        //
        // PORTING: exp reconstructed raw public key bytes for `verify_inner`; the key is now
        // loaded into the backend (see below) after these (unchanged) size checks.
        let mut sig_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut r_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut s_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let crypto = self.crypto();
        let digest = cmd.digest.as_slice();
        let verified = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, unique) => {
                let key_size = usize::from(parms.key_bits.as_u16() / 8);
                if unique.get_buffer().len() > key_size {
                    return Err(TpmRc::KEY.to_rc());
                }
                let signature = match &cmd.signature {
                    TpmtSignature::Rsassa(sig_rsa) | TpmtSignature::Rsapss(sig_rsa) => {
                        left_pad(&mut sig_buf, sig_rsa.sig.as_slice(), key_size)
                            .ok_or(TpmRc::SIGNATURE.with(Position::handle(2)))?;
                        let padded = TpmsSignatureRsa {
                            hash: sig_rsa.hash,
                            sig: sig_buf
                                .get(..key_size)
                                .and_then(Tpm2bPublicKeyRsa::new)
                                .ok_or(TpmRc::FAILURE)?,
                        };
                        if matches!(cmd.signature, TpmtSignature::Rsassa(_)) {
                            TpmtSignature::Rsassa(padded)
                        } else {
                            TpmtSignature::Rsapss(padded)
                        }
                    }
                    _ => {
                        return Err(TpmRc::SCHEME.with(Position::handle(2)));
                    }
                };
                load_rsa_public(crypto, parms, unique.get_buffer())
                    .map(|key| crypto::verify(crypto, VerifyingKey::Rsa(&key), digest, signature))
            }
            OwnedPublicParmsAndId::Ecc(parms, point) => {
                let curve = parms.curve_id;
                let param_size = ecc_param_size(curve).ok_or(TpmRc::KEY.to_rc())?;
                let public =
                    PaddedEccPoint::new(point.x.get_buffer(), point.y.get_buffer(), param_size)
                        .ok_or(TpmRc::KEY.to_rc())?;
                let signature = match &cmd.signature {
                    // PORTING: as in exp, ECDAA signatures are verified with the ECDSA algorithm.
                    TpmtSignature::Ecdsa(sig_ecc) | TpmtSignature::Ecdaa(sig_ecc) => {
                        TpmtSignature::Ecdsa(
                            pad_ecc_signature(sig_ecc, param_size, &mut r_buf, &mut s_buf)
                                .ok_or(TpmRc::SIGNATURE.with(Position::handle(2)))?,
                        )
                    }
                    _ => {
                        return Err(TpmRc::SCHEME.with(Position::handle(2)));
                    }
                };
                load_ecc_public(crypto, curve, &public)
                    .map(|key| crypto::verify(crypto, VerifyingKey::Ecc(&key), digest, signature))
            }
            _ => return Err(TpmRc::TYPE.to_rc()),
        };

        // PORTING: exp's `TpmtHa::from_alg` digest-size check is done by `crypto::verify`
        // (`Ok(false)`); an unloadable key fails like exp's `verify_inner`.
        if verified != Some(Ok(true)) {
            return Err(TpmRc::SIGNATURE.with(Position::handle(2)));
        }

        // If key is in TPM_RH_NULL or nameAlg is TPM_ALG_NULL, return NULL ticket
        let ticket_hmac;
        let (hierarchy, digest) = match Handle(obj.hierarchy) {
            Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT
                if obj.public.name_alg.is_some() =>
            {
                ticket_hmac = self.compute_verified_ticket(
                    obj.hierarchy,
                    cmd.digest.as_slice(),
                    obj.name.get_buffer(),
                )?;
                (
                    Handle(obj.hierarchy),
                    Tpm2bDigest::new(&ticket_hmac).ok_or(TpmRc::FAILURE)?,
                )
            }
            _ => (Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let rsp = responses::VerifySignature {
            validation: TpmtTkVerified::Verified(hierarchy, digest),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::Sign] (`0x15D`) command.
    ///
    /// # Description
    /// This command signs an externally provided message digest using a loaded private key and returns the signature.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 20.1 (TPM2_Sign).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be a loaded signing key with the `sign` attribute set.
    /// - For ECDAA schemes, the signing process requires a commit counter generated by [TpmCc::Commit](commit.rs).
    #[allow(deprecated)]
    pub fn sign(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<Sign>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<Sign>(handles)?;
        check(
            cmd.validation.hierarchy(),
            Tpmi::RhHierarchy,
            Position::parameter(3),
        )?;

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        if !obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::KEY.to_rc());
        }

        if obj.public.object_attributes.contains(TpmaObject::X509_SIGN) {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        let (object_has_default, object_scheme_id, object_hash_alg) = match &obj.public.parms_and_id
        {
            OwnedPublicParmsAndId::Rsa(parms, _) => match &parms.scheme {
                Some(TpmtRsaScheme::Rsassa(h)) => (true, Alg::RSASSA, Some(*h)),
                Some(TpmtRsaScheme::Rsapss(h)) => (true, Alg::RSAPSS, Some(*h)),
                None => (false, Alg::NULL, None),
                _ => (true, Alg::NULL, None),
            },
            OwnedPublicParmsAndId::Ecc(parms, _) => match &parms.scheme {
                Some(TpmtEccScheme::Ecdsa(h)) => (true, Alg::ECDSA, Some(*h)),
                Some(TpmtEccScheme::Ecdaa(s)) => (true, Alg::ECDAA, Some(s.hash_alg)),
                Some(TpmtEccScheme::Ecschnorr(h)) => (true, Alg::ECSCHNORR, Some(*h)),
                Some(TpmtEccScheme::Sm2(h)) => (true, Alg::SM2, Some(*h)),
                None => (false, Alg::NULL, None),
                _ => (true, Alg::NULL, None),
            },
            OwnedPublicParmsAndId::KeyedHash(scheme, _) => match scheme {
                Some(TpmtKeyedHashScheme::Hmac(h)) => (true, Alg::HMAC, Some(*h)),
                None => (false, Alg::NULL, None),
                _ => (true, Alg::NULL, None),
            },
            _ => (true, Alg::NULL, None),
        };

        if let Some(in_scheme) = &cmd.in_scheme {
            if let Some(h) = sig_scheme_hash_alg(in_scheme)
                && !is_signing_hash(h)
            {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }
        } else if !object_has_default {
            return Err(TpmRc::SCHEME.with(Position::parameter(2)));
        }

        let selected_scheme = if object_has_default {
            match cmd.in_scheme {
                None => match &obj.public.parms_and_id {
                    OwnedPublicParmsAndId::Rsa(parms, _) => match parms.scheme {
                        Some(TpmtRsaScheme::Rsassa(h)) => TpmtSigScheme::Rsassa(h),
                        Some(TpmtRsaScheme::Rsapss(h)) => TpmtSigScheme::Rsapss(h),
                        _ => return Err(TpmRc::SCHEME.to_rc()),
                    },
                    OwnedPublicParmsAndId::Ecc(parms, _) => match parms.scheme {
                        Some(TpmtEccScheme::Ecdsa(h)) => TpmtSigScheme::Ecdsa(h),
                        Some(TpmtEccScheme::Ecdaa(s)) => TpmtSigScheme::Ecdaa(s),
                        _ => return Err(TpmRc::SCHEME.to_rc()),
                    },
                    OwnedPublicParmsAndId::KeyedHash(Some(TpmtKeyedHashScheme::Hmac(h)), _) => {
                        TpmtSigScheme::Hmac(*h)
                    }
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                Some(in_scheme) => {
                    let in_scheme_id = in_scheme.scheme();
                    if in_scheme_id != object_scheme_id {
                        return Err(TpmRc::SCHEME.to_rc());
                    }
                    let in_hash_alg = sig_scheme_hash_alg(&in_scheme);
                    if object_hash_alg.is_some() && object_hash_alg != in_hash_alg {
                        return Err(TpmRc::SCHEME.to_rc());
                    }
                    in_scheme
                }
            }
        } else {
            cmd.in_scheme.ok_or(TpmRc::SCHEME.to_rc())?
        };

        // Validate selected scheme against key type
        match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(..) => match &selected_scheme {
                TpmtSigScheme::Rsassa(_) | TpmtSigScheme::Rsapss(_) => {}
                _ => return Err(TpmRc::SCHEME.to_rc()),
            },
            OwnedPublicParmsAndId::Ecc(..) => match &selected_scheme {
                TpmtSigScheme::Ecdsa(_)
                | TpmtSigScheme::Ecdaa(_)
                | TpmtSigScheme::Sm2(_)
                | TpmtSigScheme::Ecschnorr(_) => {}
                _ => return Err(TpmRc::SCHEME.to_rc()),
            },
            OwnedPublicParmsAndId::KeyedHash(..) => match &selected_scheme {
                TpmtSigScheme::Hmac(_) => {}
                _ => return Err(TpmRc::VALUE.to_rc()),
            },
            _ => return Err(TpmRc::SCHEME.to_rc()),
        }

        let scheme_hash_alg =
            sig_scheme_hash_alg(&selected_scheme).ok_or_else(|| TpmRc::SCHEME.to_rc())?;
        if !is_signing_hash(scheme_hash_alg) {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }

        let is_restricted = obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED);

        if !cmd.validation.digest().as_slice().is_empty() || is_restricted {
            let ticket_hmac = self.compute_hashcheck_ticket(
                cmd.validation.hierarchy(),
                scheme_hash_alg,
                cmd.digest.as_slice(),
            )?;
            if !crate::util::constant_time_eq(cmd.validation.digest().as_slice(), &ticket_hmac) {
                return Err(TpmRc::TICKET.with(Position::parameter(3)));
            }
        } else if cmd.digest.as_slice().len() != scheme_hash_alg.digest_size() {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        let hmac_bytes = if let TpmtSigScheme::Hmac(_) = &selected_scheme {
            let (computed_hmac, _) = self
                .compute_hmac(
                    scheme_hash_alg,
                    obj.sensitive.as_bytes(),
                    &[cmd.digest.as_slice()],
                )
                .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;
            computed_hmac
        } else {
            [0u8; TpmiAlgHash::MAX_DIGEST_BYTES]
        };

        let mut sig_buf: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut sig_r = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut sig_s = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let crypto = self.crypto();
        let signature = if let TpmtSigScheme::Ecdaa(ecdaa_s) = &selected_scheme {
            if ecdaa_s.count != self.global_state.commit_counter || ecdaa_s.count == 0 {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }
            let (curve, point) = match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Ecc(parms, point) => (parms.curve_id, point),
                _ => {
                    return Err(TpmRc::KEY.with(Position::handle(1)));
                }
            };
            let param_size = ecc_param_size(curve).ok_or(TpmRc::VALUE.to_rc())?;
            // PORTING: exp passed the commit random `r` (`compute_commit_r`), `commit_x` and
            // `commit_p1` to its `ecdaa_sign`. The new `Signing::ecc_sign` only receives the
            // commit `count` (`EccSigScheme::Ecdaa`), so the ECDAA computation is left to the
            // backend.
            let key = load_ecc_private(crypto, curve, point, &obj.sensitive)
                .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
            let signature = crypto::sign(
                crypto,
                &mut self.context.platform.rng,
                SigningKey::Ecc(&key),
                selected_scheme,
                cmd.digest.as_slice(),
                &mut sig_buf,
            )
            .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;
            match signature {
                TpmtSignature::Ecdaa(sig) => TpmtSignature::Ecdaa(
                    pad_ecc_signature(&sig, param_size, &mut sig_r, &mut sig_s)
                        .ok_or(TpmRc::FAILURE)?,
                ),
                _ => return Err(TpmRc::FAILURE),
            }
        } else if let TpmtSigScheme::Hmac(_) = &selected_scheme {
            let tpmt_ha = hmac_bytes
                .get(..scheme_hash_alg.digest_size())
                .and_then(|digest| TpmtHa::new(scheme_hash_alg, digest))
                .ok_or_else(|| TpmRc::VALUE.with(Position::parameter(2)))?;
            TpmtSignature::Hmac(tpmt_ha)
        } else {
            let resolved_hash_alg = match selected_scheme {
                TpmtSigScheme::Rsassa(h) | TpmtSigScheme::Rsapss(h) | TpmtSigScheme::Ecdsa(h) => h,
                _ => return Err(TpmRc::SCHEME.to_rc()),
            };

            if TpmtHa::new(resolved_hash_alg, cmd.digest.as_slice()).is_none() {
                return Err(TpmRc::SIZE.with(Position::parameter(1)));
            }

            // PORTING: exp's `sign_inner(sign_alg, private, digest)` is now `crypto::sign` with
            // the private key loaded from the object's sensitive area. A key that fails to load
            // is reported like a failing `sign_inner`.
            let rng = &mut self.context.platform.rng;
            let digest = cmd.digest.as_slice();
            let signature = match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, unique) => {
                    let key = load_rsa_private(crypto, parms, unique.get_buffer(), &obj.sensitive)
                        .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
                    crypto::sign(
                        crypto,
                        rng,
                        SigningKey::Rsa(&key),
                        selected_scheme,
                        digest,
                        &mut sig_buf,
                    )
                }
                OwnedPublicParmsAndId::Ecc(parms, point) => {
                    let key = load_ecc_private(crypto, parms.curve_id, point, &obj.sensitive)
                        .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
                    crypto::sign(
                        crypto,
                        rng,
                        SigningKey::Ecc(&key),
                        selected_scheme,
                        digest,
                        &mut sig_buf,
                    )
                }
                _ => Err(CryptoError::Unsupported),
            }
            .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;

            match signature {
                TpmtSignature::Rsassa(_) | TpmtSignature::Rsapss(_) => signature,
                TpmtSignature::Ecdsa(sig) => {
                    let curve = match &obj.public.parms_and_id {
                        OwnedPublicParmsAndId::Ecc(parms, _) => parms.curve_id,
                        _ => return Err(TpmRc::FAILURE),
                    };
                    let param_size = ecc_param_size(curve).ok_or(TpmRc::FAILURE)?;
                    TpmtSignature::Ecdsa(
                        pad_ecc_signature(&sig, param_size, &mut sig_r, &mut sig_s)
                            .ok_or(TpmRc::FAILURE)?,
                    )
                }
                _ => return Err(TpmRc::SCHEME.to_rc()),
            }
        };

        let rsp = responses::Sign { signature };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::RSAEncrypt] (`0x174`) command.
    ///
    /// # Description
    /// This command performs RSA encryption on a message using the public key of a loaded RSA key object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 14.1 (TPM2_RSA_Encrypt).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be an RSA key.
    /// - Does not require authorization sessions, as it only uses public key parameters.
    pub fn rsa_encrypt(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<RSAEncrypt>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<RSAEncrypt>(handles)?;

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        // Validate the key referenced by key_handle is an RSA key
        let (parms, pub_key) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, pub_key) => (parms, pub_key.get_buffer()),
            _ => {
                return Err(TpmRc::KEY.with(Position::handle(1)));
            }
        };

        // Validate attributes (RESTRICTED or !DECRYPT return TPM_RC_ATTRIBUTES)
        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // Resolve the padding scheme
        let resolved_scheme = self.resolve_rsa_scheme(parms.scheme, cmd.in_scheme)?;

        // Check label constraints (must be zero-terminated if not empty)
        let label_bytes = cmd.label.as_slice();
        if !label_bytes.is_empty() && label_bytes.last() != Some(&0) {
            return Err(TpmRc::VALUE.with(Position::handle(3)));
        }

        // Encrypt with the resolved scheme / hash alg.
        //
        // PORTING: exp called `self.crypto().encrypt(scheme, hash_alg, pub_key, ..)`; the public
        // key is now loaded first, and a key that fails to load is reported like a failing
        // `encrypt`.
        let key_size = usize::from(parms.key_bits.as_u16() / 8);
        if cmd.message.as_slice().len() > key_size {
            return Err(TpmRc::SIZE.with(Position::handle(1)));
        }
        let crypto = self.crypto();
        let key = load_rsa_public(crypto, parms, pub_key)
            .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
        let mut encrypted_data = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let out_data = Rsa::encrypt(
            crypto,
            &mut self.context.platform.rng,
            &key,
            rsa_encrypt_scheme(resolved_scheme, label_bytes),
            cmd.message.as_slice(),
            &mut encrypted_data,
        )
        .ok()
        .flatten()
        .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;

        let rsp = responses::RSAEncrypt { out_data };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::RSADecrypt] (`0x159`) command.
    ///
    /// # Description
    /// This command performs RSA decryption on a ciphertext using the private key of a loaded RSA decryption key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 14.2 (TPM2_RSA_Decrypt).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be an unrestricted decryption RSA key.
    /// - Requires USER authorization for the decryption key.
    pub fn rsa_decrypt(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<RSADecrypt>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<RSADecrypt>(handles)?;

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if !obj.public.object_attributes.contains(TpmaObject::DECRYPT) {
            return Err(TpmRc::KEY.to_rc());
        }

        let (parms, modulus) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, modulus) => (parms, modulus.get_buffer()),
            _ => return Err(TpmRc::KEY.to_rc()),
        };

        let resolved_scheme = self.resolve_rsa_scheme(parms.scheme, cmd.in_scheme)?;

        // Check label constraints (must be zero-terminated if not empty)
        let label_bytes = cmd.label.as_slice();
        if !label_bytes.is_empty() && label_bytes.last() != Some(&0) {
            return Err(TpmRc::VALUE.with(Position::handle(3)));
        }

        // PORTING: a private key that fails to load is reported like a failing `decrypt`.
        let key_size = usize::from(parms.key_bits.as_u16() / 8);
        let crypto = self.crypto();
        let key = load_rsa_private(crypto, parms, modulus, &obj.sensitive)
            .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
        let mut decrypted_message = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let decrypted = Rsa::decrypt(
            crypto,
            &key,
            rsa_encrypt_scheme(resolved_scheme, label_bytes),
            cmd.cipher_text.as_slice(),
            &mut decrypted_message,
        )
        .ok()
        .flatten()
        .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;

        let mut m_bytes = decrypted.as_slice();
        let mut padded = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        if resolved_scheme.is_none() && m_bytes.len() < key_size {
            left_pad(&mut padded, m_bytes, key_size).ok_or(TpmRc::FAILURE)?;
            m_bytes = padded.get(..key_size).ok_or(TpmRc::FAILURE)?;
        }

        let rsp = responses::RSADecrypt {
            message: Tpm2bPublicKeyRsa::new(m_bytes).ok_or(TpmRc::FAILURE)?,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Resolves the RSA padding scheme from the key's scheme and the command's `inScheme`.
    ///
    /// Returns `None` for raw RSA (`TPM_ALG_NULL`).
    ///
    /// PORTING: returned `(scheme: Alg, hash_alg: Alg)` in exp; now the typed
    /// [`TpmtRsaDecrypt`] (with the OAEP hash).
    fn resolve_rsa_scheme(
        &self,
        key_scheme: Option<TpmtRsaScheme>,
        in_scheme: Option<TpmtRsaDecrypt>,
    ) -> Result<Option<TpmtRsaDecrypt>, TpmRc> {
        let resolved_scheme = match (key_scheme, in_scheme) {
            (None, None) => None,
            (None, Some(TpmtRsaDecrypt::Oaep(details))) => Some(TpmtRsaDecrypt::Oaep(details)),
            (None, Some(TpmtRsaDecrypt::Rsaes)) => Some(TpmtRsaDecrypt::Rsaes),
            (Some(TpmtRsaScheme::Oaep(key_details)), None) => {
                Some(TpmtRsaDecrypt::Oaep(key_details))
            }
            (Some(TpmtRsaScheme::Oaep(key_details)), Some(TpmtRsaDecrypt::Oaep(cmd_details))) => {
                if cmd_details != key_details {
                    return Err(TpmRc::SCHEME.with(Position::handle(2)));
                }
                Some(TpmtRsaDecrypt::Oaep(key_details))
            }
            (Some(TpmtRsaScheme::Rsaes), None)
            | (Some(TpmtRsaScheme::Rsaes), Some(TpmtRsaDecrypt::Rsaes)) => {
                Some(TpmtRsaDecrypt::Rsaes)
            }
            _ => {
                return Err(TpmRc::SCHEME.with(Position::handle(2)));
            }
        };

        Ok(resolved_scheme)
    }

    /// Handles the [TpmCc::MAC] / [TpmCc::HMAC] (`0x155`) command.
    ///
    /// # Description
    /// This command performs an HMAC or MAC operation on a message buffer using a loaded Keyed Hash object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.2 (TPM2_HMAC / TPM2_MAC).
    ///
    /// # Relationships
    /// - The key referenced by `handle` must be a loaded Keyed Hash signing object.
    /// - For sequence-based HMAC operations, use [TpmCc::HMACStart] instead.
    pub fn mac(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<HMAC>()?;
        let [handle] = handles;
        check(handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<HMAC>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(handle.0, Position::handle(1))?;

        let scheme = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::KeyedHash(scheme, _) => scheme,
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };

        // PORTING: exp compared `Alg`s with `TPM_ALG_NULL` standing for an absent hash; the
        // command's `hashAlg` is now an `Option<TpmiAlgHash>`.
        let key_hash_alg = match scheme {
            Some(TpmtKeyedHashScheme::Hmac(scheme_hash)) => {
                if cmd
                    .hash_alg
                    .is_some_and(|cmd_hash_alg| cmd_hash_alg != *scheme_hash)
                {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                *scheme_hash
            }
            None => cmd
                .hash_alg
                .ok_or(TpmRc::VALUE.with(Position::parameter(2)))?,
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        if !obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        if obj.sensitive.as_bytes().is_empty() {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        if !matches!(
            key_hash_alg,
            TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
        ) {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }

        let key = obj.sensitive.as_bytes();
        let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = crypto::hmac(
            self.crypto(),
            key_hash_alg,
            key,
            cmd.buffer.as_slice(),
            &mut digest_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let out_hmac = Tpm2bDigest::new(digest.digest()).ok_or(TpmRc::FAILURE)?;

        let rsp = responses::HMAC { out_hmac };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::ECDHZGen] (`0x154`) command.
    ///
    /// # Description
    /// This command performs an ECDH point multiplication between a loaded private ECC key and an external public ECC point
    /// to generate a shared secret `Z`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 14.4 (TPM2_ECDH_ZGen).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be a loaded ECC decryption key with the scheme set to ECDH (or Null).
    /// - Used in ECDH key exchange protocols to derive symmetric encryption keys.
    pub fn ecdh_zgen(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<ECDHZGen>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<ECDHZGen>(handles)?;

        let obj = match key_handle.handle_type() {
            Some(TpmHt::Transient) => self
                .global_state
                .find_transient_object(key_handle.0)
                .ok_or(TpmRc::HANDLE.to_rc())?
                .clone(),
            Some(TpmHt::Persistent) => self
                .context
                .load_persistent_object(self.global_state, key_handle.0)
                .map_err(|_| TpmRc::HANDLE.to_rc())?,
            _ => return Err(TpmRc::HANDLE.to_rc()),
        };

        if obj.sensitive.as_bytes().is_empty() {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        let (curve, public_point) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(ecc_parms, public_point) => {
                match ecc_parms.scheme {
                    Some(TpmtEccScheme::Ecdh(_)) | None => {}
                    _ => return Err(TpmRc::SCHEME.with(Position::handle(1))),
                }
                (ecc_parms.curve_id, public_point)
            }
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };

        // PORTING: exp's `cmd.in_point.to_struct()` (`TPM_RC_SIZE` + P1) is now done when the
        // command is unmarshaled.
        let in_point_struct = cmd.in_point.0;

        let param_size = ecc_param_size(curve).ok_or(TpmRc::CURVE.with(Position::handle(1)))?;

        let in_point = PaddedEccPoint::from_tpms(&in_point_struct, param_size)
            .ok_or(TpmRc::ECC_POINT.with(Position::parameter(1)))?;

        let crypto = self.crypto();
        let peer = load_ecc_public(crypto, curve, &in_point)
            .ok_or(TpmRc::ECC_POINT.with(Position::parameter(1)))?;

        // PORTING: exp passed the raw private scalar to `point_multiply`; the key is now loaded
        // from the object's public point and sensitive area first.
        let key = load_ecc_private(crypto, curve, public_point, &obj.sensitive)
            .ok_or(TpmRc::KEY.with(Position::handle(1)))?;

        let z = ecc_point_multiply(crypto, &key, &peer, param_size)
            .map_err(|_| TpmRc::ECC_POINT.with(Position::parameter(1)))?
            .ok_or(TpmRc::NO_RESULT)?;

        let rsp = responses::ECDHZGen {
            out_point: Tpm2b(z.as_tpms()?),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
