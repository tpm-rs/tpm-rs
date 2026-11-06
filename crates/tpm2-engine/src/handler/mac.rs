//! `TPM2_MAC` and `TPM2_MAC_Start` (the `cmac` feature), which a TPM with a block cipher MAC
//! implements in place of `TPM2_HMAC` and `TPM2_HMAC_Start` (same command codes, TPM 2.0 Part 3:
//! "A TPM can implement either `TPM2_HMAC()` or `TPM2_MAC()` but not both"). Their `inScheme`
//! is a `TPMI_ALG_MAC_SCHEME+` (a hash for an HMAC, or `TPM_ALG_CMAC`), and the key may be a
//! KEYEDHASH (HMAC) or a SYMCIPHER (CMAC) signing key.

use crate::Platform;
use crate::cmac::CmacState;
use crate::handle_checks::{Tpmi, check};
use crate::owned::{OwnedPublicParmsAndId, OwnedSensitiveData};
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::responses;
use tpm2::commands::{MAC, MACStart};
use tpm2::crypto::Crypto;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Handle, Tpm2bDigest, TpmaObject, TpmiAlgHash, TpmiAlgMacScheme, TpmiAlgSymMode,
    TpmtKeyedHashScheme,
};

/// The MAC algorithm selected for a key ([`CommandHandler::select_mac`]).
#[derive(Clone, Copy)]
enum SelectedMac {
    /// An HMAC with this hash (KEYEDHASH key).
    Hmac(TpmiAlgHash),
    /// A CMAC with the key's block cipher (SYMCIPHER key).
    Cmac(AlgSym),
}

impl<'b, C: Crypto, P: Platform<Crypto = C>> CommandHandler<'b, P> {
    /// `CryptSelectMac()`: the MAC algorithm of the key `key_handle` (already checked to be a
    /// loaded object) for `in_scheme`, together with the key's attributes.
    ///
    /// TPM 2.0 Part 3, TPM2_MAC / TPM2_MAC_Start: "If the key type is neither
    /// `TPM_ALG_KEYEDHASH` nor `TPM_ALG_SYMCIPHER` then the TPM shall return `TPM_RC_TYPE`";
    /// "If the default scheme or mode of the key referenced by *handle* is not `TPM_ALG_NULL`,
    /// then the *inScheme* parameter is required to be either the same as the key's default or
    /// `TPM_ALG_NULL` (`TPM_RC_VALUE`)"; with a `TPM_ALG_NULL` default, *inScheme* "is required
    /// to be a valid hash" (HMAC key) or "a valid block cipher mode for authentication" (symmetric
    /// cipher key) "and not `TPM_ALG_NULL` (`TPM_RC_VALUE`)". A selected algorithm that the key
    /// type cannot use (a hash for a SYMCIPHER key, CMAC or a block cipher mode for a KEYEDHASH
    /// key) is `TPM_RC_SCHEME` (`CryptMacIsValidForKey()`). The key's `restricted` and `sign`
    /// attributes are checked by the caller after this (the TCG reference's order; the
    /// specification does not order these checks).
    fn select_mac(
        &mut self,
        key_handle: u32,
        in_scheme: Option<TpmiAlgMacScheme>,
        scheme_pos: Position,
    ) -> Result<(SelectedMac, crate::handler::TransientObject), TpmRc> {
        // A sequence object is a loaded object of type `TPM_ALG_NULL` (C
        // `AllocateSequenceSlot()`), not a MAC key.
        if self
            .context
            .state
            .find_active_sequence(key_handle)
            .is_some()
        {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }
        let key_obj = self.resolve_object(key_handle, Position::handle(1))?;

        // The key's default MAC algorithm (`TPM_ALG_NULL` = none). For a KEYEDHASH key it is the
        // hash of its scheme (for an XOR key the C reference reads `details.hmac.hashAlg`, which
        // aliases the XOR hash; such keys cannot sign and fail the caller's `sign` check); for a
        // SYMCIPHER key it is its mode.
        let key_alg = match &key_obj.public.parms_and_id {
            OwnedPublicParmsAndId::KeyedHash(scheme, _) => match scheme {
                Some(TpmtKeyedHashScheme::Hmac(hash))
                | Some(TpmtKeyedHashScheme::ExclusiveOr(tpm2::TpmsSchemeXor {
                    hash_alg: hash,
                    ..
                })) => Alg::from(*hash),
                None => Alg::NULL,
            },
            OwnedPublicParmsAndId::Sym(sym, _) => Alg::from(sym.mode()),
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };
        let selected = match in_scheme {
            Some(scheme) => {
                let scheme = Alg::from(scheme);
                if key_alg != Alg::NULL && scheme != key_alg {
                    return Err(TpmRc::VALUE.with(scheme_pos));
                }
                scheme
            }
            None if key_alg == Alg::NULL => return Err(TpmRc::VALUE.with(scheme_pos)),
            None => key_alg,
        };
        let mac = match &key_obj.public.parms_and_id {
            OwnedPublicParmsAndId::KeyedHash(..) => {
                // `CryptHashIsValidAlg(macAlg, FALSE)`: an implemented hash.
                match TpmiAlgHash::try_from(selected) {
                    Ok(hash) if crate::handler::capability::is_implemented_algorithm(selected) => {
                        SelectedMac::Hmac(hash)
                    }
                    _ => return Err(TpmRc::SCHEME.with(scheme_pos)),
                }
            }
            OwnedPublicParmsAndId::Sym(sym, _) => {
                // `CryptSmacIsValidAlg(macAlg, FALSE)`: `TPM_ALG_CMAC`.
                if Option::<TpmiAlgSymMode>::try_from(selected) != Ok(Some(TpmiAlgSymMode::Cmac)) {
                    return Err(TpmRc::SCHEME.with(scheme_pos));
                }
                SelectedMac::Cmac(sym.alg)
            }
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };
        Ok((mac, key_obj))
    }

    /// Checks that the key of a MAC is an unrestricted signing key with a sensitive area
    /// (`TPM2_MAC()`/`TPM2_MAC_Start()` after `CryptSelectMac()`): "If the key referenced by
    /// *handle* has the *restricted* attribute SET, the TPM shall return `TPM_RC_ATTRIBUTES`"
    /// and "If the *sign* attribute is not SET in the key referenced by *handle*, then the TPM
    /// shall return `TPM_RC_KEY`".
    fn check_mac_key(key_obj: &crate::handler::TransientObject) -> Result<(), TpmRc> {
        let attrs = key_obj.public.object_attributes;
        if attrs.contains(TpmaObject::RESTRICTED) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        if !attrs.contains(TpmaObject::SIGN_ENCRYPT) {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        // Defense in depth: a public-only key cannot be authorized (`TPM_RC_AUTH_UNAVAILABLE`).
        if key_obj.private_len == 0 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        Ok(())
    }

    /// Starts a CMAC with the block cipher `alg` and the key of `key_obj`, after the self test
    /// of the block cipher (the CMAC is computed with it; TPM 2.0 Part 1, "Self-Test": the TPM
    /// returns no value that depends on an untested function). A key whose size does not match
    /// `alg` is `TPM_RC_FAILURE` (`CryptSmacStart()` fails).
    fn start_cmac(
        &self,
        alg: AlgSym,
        key_obj: &crate::handler::TransientObject,
    ) -> Result<CmacState, TpmRc> {
        self.crypto()
            .do_self_test(alg.algorithm())
            .map_err(|_| TpmRc::FAILURE)?;
        CmacState::new(alg, &key_obj.private[..key_obj.private_len]).ok_or(TpmRc::FAILURE)
    }

    /// Handles [`tpm2::TpmCc::MAC`] (`0x155`) as `TPM2_MAC` (the `cmac` feature; without it this
    /// TPM implements `TPM2_HMAC`, see [`Self::mac`]).
    ///
    /// # Description
    /// Computes an HMAC (KEYEDHASH key) or a CMAC (SYMCIPHER key) over `buffer` with a loaded
    /// unrestricted signing key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.6 (TPM2_MAC).
    pub fn mac_with_scheme(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<MAC>()?;
        let [handle] = handles;
        check(handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<MAC>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let (mac, key_obj) = self.select_mac(handle.0, cmd.in_scheme, Position::parameter(2))?;
        Self::check_mac_key(&key_obj)?;

        let key = &key_obj.private[..key_obj.private_len];
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let len = match mac {
            SelectedMac::Hmac(hash) => {
                let digest = self
                    .crypto()
                    .hmac(hash, key, &[cmd.buffer.get_buffer()], &mut out)
                    .map_err(|_| TpmRc::FAILURE)?;
                digest.digest().len()
            }
            SelectedMac::Cmac(alg) => {
                let mut state = self.start_cmac(alg, &key_obj)?;
                state
                    .update(&self.crypto(), cmd.buffer.get_buffer())
                    .map_err(|_| TpmRc::FAILURE)?;
                let tag = state.finalize(&self.crypto()).map_err(|_| TpmRc::FAILURE)?;
                out[..tag.len()].copy_from_slice(&tag);
                tag.len()
            }
        };
        let rsp = responses::MAC {
            out_hmac: Tpm2bDigest::from_bytes(&out[..len]).map_err(|_| TpmRc::FAILURE)?,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles [`tpm2::TpmCc::MACStart`] (`0x15B`) as `TPM2_MAC_Start` (the `cmac` feature;
    /// without it this TPM implements `TPM2_HMAC_Start`, see [`Self::mac_start`]).
    ///
    /// # Description
    /// Starts an HMAC (KEYEDHASH key) or CMAC (SYMCIPHER key) sequence with a loaded
    /// unrestricted signing key; the sequence is completed by `TPM2_SequenceComplete`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 17.3 (TPM2_MAC_Start).
    pub fn mac_start_with_scheme(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<MACStart>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<MACStart>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let (mac, key_obj) =
            self.select_mac(key_handle.0, cmd.in_scheme, Position::parameter(2))?;
        Self::check_mac_key(&key_obj)?;

        // `ObjectCreateHMACSequence()`: the sequence slot (`TPM_RC_OBJECT_MEMORY`), then the MAC.
        let (index, handle) = self.context.state.find_empty_sequence_slot()?;
        let sequence_type = match mac {
            SelectedMac::Hmac(hash_alg) => crate::SequenceType::Hmac {
                hash_alg,
                key: OwnedSensitiveData::from_bytes(&key_obj.private[..key_obj.private_len])
                    .map_err(|_| TpmRc::FAILURE)?,
            },
            SelectedMac::Cmac(alg) => crate::SequenceType::Cmac {
                state: CmacState::new(alg, &key_obj.private[..key_obj.private_len])
                    .ok_or(TpmRc::FAILURE)?,
            },
        };
        self.context.self_test_sequence_start(&sequence_type)?;
        self.context.state.active_sequences[index] = Some(crate::ActiveSequence::new(
            handle,
            crate::owned::OwnedAuth::from(cmd.auth),
            sequence_type,
        ));

        let rsp = responses::MACStart {
            sequence_handle: Handle(handle),
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
