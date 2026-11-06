//! Secure channel (SPDM) support: the TPM side of `SEC_CHANNEL_SUPPORT` (the `sec-channel`
//! feature).
//!
//! TPM 2.0 Part 3, TPM2_PolicyTransportSPDM: "The secure channel establishment is out of scope
//! of this specification", and the information "on whether a secure channel is present (during
//! the execution of a command) and the corresponding requester and TPM public keys used in the
//! secure channel negotiation have to be provided to a TPM application layer via internal
//! protected capabilities". The platform's secure transport layer provides it
//! ([`tpm2::platform::SecureChannel`], `Platform::secure_channel`); this module derives what
//! the commands need from it:
//!
//! * `TPM2_GetCapability(TPM_CAP_PUB_KEYS)` lists the TPM SPDM authentication public keys
//!   ([`TpmEngine::tpm_spdm_public_key`]);
//! * `TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO)` reports the requester and TPM key Names of
//!   the SPDM session protecting the command ([`TpmEngine::spdm_session_names`]);
//! * `TPM2_PolicyTransportSPDM()` records *scKeyNameHash* ([`TpmEngine::sc_key_name_hash`]),
//!   and the use of the policy session for authorization checks the channel
//!   ([`TpmEngine::check_sec_channel_policy`]: `TPM_RC_CHANNEL`, `TPM_RC_CHANNEL_KEY`).

use crate::Platform;
use crate::engine::TpmEngine;
use crate::handler::SecChannelPolicy;
use crate::owned::OwnedName;
use tpm2::crypto::Crypto;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Marshal, TpmiAlgHash, TpmtPublic};

impl<C: Crypto, P: Platform<Crypto = C>> TpmEngine<P> {
    /// The public area of the TPM SPDM authentication key `TPM_PUB_KEY_TPM_SPDM_00 + index`
    /// (TPM 2.0 Part 2, `TPM_PUB_KEY`), or `None` if the platform has no such key.
    pub(crate) fn tpm_spdm_public_key(&self, index: u8) -> Option<TpmtPublic<'_>> {
        self.platform.secure_channel()?.tpm_spdm_public_key(index)
    }

    /// The Name of the TPM SPDM key `index`: `nameAlg || H_nameAlg(publicArea)` (TPM 2.0 Part 1,
    /// "Names"); an Empty Buffer if the platform has no such key or its nameAlg is
    /// `TPM_ALG_NULL`.
    fn tpm_spdm_key_name(&self, index: u8) -> Result<OwnedName, TpmRc> {
        let Some(public) = self.tpm_spdm_public_key(index) else {
            return Ok(OwnedName::default());
        };
        let Some(name_alg) = public.name_alg else {
            return Ok(OwnedName::default());
        };
        let mut public_bytes = [0u8; TpmtPublic::MAX_SIZE];
        let public_len = public.marshal(&mut public_bytes);
        let mut digest = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = self.digest(name_alg, &[&public_bytes[..public_len]], &mut digest)?;
        let mut name = [0u8; 2 + TpmiAlgHash::MAX_DIGEST_BYTES];
        name[..2].copy_from_slice(&u16::from(tpm2::Alg::from(name_alg)).to_be_bytes());
        name[2..2 + digest.len()].copy_from_slice(digest);
        OwnedName::from_bytes(&name[..2 + digest.len()]).map_err(|_| TpmRc::FAILURE)
    }

    /// The requester and TPM key Names of the SPDM session protecting the command being
    /// executed (TPM 2.0 Part 2, `TPMS_SPDM_SESSION_INFO`), or `None` if the command was not
    /// received within an SPDM session.
    ///
    /// The TPM key Name is computed whenever a session is present, as by the TCG reference's
    /// `IsSpdmSessionActive()`, so that the hash of the key's nameAlg is used (and self-tested)
    /// at the same points.
    pub(crate) fn spdm_session_names(&self) -> Result<Option<(OwnedName, OwnedName)>, TpmRc> {
        let Some(session) = self
            .platform
            .secure_channel()
            .and_then(|channel| channel.spdm_session())
        else {
            return Ok(None);
        };
        let req_key_name =
            OwnedName::from_bytes(session.req_key_name.get_buffer()).map_err(|_| TpmRc::FAILURE)?;
        let tpm_key_name = self.tpm_spdm_key_name(session.tpm_key)?;
        Ok(Some((req_key_name, tpm_key_name)))
    }

    /// `H_alg(data[0] || data[1] || ...)`, written into `out`.
    fn digest<'o>(
        &self,
        alg: TpmiAlgHash,
        data: &[&[u8]],
        out: &'o mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
    ) -> Result<&'o [u8], TpmRc> {
        let mut hash = self.crypto().hash_stream(alg).map_err(|_| TpmRc::FAILURE)?;
        for part in data {
            hash.update(part).map_err(|_| TpmRc::FAILURE)?;
        }
        let len = hash
            .finalize(out)
            .map_err(|_| TpmRc::FAILURE)?
            .digest()
            .len();
        Ok(&out[..len])
    }

    /// *scKeyNameHash* (TPM 2.0 Part 3, TPM2_PolicyTransportSPDM):
    /// `H_policyAlg(reqKeyName.size || reqKeyName.name || tpmKeyName.size || tpmKeyName.name)`,
    /// where either Name may be the Empty Buffer. Returns the digest and its size.
    pub(crate) fn sc_key_name_hash(
        &self,
        policy_alg: TpmiAlgHash,
        req_key_name: &[u8],
        tpm_key_name: &[u8],
    ) -> Result<([u8; 64], usize), TpmRc> {
        let req_size = (req_key_name.len() as u16).to_be_bytes();
        let tpm_size = (tpm_key_name.len() as u16).to_be_bytes();
        let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let hash = self.digest(
            policy_alg,
            &[&req_size, req_key_name, &tpm_size, tpm_key_name],
            &mut buf,
        )?;
        let mut digest = [0u8; 64];
        let len = hash.len();
        digest[..len].copy_from_slice(hash);
        Ok((digest, len))
    }

    /// The deferred checks of `TPM2_PolicyTransportSPDM()` when a policy session with
    /// *checkSecureChannel* SET is used for authorization (TPM 2.0 Part 3,
    /// TPM2_PolicyTransportSPDM): "the TPM will check that an SPDM secure channel is present,
    /// otherwise return `TPM_RC_CHANNEL`. If either the requester or TPM secure channel key has
    /// to be checked, the TPM will compute *scKeyNameHash* [...] using the requester and/or TPM
    /// key that were used in the secure channel negotiation. If the *scKeyNameHash* values do
    /// not match, the TPM shall return `TPM_RC_CHANNEL_KEY`." A key that is not checked enters
    /// the hash as an Empty Buffer, as in the assertion. `pos` is the session's position.
    pub(crate) fn check_sec_channel_policy(
        &self,
        policy: &SecChannelPolicy,
        policy_alg: TpmiAlgHash,
        pos: Position,
    ) -> Result<(), TpmRc> {
        if !policy.check_secure_channel {
            return Ok(());
        }
        let Some((req_key_name, tpm_key_name)) = self.spdm_session_names()? else {
            return Err(TpmRc::CHANNEL.with(pos));
        };
        if policy.check_req_key || policy.check_tpm_key {
            let req: &[u8] = if policy.check_req_key {
                req_key_name.get_buffer()
            } else {
                &[]
            };
            let tpm: &[u8] = if policy.check_tpm_key {
                tpm_key_name.get_buffer()
            } else {
                &[]
            };
            let (digest, len) = self.sc_key_name_hash(policy_alg, req, tpm)?;
            if digest[..len] != policy.sc_key_name_hash[..policy.sc_key_name_hash_len] {
                return Err(TpmRc::CHANNEL_KEY.with(pos));
            }
        }
        Ok(())
    }
}
