//! Secure channel (SPDM) information of the TPM's secure transport layer.
//!
//! TPM 2.0 Part 1, "Internal Protected Capabilities": "Secure channel information may be passed
//! by a TPM implementation's secure transport layer to its application layer, which then can
//! evaluate this information in a policy assertion or store it in a Shielded Location". Part 3,
//! TPM2_PolicyTransportSPDM: "The secure channel establishment is out of scope of this
//! specification", and "The information on whether a secure channel is present (during the
//! execution of a command) and the corresponding requester and TPM public keys used in the
//! secure channel negotiation have to be provided to a TPM application layer via internal
//! protected capabilities e.g., by a TPM's secure transport layer." That is the job of the
//! platform: the [`SecureChannel`] trait.
//!
//! The TPM uses it (with the `sec-channel` feature of `tpm2-engine`) for
//! `TPM2_GetCapability(TPM_CAP_PUB_KEYS)` (the TPM SPDM authentication public keys),
//! `TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO)` (the key Names of the SPDM session that
//! protects the command) and the deferred checks of `TPM2_PolicyTransportSPDM()`
//! (`TPM_RC_CHANNEL`, `TPM_RC_CHANNEL_KEY`). A platform without a [`SecureChannel`]
//! (`TpmPlatform::secure_channel` is `None`) has no TPM SPDM keys and never protects a command
//! with an SPDM session.
//!
//! [`SimulatedSecureChannel`] is the *insecure* dummy of the TCG reference implementation
//! (`SecChannel.c`), for simulators and tests.

use crate::{Tpm2bName, TpmtPublic, Unmarshal};

/// The SPDM session that protects the command being executed (TPM 2.0 Part 2,
/// `TPMS_SPDM_SESSION_INFO`: the requester and TPM keys "associated with the current SPDM
/// session").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpdmSession<'a> {
    /// The Name of the requester's secure channel key. Part 2: "An Empty Buffer is allowed and
    /// indicates that the SPDM session was established with Responder-only authentication".
    pub req_key_name: Tpm2bName<'a>,
    /// The TPM SPDM authentication key the session was established with: the key
    /// `TPM_PUB_KEY_TPM_SPDM_00 + tpm_key` of [`SecureChannel::tpm_spdm_public_key`], whose Name
    /// the TPM computes.
    pub tpm_key: u8,
}

/// The platform interface to the TPM's secure transport layer (the counterpart of the TCG
/// reference's `SpdmCapGetTpmPubKeys`, `SpdmCapGetSessionInfo` and `IsSpdmSessionActive`).
pub trait SecureChannel {
    /// The public area of the TPM SPDM authentication key `TPM_PUB_KEY_TPM_SPDM_00 + index`
    /// (Part 2, `TPM_PUB_KEY`), or `None` if the TPM has no such key. The keys are numbered
    /// from 0 without gaps.
    fn tpm_spdm_public_key(&self, index: u8) -> Option<TpmtPublic<'_>>;

    /// The SPDM session that protects the command being executed, or `None` if the command was
    /// not received within an SPDM session.
    fn spdm_session(&self) -> Option<SpdmSession<'_>>;
}

/// The *insecure* dummy secure channel of the TCG reference implementation (`SecChannel.c`),
/// for simulators and tests only. Like the reference, which "does not implement SPDM
/// functionality":
///
/// * there is a single TPM SPDM public key (`GetTpmSpdmPubKey`): an ECC NIST P-384 signing key
///   (nameAlg SHA-384, `fixedTPM | fixedParent | sensitiveDataOrigin | restricted | sign`,
///   ECDSA with SHA-384, no symmetric algorithm or KDF) whose point has all-zero coordinates;
/// * every command is protected by an SPDM session (`IsSpdmSessionActive` "returns always
///   TRUE") with that TPM key and the requester key Name `TPM_ALG_SHA384 || 0x11 * 48`
///   (`dummy_reqKeyName`).
///
/// In a build without SHA-384 or NIST P-384 (the `sha384`/`nist_p384` features of
/// `tpm2`) the dummy key does not unmarshal, so the TPM then has no SPDM key.
#[derive(Clone, Copy, Debug, Default)]
pub struct SimulatedSecureChannel;

impl SimulatedSecureChannel {
    /// The marshaled `TPMT_PUBLIC` of the dummy TPM SPDM key (`GetTpmSpdmPubKey`).
    pub const TPM_SPDM_00_PUBLIC: [u8; 120] = {
        let mut public = [0u8; 120];
        let head: [u8; 20] = [
            0x00, 0x23, // type = TPM_ALG_ECC
            0x00, 0x0C, // nameAlg = TPM_ALG_SHA384
            0x00, 0x05, 0x00, 0x32, // objectAttributes
            0x00, 0x00, // authPolicy = Empty Buffer
            0x00, 0x10, // symmetric = TPM_ALG_NULL
            0x00, 0x18, 0x00, 0x0C, // scheme = TPM_ALG_ECDSA, SHA-384
            0x00, 0x04, // curveID = TPM_ECC_NIST_P384
            0x00, 0x10, // kdf = TPM_ALG_NULL
        ];
        let mut i = 0;
        while i < head.len() {
            public[i] = head[i];
            i += 1;
        }
        // unique.ecc.x and unique.ecc.y: 48 zero octets each.
        public[20 + 1] = 0x30;
        public[20 + 50 + 1] = 0x30;
        public
    };

    /// The requester key Name of the dummy SPDM session (`dummy_reqKeyName`): `TPM_ALG_SHA384`
    /// followed by 48 octets `0x11`.
    pub const REQ_KEY_NAME: [u8; 50] = {
        let mut name = [0x11u8; 50];
        name[0] = 0x00;
        name[1] = 0x0C;
        name
    };
}

impl SecureChannel for SimulatedSecureChannel {
    fn tpm_spdm_public_key(&self, index: u8) -> Option<TpmtPublic<'_>> {
        if index != 0 {
            return None;
        }
        let mut bytes: &'static [u8] = &Self::TPM_SPDM_00_PUBLIC;
        let public = TpmtPublic::unmarshal(&mut bytes).ok()?;
        bytes.is_empty().then_some(public)
    }

    fn spdm_session(&self) -> Option<SpdmSession<'_>> {
        Some(SpdmSession {
            req_key_name: Tpm2bName::from_bytes(&Self::REQ_KEY_NAME).ok()?,
            tpm_key: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "sha384", feature = "nist_p384"))]
    fn dummy_key_round_trips() {
        use crate::Marshal;
        let key = SimulatedSecureChannel
            .tpm_spdm_public_key(0)
            .expect("dummy key");
        let mut buf = [0u8; TpmtPublic::MAX_SIZE];
        let len = key.marshal(&mut buf);
        assert_eq!(&buf[..len], &SimulatedSecureChannel::TPM_SPDM_00_PUBLIC[..]);
        assert_eq!(SimulatedSecureChannel.tpm_spdm_public_key(1), None);
    }

    #[test]
    fn every_command_is_in_the_dummy_session() {
        let session = SimulatedSecureChannel.spdm_session().expect("session");
        assert_eq!(session.tpm_key, 0);
        assert_eq!(
            session.req_key_name.get_buffer(),
            &SimulatedSecureChannel::REQ_KEY_NAME[..]
        );
    }
}
