use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::{GetCapability, PolicyCapability};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Marshal, TpmCap, TpmCc, TpmEo, TpmSe, TpmsCapabilityData, Unmarshal};

/// The largest property structure `TPM2_PolicyCapability` compares against (the largest
/// `TPMS_TAGGED_POLICY`, `TPMS_TAGGED_PCR_SELECT`, `TPMS_ACT_DATA`, ..., and with secure
/// channel support a `TPM2B_PUBLIC` or `TPMS_SPDM_SESSION_INFO`).
const MAX_PROPERTY_SIZE: usize = {
    let mut max = 128;
    if cfg!(feature = "sec-channel") {
        if tpm2::Tpm2bPublic::MAX_SIZE > max {
            max = tpm2::Tpm2bPublic::MAX_SIZE;
        }
        if tpm2::TpmsSpdmSessionInfo::MAX_SIZE > max {
            max = tpm2::TpmsSpdmSessionInfo::MAX_SIZE;
        }
    }
    max
};

/// A property of a capability as its marshaled property structure (operand A).
type PropertyData = ([u8; MAX_PROPERTY_SIZE], usize);

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyCapability] (`0x19B`) command.
    ///
    /// # Description
    /// TPM 2.0 Part 3, TPM2_PolicyCapability: "This command is used to cause conditional gating
    /// of a policy based on the value of a TPM capability. It is an immediate assertion. The TPM
    /// will use the parameters of this command to fetch the indicated property that is used by
    /// the TPM in the requested logical operation. If the requested TPM *property* does not
    /// exist, the TPM will return `TPM_RC_POLICY` unless the *operation* is `TPM_EO_NEQ`." The
    /// property is the structure of the capability's "Capability Contents" table row
    /// (`TPMS_ALG_PROPERTY`, `TPM_HANDLE`, `TPMA_CC`, `TPM_CC`, `TPMS_TAGGED_PROPERTY`,
    /// `TPMS_TAGGED_PCR_SELECT`, `TPM_ECC_CURVE`, `TPMS_TAGGED_POLICY`, `TPMS_ACT_DATA`), operand
    /// A starts *offset* octets into it. Then args ≔ H_policyAlg(operandB.buffer ∥ offset ∥
    /// operation ∥ capability ∥ property) and policyDigest_new ≔ H_policyAlg(policyDigest_old ∥
    /// TPM_CC_PolicyCapability ∥ args). "This command may be used with a trial policy" (which
    /// skips the assertion).
    ///
    /// A property exists if `TPM2_GetCapability(capability, property, 1)` reports exactly it
    /// (see `policy_capability_property`). `TPM_CAP_PCRS` (whose property must be 0),
    /// `TPM_CAP_VENDOR_PROPERTY` (this TPM has no vendor properties) and the capabilities this
    /// TPM does not implement are `TPM_RC_VALUE` (capability). The
    /// spec is silent on the errors of the comparison; as the TCG reference, an *offset*
    /// beyond the property is `TPM_RC_VALUE` (offset) and an *operandB* longer than the rest of
    /// the property `TPM_RC_SIZE` (operandB).
    pub fn policy_capability(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PolicyCapability>()?;
        let [policy_session] = handles;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // `TPM_CAP` ends with "#TPM_RC_VALUE" (TPM 2.0 Part 2): the capability is validated as
        // it is unmarshaled, before *property*. As in `TPM2_GetCapability`, only the
        // capabilities this TPM reports unmarshal (the SPDM ones then fail below, as in the
        // TCG reference, whose `TPM2_PolicyCapability` has no property type for them).
        {
            let mut params = request.remaining_slice();
            if tpm2::Tpm2bOperand::unmarshal(&mut params).is_ok()
                && u16::unmarshal(&mut params).is_ok()
                && TpmEo::unmarshal(&mut params).is_ok()
                && let Some(b) = params.get(..4)
                && !crate::handler::capability::is_unmarshalable_capability(u32::from_be_bytes([
                    b[0], b[1], b[2], b[3],
                ]))
            {
                return Err(TpmRc::VALUE.with(Position::parameter(4)));
            }
        }
        let cmd = request.try_unmarshal_command::<PolicyCapability>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.validate_policy_session(policy_session, Position::handle(1))?;

        let (auth_hash, policy_digest, policy_digest_len, session_type) = {
            let session_state = self
                .context
                .state
                .session(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                session_state.session_type,
            )
        };

        let operand_b = cmd.operand_b.get_buffer();
        if session_type != TpmSe::Trial {
            match self.policy_capability_property(cmd.capability, cmd.property)? {
                // "A property that doesn't exist trivially satisfies NEQ, and trivially can't
                // satisfy any other operation" (TCG reference).
                None => {
                    if cmd.operation != TpmEo::Neq {
                        return Err(TpmRc::POLICY);
                    }
                }
                Some((data, len)) => {
                    let offset = cmd.offset as usize;
                    if offset > len {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    if len - offset < operand_b.len() {
                        return Err(TpmRc::SIZE.with(Position::parameter(1)));
                    }
                    let operand_a = &data[offset..offset + operand_b.len()];
                    if !check_condition(cmd.operation, operand_a, operand_b) {
                        return Err(TpmRc::POLICY);
                    }
                }
            }
        }

        // args = H(operandB.buffer || offset || operation || capability || property)
        let (args, args_len) = self.compute_hash(
            auth_hash,
            &[
                operand_b,
                &cmd.offset.to_be_bytes(),
                &u16::from(cmd.operation).to_be_bytes(),
                &u32::from(cmd.capability).to_be_bytes(),
                &cmd.property.to_be_bytes(),
            ],
        )?;
        // policyDigest_new = H(policyDigest_old || TPM_CC_PolicyCapability || args)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &TpmCc::PolicyCapability.code().to_be_bytes(),
                &args[..args_len],
            ],
        )?;

        {
            let session_state = self
                .context
                .state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])
    }

    /// Returns the marshaled property structure of `property` of `capability`, or `None` if
    /// the property does not exist.
    ///
    /// A property exists if `TPM2_GetCapability(capability, property, 1)` reports exactly that
    /// property: its first (and only) entry has the key `property` (the algorithm, handle,
    /// command code, `TPM_PT`, `TPM_PT_PCR`, curve, ...; the algorithm and curve IDs are the
    /// low 16 bits, as in `TPM2_GetCapability`). The errors of `TPM2_GetCapability` about the
    /// property (an unsupported handle type is `TPM_RC_HANDLE`, a `TPM_CAP_AUTH_POLICIES`
    /// property that is not a permanent handle or a `TPM_CAP_ACT` property that is not an ACT
    /// handle `TPM_RC_VALUE`) are reported at *property* (parameter 5).
    ///
    /// The session handles of `TPM_CAP_HANDLES` name a session slot: `TPM_HT_LOADED_SESSION`
    /// (`0x02`) exists if a session (HMAC or policy) is loaded in the slot,
    /// `TPM_HT_SAVED_SESSION` (`0x03`) if a session context of the slot is saved, as
    /// `TPM2_GetCapability` lists them.
    ///
    /// With secure channel support, `TPM_CAP_PUB_KEYS` (property `TPM_PUB_KEY`, a
    /// `TPM2B_PUBLIC`) has the TPM SPDM public keys `TPM_PUB_KEY_TPM_SPDM_00..=FF` (a property
    /// beyond that range is not a `TPM_PUB_KEY`: `TPM_RC_VALUE`), and
    /// `TPM_CAP_SPDM_SESSION_INFO` (a `TPMS_SPDM_SESSION_INFO`, reserved property 0, else
    /// `TPM_RC_VALUE` as in `TPM2_GetCapability`) the key Names of the SPDM session protecting
    /// the command, if any.
    fn policy_capability_property(
        &mut self,
        capability: TpmCap,
        property: u32,
    ) -> Result<Option<PropertyData>, TpmRc> {
        if !matches!(
            capability,
            TpmCap::Algs
                | TpmCap::Handles
                | TpmCap::Commands
                | TpmCap::PPCommands
                | TpmCap::AuditCommands
                | TpmCap::TPMProperties
                | TpmCap::PCRProperties
                | TpmCap::ECCCurves
                | TpmCap::AuthPolicies
                | TpmCap::ACT
        ) && !(cfg!(feature = "sec-channel")
            && matches!(capability, TpmCap::PubKeys | TpmCap::SpdmSessionInfo))
        {
            return Err(TpmRc::VALUE.with(Position::parameter(4)));
        }

        /// The marshaled `value` as property data.
        fn marshaled<M: Marshal<MaxBuffer = [u8; N]>, const N: usize>(value: &M) -> PropertyData {
            let mut buf = [0u8; N];
            let len = value.marshal(&mut buf);
            let mut data = [0u8; MAX_PROPERTY_SIZE];
            data[..len].copy_from_slice(&buf[..len]);
            (data, len)
        }
        #[cfg(feature = "sec-channel")]
        match capability {
            TpmCap::PubKeys => {
                /// `TPM_PUB_KEY_TPM_SPDM_FF`, the end of the TPM SPDM key range.
                const PUB_KEY_TPM_SPDM_FF: u32 = 0xFF;
                if property > PUB_KEY_TPM_SPDM_FF {
                    return Err(TpmRc::VALUE.with(Position::parameter(5)));
                }
                return Ok(self
                    .context
                    .tpm_spdm_public_key(property as u8)
                    .map(|public| marshaled(&tpm2::Tpm2b(public))));
            }
            TpmCap::SpdmSessionInfo => {
                if property != 0 {
                    return Err(TpmRc::VALUE.with(Position::parameter(5)));
                }
                return Ok(self.context.spdm_session_names()?.map(
                    |(req_key_name, tpm_key_name)| {
                        marshaled(&tpm2::TpmsSpdmSessionInfo {
                            req_key_name: req_key_name.as_tpm2b(),
                            tpm_key_name: tpm_key_name.as_tpm2b(),
                        })
                    },
                ));
            }
            _ => {}
        }

        let handle_property = |exists: bool| {
            exists.then(|| {
                let mut data = [0u8; MAX_PROPERTY_SIZE];
                data[..4].copy_from_slice(&property.to_be_bytes());
                (data, 4)
            })
        };
        if capability == TpmCap::Handles {
            let slot = property & 0x00FF_FFFF;
            match property >> 24 {
                0x02 => {
                    let loaded = self
                        .context
                        .state
                        .active_sessions
                        .iter()
                        .flatten()
                        .any(|session| session.session_handle & 0x00FF_FFFF == slot);
                    return Ok(handle_property(loaded));
                }
                0x03 => {
                    let saved = self.context.state.saved_session_slot(property).is_some();
                    return Ok(handle_property(saved));
                }
                _ => {}
            }
        }

        let query = GetCapability {
            capability,
            property,
            property_count: 1,
        };
        self.with_capability_data(&query, Position::parameter(5), |_, data, _| {
            let mut buf = [0u8; TpmsCapabilityData::MAX_SIZE];
            let len = data.marshal(&mut buf);
            // `capability` (4 octets), the list's `count` (4 octets), then the entries.
            if len <= 8 || buf[4..8] != 1u32.to_be_bytes() {
                return Ok(None);
            }
            let entry = &buf[8..len];
            let key_matches = match capability {
                TpmCap::Algs | TpmCap::ECCCurves => entry[..2] == (property as u16).to_be_bytes(),
                TpmCap::Commands => {
                    // A `TPMA_CC`: `commandIndex` (bits 15:0) and `V` (bit 29) identify the
                    // command.
                    let attributes = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
                    attributes & (0xFFFF | TpmCc::VEND.code()) == property
                }
                _ => entry[..4] == property.to_be_bytes(),
            };
            if !key_matches || entry.len() > MAX_PROPERTY_SIZE {
                return Ok(None);
            }
            let mut property_data = [0u8; MAX_PROPERTY_SIZE];
            property_data[..entry.len()].copy_from_slice(entry);
            Ok(Some((property_data, entry.len())))
        })
    }
}

/// Whether operand A and operand B (of equal length) have the relationship `operation` (C
/// `PolicySptCheckCondition()`): big-endian unsigned or two's-complement signed comparisons, or
/// bit tests.
fn check_condition(operation: TpmEo, a: &[u8], b: &[u8]) -> bool {
    use core::cmp::Ordering;
    let unsigned = a.cmp(b);
    let signed = match (a.first(), b.first()) {
        (Some(&a0), Some(&b0)) if (a0 ^ b0) & 0x80 != 0 => {
            if a0 & 0x80 != 0 {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        _ => unsigned,
    };
    match operation {
        TpmEo::Eq => unsigned == Ordering::Equal,
        TpmEo::Neq => unsigned != Ordering::Equal,
        TpmEo::SignedGT => signed == Ordering::Greater,
        TpmEo::UnsignedGT => unsigned == Ordering::Greater,
        TpmEo::SignedLT => signed == Ordering::Less,
        TpmEo::UnsignedLT => unsigned == Ordering::Less,
        TpmEo::SignedGE => signed != Ordering::Less,
        TpmEo::UnsignedGE => unsigned != Ordering::Less,
        TpmEo::SignedLE => signed != Ordering::Greater,
        TpmEo::UnsignedLE => unsigned != Ordering::Greater,
        TpmEo::BitSet => a.iter().zip(b).all(|(a, b)| a & b == *b),
        TpmEo::BitClear => a.iter().zip(b).all(|(a, b)| a & b == 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions() {
        assert!(check_condition(TpmEo::Eq, &[1, 2], &[1, 2]));
        assert!(check_condition(TpmEo::Neq, &[1, 2], &[1, 3]));
        assert!(check_condition(TpmEo::UnsignedGT, &[0x80], &[0x7F]));
        assert!(check_condition(TpmEo::SignedLT, &[0x80], &[0x7F]));
        assert!(check_condition(TpmEo::SignedGE, &[0x01], &[0x01]));
        assert!(check_condition(TpmEo::UnsignedLE, &[0x01], &[0x02]));
        assert!(check_condition(TpmEo::BitSet, &[0xF0], &[0x30]));
        assert!(!check_condition(TpmEo::BitSet, &[0xF0], &[0x31]));
        assert!(check_condition(TpmEo::BitClear, &[0xF0], &[0x0F]));
        // An empty operand B satisfies every comparison but the strict ones.
        assert!(check_condition(TpmEo::Eq, &[], &[]));
        assert!(!check_condition(TpmEo::UnsignedGT, &[], &[]));
    }
}
