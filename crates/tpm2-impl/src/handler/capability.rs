use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{ECCParameters, GetCapability, TestParms};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, TpmCap, TpmEccCurve, TpmPt};
use tpm2::{
    Tpm2bEccParameter, TpmaAlgorithm, TpmaCc, TpmlAlgProperty, TpmlCca, TpmlEccCurve, TpmlHandle,
    TpmlTaggedTpmProperty, TpmsAlgProperty, TpmsCapabilityData, TpmsTaggedProperty,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::GetCapability] (`0x17A`) command.
    ///
    /// # Description
    /// This command returns various information about the TPM, including its properties,
    /// supported algorithms, current PCR allocations, and handles of loaded entities.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 30.1 (TPM2_GetCapability).
    ///
    /// # Relationships
    /// - Clients query [TpmCc::GetCapability] to check capabilities before running commands that might depend on them.
    /// - Can be used to list handles of objects loaded by [TpmCc::Load](load.rs)
    ///   or active sessions created by [TpmCc::StartAuthSession](session.rs).
    pub fn get_capability(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<GetCapability>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut more_data = false;

        let capability_data = match cmd.capability {
            TpmCap::TPMProperties => {
                let active_sessions_count =
                    (self.global_state.active_sessions.iter().flatten().count()
                        + self.global_state.saved_sessions.iter().flatten().count())
                        as u32;
                let loaded_transient_count =
                    self.global_state.transient_objects.iter().flatten().count() as u32;
                let (persistent_count, nv_index_count) = {
                    let storage = crate::storage::manager::StorageManager::new(
                        &mut *self.context.platform.storage,
                    );
                    if let Ok(toc) = storage.read_toc() {
                        let p = toc
                            .iter()
                            .filter(|item| item.in_use != 0 && (item.handle >> 24) == 0x81)
                            .count() as u32;
                        let n = toc
                            .iter()
                            .filter(|item| item.in_use != 0 && (item.handle >> 24) == 0x01)
                            .count() as u32;
                        (p, n)
                    } else {
                        (0, 0)
                    }
                };

                let mut permanent_attr = tpm2::TpmaPermanent::empty();
                if self.global_state.owner_auth.get_size() > 0 {
                    permanent_attr |= tpm2::TpmaPermanent::OWNER_AUTH_SET;
                }
                if self.global_state.endorsement_auth.get_size() > 0 {
                    permanent_attr |= tpm2::TpmaPermanent::ENDORSEMENT_AUTH_SET;
                }
                if self.global_state.lockout_auth.get_size() > 0 {
                    permanent_attr |= tpm2::TpmaPermanent::LOCKOUT_AUTH_SET;
                }
                if self.global_state.disable_clear {
                    permanent_attr |= tpm2::TpmaPermanent::DISABLE_CLEAR;
                }
                if self.global_state.max_tries > 0
                    && self.global_state.failed_tries >= self.global_state.max_tries
                {
                    permanent_attr |= tpm2::TpmaPermanent::IN_LOCKOUT;
                }

                let mut startup_clear_attr = tpm2::TpmaStartupClear::ORDERLY;
                if self.global_state.ph_enable {
                    startup_clear_attr |= tpm2::TpmaStartupClear::PH_ENABLE;
                }
                if self.global_state.sh_enable {
                    startup_clear_attr |= tpm2::TpmaStartupClear::SH_ENABLE;
                }
                if self.global_state.eh_enable {
                    startup_clear_attr |= tpm2::TpmaStartupClear::EH_ENABLE;
                }
                if self.global_state.ph_enable_nv {
                    startup_clear_attr |= tpm2::TpmaStartupClear::PH_ENABLE_NV;
                }

                let all_properties = [
                    (TpmPt::FAMILY_INDICATOR, tpm2::TPM_SPEC_FAMILY), // "2.0\0"
                    (TpmPt::LEVEL, tpm2::TPM_SPEC_LEVEL),
                    (TpmPt::REVISION, tpm2::TPM_SPEC_VERSION),
                    (TpmPt::DAY_OF_YEAR, tpm2::TPM_SPEC_DAY_OF_YEAR),
                    (TpmPt::YEAR, tpm2::TPM_SPEC_YEAR),
                    (TpmPt::MANUFACTURER, 0x474F4F47),    // "GOOG"
                    (TpmPt::VENDOR_STRING_1, 0x54504D2D), // "TPM-"
                    (TpmPt::VENDOR_STRING_2, 0x52555354), // "RUST"
                    (TpmPt::VENDOR_STRING_3, 0),
                    (TpmPt::VENDOR_STRING_4, 0),
                    (TpmPt::VENDOR_TPM_TYPE, 1),
                    (TpmPt::FIRMWARE_VERSION_1, 1),
                    (TpmPt::FIRMWARE_VERSION_2, 0),
                    (TpmPt::INPUT_BUFFER, 1024),
                    (TpmPt::HR_TRANSIENT_MIN, 3),
                    (TpmPt::HR_PERSISTENT_MIN, 7),
                    (TpmPt::HR_LOADED_MIN, 3),
                    (TpmPt::ACTIVE_SESSIONS_MAX, 64),
                    // The PCR count for PC Client profile platforms (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
                    (TpmPt::PCR_COUNT, 24),
                    (TpmPt::PCR_SELECT_MIN, 3),
                    (TpmPt::CONTEXT_GAP_MAX, 0xFFFF),
                    (TpmPt::NV_COUNTERS_MAX, 8),
                    (TpmPt::NV_INDEX_MAX, 2048),
                    (TpmPt::MEMORY, tpm2::TpmaMemory::SHARED_NV.bits()),
                    (TpmPt::CLOCK_UPDATE, 8192),
                    (TpmPt::CONTEXT_HASH, tpm2::Alg::SHA256.id() as u32),
                    (TpmPt::CONTEXT_SYM, tpm2::Alg::AES.id() as u32),
                    (TpmPt::CONTEXT_SYM_SIZE, 128),
                    (TpmPt::ORDERLY_COUNT, 255),
                    (TpmPt::MAX_COMMAND_SIZE, 4096),
                    (TpmPt::MAX_RESPONSE_SIZE, 4096),
                    (TpmPt::MAX_DIGEST, 64),
                    (TpmPt::MAX_OBJECT_CONTEXT, 3072),
                    (TpmPt::MAX_SESSION_CONTEXT, 512),
                    (TpmPt::PS_FAMILY_INDICATOR, 0),
                    (TpmPt::PS_LEVEL, 0),
                    (TpmPt::PS_REVISION, 0),
                    (TpmPt::PS_DAY_OF_YEAR, 0),
                    (TpmPt::PS_YEAR, 0),
                    (TpmPt::SPLIT_MAX, 128),
                    (
                        TpmPt::TOTAL_COMMANDS,
                        crate::engine::SUPPORTED_COMMANDS.len() as u32,
                    ),
                    (
                        TpmPt::LIBRARY_COMMANDS,
                        crate::engine::SUPPORTED_COMMANDS.len() as u32,
                    ),
                    (TpmPt::VENDOR_COMMANDS, 0),
                    (TpmPt::NV_BUFFER_MAX, 1024),
                    (TpmPt::MODES, tpm2::TpmaModes::empty().bits()),
                    (TpmPt::MAX_CAP_BUFFER, 1024),
                    (TpmPt::PERMANENT, permanent_attr.bits()),
                    (TpmPt::STARTUP_CLEAR, startup_clear_attr.bits()),
                    (TpmPt::HR_NV_INDEX, nv_index_count),
                    (TpmPt::HR_LOADED, loaded_transient_count),
                    (
                        TpmPt::HR_LOADED_AVAIL,
                        64u32.saturating_sub(loaded_transient_count),
                    ),
                    (TpmPt::HR_ACTIVE, active_sessions_count),
                    (
                        TpmPt::HR_ACTIVE_AVAIL,
                        64u32.saturating_sub(active_sessions_count),
                    ),
                    (
                        TpmPt::HR_TRANSIENT_AVAIL,
                        64u32.saturating_sub(loaded_transient_count),
                    ),
                    (TpmPt::HR_PERSISTENT, persistent_count),
                    (
                        TpmPt::HR_PERSISTENT_AVAIL,
                        7u32.saturating_sub(persistent_count),
                    ),
                    (TpmPt::NV_COUNTERS, 0),
                    (TpmPt::NV_COUNTERS_AVAIL, 8),
                    (TpmPt::LOCKOUT_COUNTER, 0),
                    (TpmPt::MAX_AUTH_FAIL, 10),
                    (TpmPt::LOCKOUT_INTERVAL, 1000),
                    (TpmPt::LOCKOUT_RECOVERY, 1000),
                    (TpmPt::NV_WRITE_RECOVERY, 0),
                    (TpmPt::AUDIT_COUNTER_0, 0),
                    (TpmPt::AUDIT_COUNTER_1, 0),
                    (TpmPt::ALGORITHM_SET, 0),
                    (TpmPt::LOADED_CURVES, 4),
                ];

                let mut all_sorted = all_properties;
                all_sorted.sort_unstable_by_key(|&(pt, _)| pt.tag());

                let starting_prop = if cmd.property < 0x00000100 {
                    0x00000100
                } else if cmd.property > 0x0000014B && cmd.property < 0x00000200 {
                    0x00000200
                } else {
                    cmd.property
                };

                let mut tpm_property =
                    [TpmsTaggedProperty::default(); tpm2::TPM2_MAX_TPM_PROPERTIES];
                let mut count = 0;

                for &(pt, val) in all_sorted.iter() {
                    if pt.tag() >= starting_prop {
                        if count < cmd.property_count as usize
                            && count < tpm2::TPM2_MAX_TPM_PROPERTIES
                        {
                            tpm_property[count] = TpmsTaggedProperty {
                                property: pt,
                                value: val,
                            };
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }

                TpmsCapabilityData::TpmProperties(
                    TpmlTaggedTpmProperty::from_slice(&tpm_property[..count])
                        .ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::Handles => {
                let mso = cmd.property >> 24;
                let mut handles = [tpm2::Handle::default(); tpm2::TPM2_MAX_CAP_HANDLES];
                let mut count = 0;

                if !matches!(mso, 0x00 | 0x01 | 0x02 | 0x03 | 0x40 | 0x80 | 0x81) {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }

                if mso == 0x80 {
                    if cmd.property > 0x80FFFFFF {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    let mut matching = [0u32; 272];
                    let mut match_count = 0;
                    for obj in self.global_state.transient_objects.iter().flatten() {
                        if obj.handle >= cmd.property && match_count < matching.len() {
                            matching[match_count] = obj.handle;
                            match_count += 1;
                        }
                    }
                    for seq in self.global_state.active_sequences.iter().flatten() {
                        if seq.handle >= cmd.property && match_count < matching.len() {
                            matching[match_count] = seq.handle;
                            match_count += 1;
                        }
                    }
                    matching[..match_count].sort_unstable();
                    for &item in matching.iter().take(match_count) {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_HANDLES
                        {
                            handles[count] = tpm2::Handle(item);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                } else if mso == tpm2::TpmHt::LOADED_SESSION as u32
                    || mso == tpm2::TpmHt::SAVED_SESSION as u32
                {
                    if cmd.property > 0x03FFFFFF {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    let mut matching = [0u32; tpm2::TPM2_MAX_CAP_HANDLES];
                    let mut match_count = 0;
                    if mso == tpm2::TpmHt::LOADED_SESSION as u32 {
                        for sess in self.global_state.active_sessions.iter().flatten() {
                            if (sess.session_handle & 0x00FF_FFFF) >= (cmd.property & 0x00FF_FFFF)
                                && match_count < matching.len()
                            {
                                matching[match_count] = sess.session_handle;
                                match_count += 1;
                            }
                        }
                    } else if mso == tpm2::TpmHt::SAVED_SESSION as u32 {
                        for saved_handle in self.global_state.saved_sessions.iter().flatten() {
                            if (*saved_handle & 0x00FF_FFFF) >= (cmd.property & 0x00FF_FFFF)
                                && match_count < matching.len()
                            {
                                matching[match_count] =
                                    (*saved_handle & 0x00FF_FFFF) | tpm2::Handle::HR_HMAC_SESSION.0;
                                match_count += 1;
                            }
                        }
                    }
                    matching[..match_count].sort_unstable();
                    for &item in matching.iter().take(match_count) {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_HANDLES
                        {
                            handles[count] = tpm2::Handle(item);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                } else if mso == 0x81 || mso == 0x01 {
                    if (mso == 0x81 && cmd.property > 0x81FFFFFF)
                        || (mso == 0x01 && cmd.property > 0x01FFFFFF)
                    {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    let storage = crate::storage::manager::StorageManager::new(
                        &mut *self.context.platform.storage,
                    );
                    if let Ok(toc) = storage.read_toc() {
                        let mut matching = [0u32; crate::storage::manager::MAX_ITEMS];
                        let mut match_count = 0;
                        for item in toc.iter() {
                            if item.in_use != 0
                                && item.handle >= cmd.property
                                && (item.handle >> 24) == mso
                                && match_count < matching.len()
                            {
                                matching[match_count] = item.handle;
                                match_count += 1;
                            }
                        }
                        matching[..match_count].sort_unstable();
                        for &item in matching.iter().take(match_count) {
                            if count < cmd.property_count as usize
                                && count < tpm2::TPM2_MAX_CAP_HANDLES
                            {
                                handles[count] = tpm2::Handle(item);
                                count += 1;
                            } else {
                                more_data = true;
                            }
                        }
                    }
                } else if mso == 0x00 {
                    if cmd.property > 23 {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    let pcr_count = self.global_state.pcrs.sha256.len() as u32;
                    let mut item = if cmd.property < pcr_count {
                        cmd.property
                    } else {
                        pcr_count
                    };
                    while item < pcr_count {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_HANDLES
                        {
                            handles[count] = tpm2::Handle(item);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                        item += 1;
                    }
                } else if mso == 0x40 {
                    let permanent = [
                        tpm2::Handle::RH_OWNER.0,
                        tpm2::Handle::RH_NULL.0,
                        tpm2::Handle::RS_PW.0,
                        tpm2::Handle::RH_LOCKOUT.0,
                        tpm2::Handle::RH_ENDORSEMENT.0,
                        tpm2::Handle::RH_PLATFORM.0,
                        tpm2::Handle::RH_PLATFORM_NV.0,
                        tpm2::Handle::RH_AUTH_00.0,
                    ];
                    for &h in permanent.iter() {
                        if h >= cmd.property {
                            if count < cmd.property_count as usize
                                && count < tpm2::TPM2_MAX_CAP_HANDLES
                            {
                                handles[count] = tpm2::Handle(h);
                                count += 1;
                            } else {
                                more_data = true;
                            }
                        }
                    }
                } else {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }

                TpmsCapabilityData::Handles(
                    TpmlHandle::from_slice(&handles[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::PCRs => {
                if cmd.property != 0 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                TpmsCapabilityData::AssignedPcr(self.global_state.pcrs.pcr_allocation)
            }
            TpmCap::Commands => {
                let mut command_attributes = [TpmaCc::default(); tpm2::TPM2_MAX_CAP_CC];
                let mut count = 0;
                let mut sorted_cmds = crate::engine::SUPPORTED_COMMANDS;
                sorted_cmds.sort_unstable_by_key(|&cc| cc.code());

                for &cc in sorted_cmds.iter() {
                    if cc.code() >= cmd.property {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_CC {
                            command_attributes[count] = crate::engine::get_command_attribute(cc);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::Command(
                    TpmlCca::from_slice(&command_attributes[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::Algs => {
                let mut algs = [
                    (Alg::RSA, TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::OBJECT),
                    (Alg::SHA1, TpmaAlgorithm::HASH),
                    (Alg::HMAC, TpmaAlgorithm::HASH | TpmaAlgorithm::SIGNING),
                    (Alg::AES, TpmaAlgorithm::SYMMETRIC),
                    (Alg::KEYEDHASH, TpmaAlgorithm::HASH | TpmaAlgorithm::OBJECT),
                    (Alg::XOR, TpmaAlgorithm::SYMMETRIC | TpmaAlgorithm::HASH),
                    (Alg::SHA256, TpmaAlgorithm::HASH),
                    (Alg::SHA384, TpmaAlgorithm::HASH),
                    (Alg::SHA512, TpmaAlgorithm::HASH),
                    (
                        Alg::RSASSA,
                        TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::SIGNING,
                    ),
                    (
                        Alg::RSAES,
                        TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::ENCRYPTING,
                    ),
                    (
                        Alg::RSAPSS,
                        TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::SIGNING,
                    ),
                    (
                        Alg::OAEP,
                        TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::ENCRYPTING,
                    ),
                    (
                        Alg::ECDSA,
                        TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::SIGNING,
                    ),
                    (Alg::ECDH, TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::METHOD),
                    (
                        Alg::ECDAA,
                        TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::SIGNING,
                    ),
                    (Alg::ECC, TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::OBJECT),
                    (Alg::SYMCIPHER, TpmaAlgorithm::OBJECT),
                    (
                        Alg::CTR,
                        TpmaAlgorithm::SYMMETRIC | TpmaAlgorithm::ENCRYPTING,
                    ),
                    (
                        Alg::OFB,
                        TpmaAlgorithm::SYMMETRIC | TpmaAlgorithm::ENCRYPTING,
                    ),
                    (
                        Alg::CBC,
                        TpmaAlgorithm::SYMMETRIC | TpmaAlgorithm::ENCRYPTING,
                    ),
                    (
                        Alg::CFB,
                        TpmaAlgorithm::SYMMETRIC | TpmaAlgorithm::ENCRYPTING,
                    ),
                    (
                        Alg::ECB,
                        TpmaAlgorithm::SYMMETRIC | TpmaAlgorithm::ENCRYPTING,
                    ),
                ];
                algs.sort_unstable_by_key(|&(alg, _)| alg.id() as u32);
                let mut alg_properties = [TpmsAlgProperty::default(); tpm2::TPM2_MAX_CAP_ALGS];
                let mut count = 0;
                for &(alg, props) in algs.iter() {
                    if (alg.id() as u32) >= cmd.property {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_ALGS {
                            alg_properties[count] = TpmsAlgProperty {
                                alg,
                                alg_properties: props,
                            };
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::Algorithms(
                    TpmlAlgProperty::from_slice(&alg_properties[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::ECCCurves => {
                let curves = [
                    TpmEccCurve::NistP224,
                    TpmEccCurve::NistP256,
                    TpmEccCurve::NistP384,
                    TpmEccCurve::NistP521,
                    TpmEccCurve::BNP256,
                ];
                let mut ecc_curves = [TpmEccCurve::NistP256; tpm2::TPM2_MAX_ECC_CURVES];
                let mut count = 0;
                for &curve in curves.iter() {
                    if (curve as u32) >= cmd.property {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_ECC_CURVES
                        {
                            ecc_curves[count] = curve;
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::EccCurves(
                    TpmlEccCurve::from_slice(&ecc_curves[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::AuthPolicies => {
                if (cmd.property >> 24) != 0x40 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                let mut tagged_policies = tpm2::TpmlTaggedPolicy::default();
                let handles = [
                    tpm2::Handle::RH_OWNER.0,
                    tpm2::Handle::RH_LOCKOUT.0,
                    tpm2::Handle::RH_ENDORSEMENT.0,
                    tpm2::Handle::RH_PLATFORM.0,
                ];
                for &h in handles.iter() {
                    if h >= cmd.property {
                        if tagged_policies.count() < cmd.property_count as usize
                            && tagged_policies.count() < tpm2::TPM2_MAX_TAGGED_POLICIES
                        {
                            let (policy_digest, policy_alg) = match h {
                                0x40000001 => {
                                    (&self.global_state.owner_policy, self.global_state.owner_alg)
                                }
                                0x4000000A => (
                                    &self.global_state.lockout_policy,
                                    self.global_state.lockout_alg,
                                ),
                                0x4000000B => (
                                    &self.global_state.endorsement_policy,
                                    self.global_state.endorsement_alg,
                                ),
                                0x4000000C => (
                                    &self.global_state.platform_policy,
                                    self.global_state.platform_alg,
                                ),
                                _ => continue,
                            };
                            let policy_hash = policy_alg
                                .or_else(|| {
                                    crate::engine::infer_alg_from_digest_size(
                                        policy_digest.get_size() as usize,
                                    )
                                })
                                .map(|alg| crate::engine::digest_to_tpmt_ha(alg, policy_digest));
                            let _ = tagged_policies.add(&tpm2::TpmsTaggedPolicy {
                                handle: tpm2::Handle(h),
                                policy_hash,
                            });
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::AuthPolicies(tagged_policies)
            }
            TpmCap::ACT => {
                if (cmd.property >> 24) != 0x40 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            TpmCap::PCRProperties => {
                let pcr_props = [
                    (tpm2::TpmPtPcr::SAVE, [0xff, 0xff, 0x00]),
                    (tpm2::TpmPtPcr::EXTEND_L0, [0xff, 0xff, 0x81]),
                    (tpm2::TpmPtPcr::RESET_L0, [0x00, 0x00, 0x81]),
                    (tpm2::TpmPtPcr::EXTEND_L1, [0xff, 0xff, 0x91]),
                    (tpm2::TpmPtPcr::RESET_L1, [0x00, 0x00, 0x81]),
                    (tpm2::TpmPtPcr::EXTEND_L2, [0xff, 0xff, 0xff]),
                    (tpm2::TpmPtPcr::RESET_L2, [0x00, 0x00, 0xf1]),
                    (tpm2::TpmPtPcr::EXTEND_L3, [0xff, 0xff, 0x9f]),
                    (tpm2::TpmPtPcr::RESET_L3, [0x00, 0x00, 0xf1]),
                    (tpm2::TpmPtPcr::EXTEND_L4, [0xff, 0xff, 0x87]),
                    (tpm2::TpmPtPcr::RESET_L4, [0x00, 0x00, 0x7e]),
                    (tpm2::TpmPtPcr::NO_INCREMENT, [0x00, 0x00, 0xe1]),
                    (tpm2::TpmPtPcr::DRTM_RESET, [0x00, 0x00, 0x7e]),
                    (tpm2::TpmPtPcr::POLICY, [0x00, 0x00, 0x00]),
                    (tpm2::TpmPtPcr::AUTH, [0x00, 0x00, 0x00]),
                ];
                let mut tagged_props =
                    [tpm2::TpmsTaggedPcrSelect::default(); tpm2::TPM2_MAX_PCR_PROPERTIES];
                let mut count = 0;
                for &(tag, select_bytes) in &pcr_props {
                    if tag.tag() >= cmd.property {
                        if count < cmd.property_count as usize
                            && count < tpm2::TPM2_MAX_PCR_PROPERTIES
                        {
                            let mut sel = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];
                            sel[..3].copy_from_slice(&select_bytes);
                            tagged_props[count] = tpm2::TpmsTaggedPcrSelect {
                                tag,
                                size_of_select: 3,
                                pcr_select: sel,
                            };
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                if count == 0 && cmd.property > 20 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                TpmsCapabilityData::PcrProperties(
                    tpm2::TpmlTaggedPcrProperty::from_slice(&tagged_props[..count])
                        .ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::PPCommands => TpmsCapabilityData::PPCommands(tpm2::TpmlCc::default()),
            TpmCap::AuditCommands => TpmsCapabilityData::AuditCommands(tpm2::TpmlCc::default()),
            _ => {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        };

        let rsp = responses::GetCapability {
            more_data,
            capability_data,
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::TestParms] (`0x18A`) command.
    ///
    /// # Description
    /// This command is used to determine if a TPM supports a particular configuration
    /// of algorithm, key size, mode, and scheme without actually creating or loading a key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 30.3 (TPM2_TestParms).
    ///
    /// # Relationships
    /// - Call this command to test parameters before trying to create objects with [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs).
    pub fn test_parms(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = match request.try_unmarshal::<TestParms>() {
            Ok(c) => c,
            Err(_) => {
                let buf = request.remaining_slice();
                let is_valid_hash =
                    |h: u16| h == 0x0004 || h == 0x000B || h == 0x000C || h == 0x000D;
                let is_valid_kdf =
                    |k: u16| k == 0x0007 || k == 0x0020 || k == 0x0021 || k == 0x0022;
                if buf.len() >= 4 {
                    let selector = u16::from_be_bytes([buf[0], buf[1]]);
                    if selector == 0x0025 && buf.len() >= 8 {
                        let sym_alg = u16::from_be_bytes([buf[2], buf[3]]);
                        if sym_alg == 0x0006 {
                            let mode = u16::from_be_bytes([buf[6], buf[7]]);
                            if mode != 0x0043 {
                                return Err(TpmRc::MODE.with(Position::parameter(1)));
                            }
                        }
                    } else if selector == 0x0008 && buf.len() >= 6 {
                        let scheme_id = u16::from_be_bytes([buf[2], buf[3]]);
                        if scheme_id == 0x0005 && buf.len() >= 6 {
                            let hash_id = u16::from_be_bytes([buf[4], buf[5]]);
                            if !is_valid_hash(hash_id) {
                                return Err(TpmRc::HASH.with(Position::parameter(1)));
                            }
                        } else if scheme_id == 0x000A && buf.len() >= 8 {
                            let hash_id = u16::from_be_bytes([buf[4], buf[5]]);
                            if !is_valid_hash(hash_id) {
                                return Err(TpmRc::HASH.with(Position::parameter(1)));
                            }
                            let kdf_id = u16::from_be_bytes([buf[6], buf[7]]);
                            if !is_valid_kdf(kdf_id) {
                                return Err(TpmRc::KDF.with(Position::parameter(1)));
                            }
                        }
                    } else if selector == 0x0001 || selector == 0x0023 {
                        let sym_alg = u16::from_be_bytes([buf[2], buf[3]]);
                        let scheme_offset = if sym_alg == 0x0010 {
                            4
                        } else if sym_alg == 0x0006 || sym_alg == 0x0013 || sym_alg == 0x0026 {
                            8
                        } else {
                            4
                        };
                        if buf.len() >= scheme_offset + 4 {
                            let scheme_id =
                                u16::from_be_bytes([buf[scheme_offset], buf[scheme_offset + 1]]);
                            if scheme_id != 0x0010 && scheme_id != 0x0015 {
                                let hash_id = u16::from_be_bytes([
                                    buf[scheme_offset + 2],
                                    buf[scheme_offset + 3],
                                ]);
                                if !is_valid_hash(hash_id) {
                                    return Err(TpmRc::HASH.with(Position::parameter(1)));
                                }
                            }
                            if selector == 0x0023 {
                                let curve_offset = if scheme_id == 0x0010 {
                                    scheme_offset + 2
                                } else {
                                    scheme_offset + 4
                                };
                                let kdf_offset = curve_offset + 2;
                                if buf.len() >= kdf_offset + 4 {
                                    let kdf_id =
                                        u16::from_be_bytes([buf[kdf_offset], buf[kdf_offset + 1]]);
                                    if kdf_id != 0x0010 {
                                        if !is_valid_kdf(kdf_id) {
                                            return Err(TpmRc::KDF.with(Position::parameter(1)));
                                        }
                                        let kdf_hash = u16::from_be_bytes([
                                            buf[kdf_offset + 2],
                                            buf[kdf_offset + 3],
                                        ]);
                                        if !is_valid_hash(kdf_hash) {
                                            return Err(TpmRc::HASH.with(Position::parameter(1)));
                                        }
                                    }
                                }
                            }
                        }
                        if let Ok(sym) =
                            <Option<tpm2::TpmtSymDefObject> as tpm2::Unmarshal>::unmarshal(
                                &mut &buf[2..],
                            )
                        {
                            validate_symmetric(sym)?;
                        } else if sym_alg == 0x0006 && buf.len() >= 8 {
                            let mode = u16::from_be_bytes([buf[6], buf[7]]);
                            if mode != 0x0043 {
                                return Err(TpmRc::MODE.with(Position::parameter(1)));
                            }
                        }
                    }
                }
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        };
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        match cmd.parameters {
            tpm2::TpmtPublicParms::Rsa(parms) => {
                if let Some(scheme) = parms.scheme {
                    match scheme {
                        tpm2::TpmtRsaScheme::Rsapss(hash)
                        | tpm2::TpmtRsaScheme::Rsassa(hash)
                        | tpm2::TpmtRsaScheme::Oaep(hash) => {
                            validate_hash_alg(Some(hash))?;
                        }
                        tpm2::TpmtRsaScheme::Rsaes => {}
                    }
                }
                validate_symmetric(parms.symmetric)?;
                if u16::from(parms.key_bits) != 1024 && u16::from(parms.key_bits) != 2048 {
                    return Err(TpmRc::VALUE.with(Position::parameter(1)));
                }
                if parms.exponent != 0 && parms.exponent != 65537 {
                    return Err(TpmRc::VALUE.with(Position::parameter(1)));
                }
            }
            tpm2::TpmtPublicParms::Ecc(parms) => {
                if let Some(scheme) = parms.scheme {
                    match scheme {
                        tpm2::TpmtEccScheme::Ecdsa(hash)
                        | tpm2::TpmtEccScheme::Sm2(hash)
                        | tpm2::TpmtEccScheme::Ecschnorr(hash)
                        | tpm2::TpmtEccScheme::Ecdh(hash)
                        | tpm2::TpmtEccScheme::Ecmqv(hash) => {
                            validate_hash_alg(Some(hash))?;
                        }
                        tpm2::TpmtEccScheme::Ecdaa(scheme) => {
                            validate_hash_alg(Some(scheme.hash_alg))?;
                        }
                        tpm2::TpmtEccScheme::Eddsa | tpm2::TpmtEccScheme::HashEddsa => {
                            return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                        }
                    }
                }
                if let Some(kdf) = parms.kdf {
                    match kdf {
                        tpm2::TpmtKdfScheme::Kdf1Sp800_56a(hash_alg)
                        | tpm2::TpmtKdfScheme::Kdf2(hash_alg)
                        | tpm2::TpmtKdfScheme::Kdf1Sp800_108(hash_alg) => {
                            validate_hash_alg(Some(hash_alg))?;
                        }
                        tpm2::TpmtKdfScheme::Mgf1(_) | tpm2::TpmtKdfScheme::Hkdf(_) => {
                            return Err(TpmRc::KDF.with(Position::parameter(1)));
                        }
                    }
                }
                validate_symmetric(parms.symmetric)?;
                if parms.curve_id != tpm2::TpmEccCurve::NistP224
                    && parms.curve_id != tpm2::TpmEccCurve::NistP256
                    && parms.curve_id != tpm2::TpmEccCurve::NistP384
                    && parms.curve_id != tpm2::TpmEccCurve::NistP521
                    && parms.curve_id != tpm2::TpmEccCurve::BNP256
                {
                    return Err(TpmRc::CURVE.with(Position::parameter(1)));
                }
            }
            tpm2::TpmtPublicParms::KeyedHash(parms) => {
                if let Some(scheme) = parms {
                    match scheme {
                        tpm2::TpmtKeyedHashScheme::Hmac(hash_alg) => {
                            validate_hash_alg(Some(hash_alg))?;
                        }
                        tpm2::TpmtKeyedHashScheme::ExclusiveOr(scheme) => {
                            validate_hash_alg(Some(scheme.hash_alg))?;
                            if scheme.kdf.is_none() || scheme.kdf == Some(tpm2::TpmiAlgKdf::Hkdf) {
                                return Err(TpmRc::KDF.with(Position::parameter(1)));
                            }
                        }
                    }
                }
            }
            tpm2::TpmtPublicParms::Sym(parms) => {
                validate_symmetric(Some(parms))?;
            }
            tpm2::TpmtPublicParms::Mldsa(_)
            | tpm2::TpmtPublicParms::HashMldsa(_)
            | tpm2::TpmtPublicParms::Mlkem(_) => {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }

        let response = request.into_response();
        self.write_response_all(response, &(), &(), &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::ECCParameters] (`0x178`) command.
    ///
    /// # Description
    /// This command returns the parameters of an ECC curve identified by its TCG-assigned `curveID`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.4 (TPM2_ECC_Parameters).
    pub fn ecc_parameters(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<ECCParameters>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let curve_id = cmd.curve_id;
        let parameters = match curve_id {
            tpm2::TpmEccCurve::NistP224 => {
                let curve_p = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0xfe,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::from_bytes(&[
                    0xb4, 0x05, 0x0a, 0x85, 0x0c, 0x04, 0xb3, 0xab, 0xf5, 0x41, 0x32, 0x56, 0x50,
                    0x44, 0xb0, 0xb7, 0xd7, 0xbf, 0xd8, 0xba, 0x27, 0x0b, 0x39, 0x43, 0x23, 0x55,
                    0xff, 0xb4,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::from_bytes(&[
                    0xb7, 0x0e, 0x0c, 0xbd, 0x6b, 0xb4, 0xbf, 0x7f, 0x32, 0x13, 0x90, 0xb9, 0x4a,
                    0x03, 0xc1, 0xd3, 0x56, 0xc2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xd6, 0x11, 0x5c,
                    0x1d, 0x21,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::from_bytes(&[
                    0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6, 0xcd,
                    0x43, 0x75, 0xa0, 0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99, 0x85, 0x00,
                    0x7e, 0x34,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xfe, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::from_bytes(&[0x01]).map_err(|_| TpmRc::FAILURE)?;
                tpm2::TpmsAlgorithmDetailEcc {
                    curve_id,
                    key_size: 224,
                    kdf: None,
                    sign: None,
                    curve_p,
                    curve_a,
                    curve_b,
                    g_x,
                    g_y,
                    n,
                    h,
                }
            }
            tpm2::TpmEccCurve::NistP256 => {
                let curve_p = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::from_bytes(&[
                    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76,
                    0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce,
                    0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::from_bytes(&[
                    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                    0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1,
                    0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::from_bytes(&[
                    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
                    0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6,
                    0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9,
                    0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::from_bytes(&[0x01]).map_err(|_| TpmRc::FAILURE)?;
                tpm2::TpmsAlgorithmDetailEcc {
                    curve_id,
                    key_size: 256,
                    kdf: None,
                    sign: None,
                    curve_p,
                    curve_a,
                    curve_b,
                    g_x,
                    g_y,
                    n,
                    h,
                }
            }
            tpm2::TpmEccCurve::NistP384 => {
                let curve_p = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfc,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::from_bytes(&[
                    0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3,
                    0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14,
                    0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1,
                    0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::from_bytes(&[
                    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3,
                    0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7,
                    0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29,
                    0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::from_bytes(&[
                    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92,
                    0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda,
                    0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81,
                    0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63,
                    0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7,
                    0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::from_bytes(&[0x01]).map_err(|_| TpmRc::FAILURE)?;
                tpm2::TpmsAlgorithmDetailEcc {
                    curve_id,
                    key_size: 384,
                    kdf: None,
                    sign: None,
                    curve_p,
                    curve_a,
                    curve_b,
                    g_x,
                    g_y,
                    n,
                    h,
                }
            }
            tpm2::TpmEccCurve::NistP521 => {
                let curve_p = Tpm2bEccParameter::from_bytes(&[
                    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::from_bytes(&[
                    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xfc,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::from_bytes(&[
                    0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21,
                    0xa0, 0xb6, 0x85, 0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3,
                    0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1, 0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec,
                    0x7e, 0x93, 0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf, 0x07, 0x35, 0x73,
                    0xdf, 0x88, 0x3d, 0x2c, 0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f,
                    0x00,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::from_bytes(&[
                    0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e, 0x3e, 0xcb,
                    0x66, 0x23, 0x95, 0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f, 0xb5, 0x21,
                    0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d, 0x3d, 0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef,
                    0xe7, 0x59, 0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff, 0xa8, 0xde, 0x33, 0x48,
                    0xb3, 0xc1, 0x85, 0x6a, 0x42, 0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5, 0xbd,
                    0x66,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::from_bytes(&[
                    0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f,
                    0xb4, 0x2c, 0x7d, 0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44, 0x68,
                    0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e,
                    0xf4, 0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad, 0x07, 0x61, 0x35, 0x3c,
                    0x70, 0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1, 0x66,
                    0x50,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::from_bytes(&[
                    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf,
                    0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5,
                    0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64,
                    0x09,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::from_bytes(&[0x01]).map_err(|_| TpmRc::FAILURE)?;
                tpm2::TpmsAlgorithmDetailEcc {
                    curve_id,
                    key_size: 521,
                    kdf: None,
                    sign: None,
                    curve_p,
                    curve_a,
                    curve_b,
                    g_x,
                    g_y,
                    n,
                    h,
                }
            }
            tpm2::TpmEccCurve::BNP256 => {
                let curve_p = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee,
                    0x71, 0xa4, 0x9f, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x98, 0x0a, 0x82, 0xd3, 0x29,
                    0x2d, 0xdb, 0xae, 0xd3, 0x30, 0x13,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::from_bytes(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::from_bytes(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::from_bytes(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::from_bytes(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee,
                    0x71, 0xa4, 0x9e, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x99, 0x92, 0x1a, 0xf6, 0x2d,
                    0x53, 0x6c, 0xd1, 0x0b, 0x50, 0x0d,
                ])
                .map_err(|_| TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::from_bytes(&[0x01]).map_err(|_| TpmRc::FAILURE)?;
                tpm2::TpmsAlgorithmDetailEcc {
                    curve_id,
                    key_size: 256,
                    kdf: None,
                    sign: None,
                    curve_p,
                    curve_a,
                    curve_b,
                    g_x,
                    g_y,
                    n,
                    h,
                }
            }
            _ => {
                return Err(TpmRc::CURVE.with(Position::parameter(1)));
            }
        };

        let rsp = responses::ECCParameters { parameters };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}

fn validate_hash_alg(hash_alg: Option<tpm2::TpmiAlgHash>) -> Result<(), TpmRc> {
    if let Some(alg) = hash_alg {
        if alg != tpm2::TpmiAlgHash::Sha1
            && alg != tpm2::TpmiAlgHash::Sha256
            && alg != tpm2::TpmiAlgHash::Sha384
            && alg != tpm2::TpmiAlgHash::Sha512
        {
            return Err(TpmRc::HASH.with(Position::parameter(1)));
        }
    }
    Ok(())
}

fn validate_symmetric(symmetric: Option<tpm2::TpmtSymDefObject>) -> Result<(), TpmRc> {
    match symmetric {
        Some(tpm2::TpmtSymDefObject::Aes128(mode)) | Some(tpm2::TpmtSymDefObject::Aes256(mode)) => {
            if mode != Some(tpm2::TpmiAlgSymMode::CFB) {
                return Err(TpmRc::MODE.with(Position::parameter(1)));
            }
        }
        None => {}
        _ => {
            return Err(TpmRc::SYMMETRIC.with(Position::parameter(1)));
        }
    }
    Ok(())
}
