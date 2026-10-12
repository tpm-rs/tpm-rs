use crate::Crypto;
use crate::owned::OwnedDigest;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{ECCParameters, GetCapability, TestParms};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, Handle, Marshal, TpmCap, TpmEccCurve, TpmHt, TpmPt, TpmPtPcr};
use tpm2::{
    Tpm2bEccParameter, TpmaAlgorithm, TpmaCc, TpmlAlgProperty, TpmlCca, TpmlEccCurve, TpmlHandle,
    TpmlTaggedPcrProperty, TpmlTaggedPolicy, TpmlTaggedTpmProperty, TpmsAlgProperty,
    TpmsCapabilityData, TpmsTaggedPcrSelect, TpmsTaggedProperty, TpmtHa,
};

// PORTING: the new `tpm2` crate has no `TPM_SPEC_*` constants. These are exp's values
// (TPM 2.0 Part 2, Section 6.1, specification version 185).
/// `TPM_SPEC_FAMILY`: `"2.0\0"`.
const TPM_SPEC_FAMILY: u32 = 0x322E_3000;
/// `TPM_SPEC_LEVEL`.
const TPM_SPEC_LEVEL: u32 = 0;
/// `TPM_SPEC_VERSION`.
const TPM_SPEC_VERSION: u32 = 185;
/// `TPM_SPEC_YEAR` (`0` since version 185: the errata level is reported instead).
const TPM_SPEC_YEAR: u32 = 0;
/// `TPM_SPEC_DAY_OF_YEAR` (alias of `TPM_SPEC_ERRATA` since version 185).
const TPM_SPEC_DAY_OF_YEAR: u32 = 0;

// PORTING: the new `tpm2` crate has no `TpmaPermanent`, `TpmaStartupClear`, `TpmaMemory` or
// `TpmaModes`. These are the bits exp reported (TPM 2.0 Part 2, Sections 8.6, 8.7, 8.8, 8.10).
/// `TPMA_PERMANENT.ownerAuthSet`.
const TPMA_PERMANENT_OWNER_AUTH_SET: u32 = 1 << 0;
/// `TPMA_PERMANENT.endorsementAuthSet`.
const TPMA_PERMANENT_ENDORSEMENT_AUTH_SET: u32 = 1 << 1;
/// `TPMA_PERMANENT.lockoutAuthSet`.
const TPMA_PERMANENT_LOCKOUT_AUTH_SET: u32 = 1 << 2;
/// `TPMA_PERMANENT.disableClear`.
const TPMA_PERMANENT_DISABLE_CLEAR: u32 = 1 << 8;
/// `TPMA_PERMANENT.inLockout`.
const TPMA_PERMANENT_IN_LOCKOUT: u32 = 1 << 9;
/// `TPMA_STARTUP_CLEAR.phEnable`.
const TPMA_STARTUP_CLEAR_PH_ENABLE: u32 = 1 << 0;
/// `TPMA_STARTUP_CLEAR.shEnable`.
const TPMA_STARTUP_CLEAR_SH_ENABLE: u32 = 1 << 1;
/// `TPMA_STARTUP_CLEAR.ehEnable`.
const TPMA_STARTUP_CLEAR_EH_ENABLE: u32 = 1 << 2;
/// `TPMA_STARTUP_CLEAR.phEnableNV`.
const TPMA_STARTUP_CLEAR_PH_ENABLE_NV: u32 = 1 << 3;
/// `TPMA_STARTUP_CLEAR.orderly`.
const TPMA_STARTUP_CLEAR_ORDERLY: u32 = 1 << 31;
/// `TPMA_MEMORY.sharedNV`.
const TPMA_MEMORY_SHARED_NV: u32 = 1 << 1;
/// `TPMA_MODES` with no bits set.
const TPMA_MODES_NONE: u32 = 0;

/// `HR_HMAC_SESSION`: the first HMAC session handle (TPM 2.0 Part 2, Section 7.4).
///
/// PORTING: replaces exp's `tpm2::Handle::HR_HMAC_SESSION.0` (not provided by the new `tpm2`).
const HR_HMAC_SESSION: u32 = 0x0200_0000;

/// `TPM_CAP_VENDOR_PROPERTY` (TPM 2.0 Part 2, Section 6.13).
///
/// PORTING: exp's `TpmCap` accepted this value (and `TPM2_GetCapability` then rejected it with
/// `TPM_RC_VALUE` + parameter 1 after the size check); the new [`TpmCap`] does not.
const TPM_CAP_VENDOR_PROPERTY: u32 = 0x0000_0100;

/// Number of hierarchies whose authorization policy is reported for `TPM_CAP_AUTH_POLICIES`.
const MAX_AUTH_POLICIES: usize = 4;

/// Converts an element count to `u32`, saturating at `u32::MAX`.
///
/// PORTING: replaces exp's `count as u32` casts on (small) table counts.
fn count_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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

        // PORTING: keep exp's checks for `TPM_CAP_VENDOR_PROPERTY`, which the new `TpmCap` cannot
        // represent: all three parameters are unmarshaled and the size is checked first.
        if request
            .remaining_slice()
            .starts_with(&TPM_CAP_VENDOR_PROPERTY.to_be_bytes())
        {
            request.skip(TpmCap::MAX_SIZE);
            request.try_unmarshal_at::<u32>(Position::parameter(2))?;
            request.try_unmarshal_at::<u32>(Position::parameter(3))?;
            if request.remaining_bytes() != 0 {
                return Err(TpmRc::SIZE.to_rc());
            }
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        let cmd = request.try_unmarshal_command::<GetCapability>([])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut more_data = false;
        let property_count = usize::try_from(cmd.property_count).unwrap_or(usize::MAX);

        let capability_data = match cmd.capability {
            TpmCap::TPMProperties => {
                let active_sessions_count = count_u32(
                    self.global_state.active_sessions.iter().flatten().count()
                        + self.global_state.saved_sessions.iter().flatten().count(),
                );
                let loaded_transient_count =
                    count_u32(self.global_state.transient_objects.iter().flatten().count());
                let (persistent_count, nv_index_count) = {
                    let storage = crate::storage::manager::StorageManager::new(
                        &mut *self.context.platform.storage,
                    );
                    if let Ok(toc) = storage.read_toc() {
                        let p = count_u32(
                            toc.iter()
                                .filter(|item| item.in_use != 0 && (item.handle >> 24) == 0x81)
                                .count(),
                        );
                        let n = count_u32(
                            toc.iter()
                                .filter(|item| item.in_use != 0 && (item.handle >> 24) == 0x01)
                                .count(),
                        );
                        (p, n)
                    } else {
                        (0, 0)
                    }
                };

                let mut permanent_attr = 0;
                if self.global_state.owner_auth.get_size() > 0 {
                    permanent_attr |= TPMA_PERMANENT_OWNER_AUTH_SET;
                }
                if self.global_state.endorsement_auth.get_size() > 0 {
                    permanent_attr |= TPMA_PERMANENT_ENDORSEMENT_AUTH_SET;
                }
                if self.global_state.lockout_auth.get_size() > 0 {
                    permanent_attr |= TPMA_PERMANENT_LOCKOUT_AUTH_SET;
                }
                if self.global_state.disable_clear {
                    permanent_attr |= TPMA_PERMANENT_DISABLE_CLEAR;
                }
                if self.global_state.max_tries > 0
                    && self.global_state.failed_tries >= self.global_state.max_tries
                {
                    permanent_attr |= TPMA_PERMANENT_IN_LOCKOUT;
                }

                let mut startup_clear_attr = TPMA_STARTUP_CLEAR_ORDERLY;
                if self.global_state.ph_enable {
                    startup_clear_attr |= TPMA_STARTUP_CLEAR_PH_ENABLE;
                }
                if self.global_state.sh_enable {
                    startup_clear_attr |= TPMA_STARTUP_CLEAR_SH_ENABLE;
                }
                if self.global_state.eh_enable {
                    startup_clear_attr |= TPMA_STARTUP_CLEAR_EH_ENABLE;
                }
                if self.global_state.ph_enable_nv {
                    startup_clear_attr |= TPMA_STARTUP_CLEAR_PH_ENABLE_NV;
                }

                let supported_commands = count_u32(crate::engine::SUPPORTED_COMMANDS.len());
                let max_message_size = count_u32(crate::MAX_MESSAGE_SIZE);
                let all_properties = [
                    (TpmPt::FamilyIndicator, TPM_SPEC_FAMILY), // "2.0\0"
                    (TpmPt::Level, TPM_SPEC_LEVEL),
                    (TpmPt::Revision, TPM_SPEC_VERSION),
                    (TpmPt::DayofYear, TPM_SPEC_DAY_OF_YEAR),
                    (TpmPt::Year, TPM_SPEC_YEAR),
                    (TpmPt::Manufacturer, 0x474F4F47),  // "GOOG"
                    (TpmPt::VendorString1, 0x54504D2D), // "TPM-"
                    (TpmPt::VendorString2, 0x52555354), // "RUST"
                    (TpmPt::VendorString3, 0),
                    (TpmPt::VendorString4, 0),
                    (TpmPt::VendorTPMType, 1),
                    (TpmPt::FirmwareVersion1, 1),
                    (TpmPt::FirmwareVersion2, 0),
                    (TpmPt::InputBuffer, 1024),
                    (TpmPt::HRTransientMin, 3),
                    (TpmPt::HRPersistentMin, 7),
                    (TpmPt::HRLoadedMin, 3),
                    (TpmPt::ActiveSessionsMax, 64),
                    // The PCR count for PC Client profile platforms (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
                    (TpmPt::PCRCount, 24),
                    (TpmPt::PCRSelectMin, 3),
                    (TpmPt::ContextGapMax, 0xFFFF),
                    (TpmPt::NVCountersMax, 8),
                    (TpmPt::NVIndexMax, 2048),
                    (TpmPt::Memory, TPMA_MEMORY_SHARED_NV),
                    (TpmPt::ClockUpdate, 8192),
                    (TpmPt::ContextHash, u32::from(Alg::SHA256.id())),
                    (TpmPt::ContextSym, u32::from(Alg::AES.id())),
                    (TpmPt::ContextSymSize, 128),
                    (TpmPt::OrderlyCount, 255),
                    (TpmPt::MaxCommandSize, max_message_size),
                    (TpmPt::MaxResponseSize, max_message_size),
                    (TpmPt::MaxDigest, 64),
                    (TpmPt::MaxObjectContext, 3072),
                    (TpmPt::MaxSessionContext, 512),
                    (TpmPt::PSFamilyIndicator, 0),
                    (TpmPt::PSLevel, 0),
                    (TpmPt::PSRevision, 0),
                    (TpmPt::PSDayOfYear, 0),
                    (TpmPt::PSYear, 0),
                    (TpmPt::SplitMax, 128),
                    (TpmPt::TotalCommands, supported_commands),
                    (TpmPt::LibraryCommands, supported_commands),
                    (TpmPt::VendorCommands, 0),
                    (TpmPt::NVBufferMax, 1024),
                    (TpmPt::Modes, TPMA_MODES_NONE),
                    (TpmPt::MaxCapBuffer, 1024),
                    (TpmPt::Permanent, permanent_attr),
                    (TpmPt::StartupClear, startup_clear_attr),
                    (TpmPt::HRNVIndex, nv_index_count),
                    (TpmPt::HRLoaded, loaded_transient_count),
                    (
                        TpmPt::HRLoadedAvail,
                        64u32.saturating_sub(loaded_transient_count),
                    ),
                    (TpmPt::HRActive, active_sessions_count),
                    (
                        TpmPt::HRActiveAvail,
                        64u32.saturating_sub(active_sessions_count),
                    ),
                    (
                        TpmPt::HRTransientAvail,
                        64u32.saturating_sub(loaded_transient_count),
                    ),
                    (TpmPt::HRPersistent, persistent_count),
                    (
                        TpmPt::HRPersistentAvail,
                        7u32.saturating_sub(persistent_count),
                    ),
                    (TpmPt::NVCounters, 0),
                    (TpmPt::NVCountersAvail, 8),
                    (TpmPt::LockoutCounter, 0),
                    (TpmPt::MaxAuthFail, 10),
                    (TpmPt::LockoutInterval, 1000),
                    (TpmPt::LockoutRecovery, 1000),
                    (TpmPt::NVWriteRecovery, 0),
                    (TpmPt::AuditCounter0, 0),
                    (TpmPt::AuditCounter1, 0),
                    (TpmPt::AlgorithmSet, 0),
                    (TpmPt::LoadedCurves, 4),
                ];

                let mut all_sorted = all_properties;
                all_sorted.sort_unstable_by_key(|&(pt, _)| u32::from(pt));

                let starting_prop = if cmd.property < 0x00000100 {
                    0x00000100
                } else if cmd.property > 0x0000014B && cmd.property < 0x00000200 {
                    0x00000200
                } else {
                    cmd.property
                };

                let mut tpm_property = [TpmsTaggedProperty::default(); TpmlTaggedTpmProperty::CAP];
                let mut count = 0;

                for &(pt, val) in all_sorted.iter() {
                    if u32::from(pt) >= starting_prop {
                        if count < property_count && count < TpmlTaggedTpmProperty::CAP {
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
                    TpmlTaggedTpmProperty::new(&tpm_property[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::Handles => {
                let mso = cmd.property >> 24;
                let mut handles = [tpm2::Handle::default(); TpmlHandle::CAP];
                let mut count = 0;
                let loaded_session = u32::from(u8::from(TpmHt::HMACSession));
                let saved_session = u32::from(u8::from(TpmHt::PolicySession));

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
                        if count < property_count && count < TpmlHandle::CAP {
                            handles[count] = tpm2::Handle(item);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                } else if mso == loaded_session || mso == saved_session {
                    if cmd.property > 0x03FFFFFF {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    let mut matching = [0u32; TpmlHandle::CAP];
                    let mut match_count = 0;
                    if mso == loaded_session {
                        for sess in self.global_state.active_sessions.iter().flatten() {
                            if (sess.session_handle & 0x00FF_FFFF) >= (cmd.property & 0x00FF_FFFF)
                                && match_count < matching.len()
                            {
                                matching[match_count] = sess.session_handle;
                                match_count += 1;
                            }
                        }
                    } else if mso == saved_session {
                        for saved_handle in self.global_state.saved_sessions.iter().flatten() {
                            if (*saved_handle & 0x00FF_FFFF) >= (cmd.property & 0x00FF_FFFF)
                                && match_count < matching.len()
                            {
                                matching[match_count] =
                                    (*saved_handle & 0x00FF_FFFF) | HR_HMAC_SESSION;
                                match_count += 1;
                            }
                        }
                    }
                    matching[..match_count].sort_unstable();
                    for &item in matching.iter().take(match_count) {
                        if count < property_count && count < TpmlHandle::CAP {
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
                            if count < property_count && count < TpmlHandle::CAP {
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
                    let pcr_count = count_u32(self.global_state.pcrs.sha256.len());
                    let mut item = if cmd.property < pcr_count {
                        cmd.property
                    } else {
                        pcr_count
                    };
                    while item < pcr_count {
                        if count < property_count && count < TpmlHandle::CAP {
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
                        crate::util::RH_AUTH_00.0,
                    ];
                    for &h in permanent.iter() {
                        if h >= cmd.property {
                            if count < property_count && count < TpmlHandle::CAP {
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
                    TpmlHandle::new(&handles[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::PCRs => {
                if cmd.property != 0 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                TpmsCapabilityData::AssignedPcr(self.global_state.pcrs.pcr_allocation)
            }
            TpmCap::Commands => {
                let mut command_attributes = [TpmaCc::default(); TpmlCca::CAP];
                let mut count = 0;
                let mut sorted_cmds = crate::engine::SUPPORTED_COMMANDS;
                sorted_cmds.sort_unstable_by_key(|&cc| cc.code());

                for &cc in sorted_cmds.iter() {
                    if cc.code() >= cmd.property {
                        if count < property_count && count < TpmlCca::CAP {
                            command_attributes[count] = crate::engine::get_command_attribute(cc);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::Command(
                    TpmlCca::new(&command_attributes[..count]).ok_or(TpmRc::FAILURE)?,
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
                algs.sort_unstable_by_key(|&(alg, _)| alg.id());
                let mut alg_properties = [TpmsAlgProperty::default(); TpmlAlgProperty::CAP];
                let mut count = 0;
                for &(alg, props) in algs.iter() {
                    if u32::from(alg.id()) >= cmd.property {
                        if count < property_count && count < TpmlAlgProperty::CAP {
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
                    TpmlAlgProperty::new(&alg_properties[..count]).ok_or(TpmRc::FAILURE)?,
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
                let mut ecc_curves = [TpmEccCurve::NistP256; TpmlEccCurve::CAP];
                let mut count = 0;
                for &curve in curves.iter() {
                    if u32::from(u16::from(curve)) >= cmd.property {
                        if count < property_count && count < TpmlEccCurve::CAP {
                            ecc_curves[count] = curve;
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::EccCurves(
                    TpmlEccCurve::new(&ecc_curves[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::AuthPolicies => {
                if (cmd.property >> 24) != 0x40 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                // PORTING: exp matched on the raw handle to pick each hierarchy's policy; the
                // handle, policy digest and policy algorithm are now listed together.
                let policies = [
                    (
                        tpm2::Handle::RH_OWNER,
                        &self.global_state.owner_policy,
                        self.global_state.owner_alg,
                    ),
                    (
                        tpm2::Handle::RH_LOCKOUT,
                        &self.global_state.lockout_policy,
                        self.global_state.lockout_alg,
                    ),
                    (
                        tpm2::Handle::RH_ENDORSEMENT,
                        &self.global_state.endorsement_policy,
                        self.global_state.endorsement_alg,
                    ),
                    (
                        tpm2::Handle::RH_PLATFORM,
                        &self.global_state.platform_policy,
                        self.global_state.platform_alg,
                    ),
                ];
                let mut tagged_policies = [TaggedPolicy {
                    handle: tpm2::Handle::default(),
                    policy_hash: None,
                }; MAX_AUTH_POLICIES];
                let mut count = 0;
                for &(h, policy_digest, policy_alg) in policies.iter() {
                    if h.0 >= cmd.property {
                        if count < property_count
                            && count < TpmlTaggedPolicy::CAP
                            && count < tagged_policies.len()
                        {
                            let policy_hash = policy_alg
                                .or_else(|| {
                                    crate::engine::infer_alg_from_digest_size(usize::from(
                                        policy_digest.get_size(),
                                    ))
                                })
                                .and_then(|alg| policy_digest_to_tpmt_ha(alg, policy_digest));
                            tagged_policies[count] = TaggedPolicy {
                                handle: h,
                                policy_hash,
                            };
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                // PORTING: `TpmsCapabilityData::AuthPolicies` cannot carry an unset policy
                // (`TPM_ALG_NULL`), so this capability is marshaled by `AuthPoliciesRsp`.
                let rsp = AuthPoliciesRsp {
                    more_data,
                    policies: &tagged_policies[..count],
                };
                let response = request.into_response();
                self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;
                return Ok(());
            }
            TpmCap::ACT => {
                if (cmd.property >> 24) != 0x40 {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            TpmCap::PCRProperties => {
                let pcr_props = [
                    (TpmPtPcr::Save, [0xff, 0xff, 0x00]),
                    (TpmPtPcr::ExtendL0, [0xff, 0xff, 0x81]),
                    (TpmPtPcr::ResetL0, [0x00, 0x00, 0x81]),
                    (TpmPtPcr::ExtendL1, [0xff, 0xff, 0x91]),
                    (TpmPtPcr::ResetL1, [0x00, 0x00, 0x81]),
                    (TpmPtPcr::ExtendL2, [0xff, 0xff, 0xff]),
                    (TpmPtPcr::ResetL2, [0x00, 0x00, 0xf1]),
                    (TpmPtPcr::ExtendL3, [0xff, 0xff, 0x9f]),
                    (TpmPtPcr::ResetL3, [0x00, 0x00, 0xf1]),
                    (TpmPtPcr::ExtendL4, [0xff, 0xff, 0x87]),
                    (TpmPtPcr::ResetL4, [0x00, 0x00, 0x7e]),
                    (TpmPtPcr::NoIncrement, [0x00, 0x00, 0xe1]),
                    (TpmPtPcr::DRTMReset, [0x00, 0x00, 0x7e]),
                    (TpmPtPcr::Policy, [0x00, 0x00, 0x00]),
                    (TpmPtPcr::Auth, [0x00, 0x00, 0x00]),
                ];
                let mut tagged_props = [TpmsTaggedPcrSelect::default(); TpmlTaggedPcrProperty::CAP];
                let mut count = 0;
                for &(tag, select_bytes) in &pcr_props {
                    if u32::from(tag) >= cmd.property {
                        if count < property_count && count < TpmlTaggedPcrProperty::CAP {
                            tagged_props[count] = tpm2::TpmsTaggedPcrSelect {
                                tag,
                                selection: tpm2::TpmsPcrSelect::new(&select_bytes)
                                    .ok_or(TpmRc::FAILURE)?,
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
                    tpm2::TpmlTaggedPcrProperty::new(&tagged_props[..count])
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

        let cmd = match request.try_unmarshal_command::<TestParms>([]) {
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
                        tpm2::TpmtKeyedHashScheme::Xor(scheme) => {
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
        let cmd = request.try_unmarshal_command::<ECCParameters>([])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let curve_id = cmd.curve_id;
        let parameters = match curve_id {
            tpm2::TpmEccCurve::NistP224 => {
                let curve_p = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0xfe,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::new(&[
                    0xb4, 0x05, 0x0a, 0x85, 0x0c, 0x04, 0xb3, 0xab, 0xf5, 0x41, 0x32, 0x56, 0x50,
                    0x44, 0xb0, 0xb7, 0xd7, 0xbf, 0xd8, 0xba, 0x27, 0x0b, 0x39, 0x43, 0x23, 0x55,
                    0xff, 0xb4,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::new(&[
                    0xb7, 0x0e, 0x0c, 0xbd, 0x6b, 0xb4, 0xbf, 0x7f, 0x32, 0x13, 0x90, 0xb9, 0x4a,
                    0x03, 0xc1, 0xd3, 0x56, 0xc2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xd6, 0x11, 0x5c,
                    0x1d, 0x21,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::new(&[
                    0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6, 0xcd,
                    0x43, 0x75, 0xa0, 0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99, 0x85, 0x00,
                    0x7e, 0x34,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xfe, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::new(&[0x01]).ok_or(TpmRc::FAILURE)?;
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
                let curve_p = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::new(&[
                    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76,
                    0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce,
                    0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::new(&[
                    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                    0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1,
                    0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::new(&[
                    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
                    0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6,
                    0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9,
                    0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::new(&[0x01]).ok_or(TpmRc::FAILURE)?;
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
                let curve_p = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfc,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::new(&[
                    0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3,
                    0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14,
                    0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1,
                    0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::new(&[
                    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3,
                    0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7,
                    0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29,
                    0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::new(&[
                    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92,
                    0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda,
                    0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81,
                    0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63,
                    0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7,
                    0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::new(&[0x01]).ok_or(TpmRc::FAILURE)?;
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
                let curve_p = Tpm2bEccParameter::new(&[
                    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::new(&[
                    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xfc,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::new(&[
                    0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21,
                    0xa0, 0xb6, 0x85, 0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3,
                    0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1, 0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec,
                    0x7e, 0x93, 0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf, 0x07, 0x35, 0x73,
                    0xdf, 0x88, 0x3d, 0x2c, 0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f,
                    0x00,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::new(&[
                    0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e, 0x3e, 0xcb,
                    0x66, 0x23, 0x95, 0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f, 0xb5, 0x21,
                    0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d, 0x3d, 0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef,
                    0xe7, 0x59, 0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff, 0xa8, 0xde, 0x33, 0x48,
                    0xb3, 0xc1, 0x85, 0x6a, 0x42, 0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5, 0xbd,
                    0x66,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::new(&[
                    0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f,
                    0xb4, 0x2c, 0x7d, 0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44, 0x68,
                    0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e,
                    0xf4, 0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad, 0x07, 0x61, 0x35, 0x3c,
                    0x70, 0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1, 0x66,
                    0x50,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::new(&[
                    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf,
                    0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5,
                    0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64,
                    0x09,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::new(&[0x01]).ok_or(TpmRc::FAILURE)?;
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
                let curve_p = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee,
                    0x71, 0xa4, 0x9f, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x98, 0x0a, 0x82, 0xd3, 0x29,
                    0x2d, 0xdb, 0xae, 0xd3, 0x30, 0x13,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_a = Tpm2bEccParameter::new(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let curve_b = Tpm2bEccParameter::new(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_x = Tpm2bEccParameter::new(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let g_y = Tpm2bEccParameter::new(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let n = Tpm2bEccParameter::new(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee,
                    0x71, 0xa4, 0x9e, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x99, 0x92, 0x1a, 0xf6, 0x2d,
                    0x53, 0x6c, 0xd1, 0x0b, 0x50, 0x0d,
                ])
                .ok_or(TpmRc::FAILURE)?;
                let h = Tpm2bEccParameter::new(&[0x01]).ok_or(TpmRc::FAILURE)?;
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
    if let Some(alg) = hash_alg
        && alg != tpm2::TpmiAlgHash::Sha1
        && alg != tpm2::TpmiAlgHash::Sha256
        && alg != tpm2::TpmiAlgHash::Sha384
        && alg != tpm2::TpmiAlgHash::Sha512
    {
        return Err(TpmRc::HASH.with(Position::parameter(1)));
    }
    Ok(())
}

fn validate_symmetric(symmetric: Option<tpm2::TpmtSymDefObject>) -> Result<(), TpmRc> {
    match symmetric {
        Some(tpm2::TpmtSymDefObject {
            alg: tpm2::AlgSym::Aes128 | tpm2::AlgSym::Aes256,
            mode,
        }) => {
            if mode != Some(tpm2::TpmiAlgSymMode::Cipher(tpm2::TpmiAlgCipherMode::Cfb)) {
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

/// Returns `digest` as a [`TpmtHa`] of `alg`, truncated to the digest size of `alg`.
///
/// PORTING: replaces exp's `crate::engine::digest_to_tpmt_ha`, which panics if `digest` is
/// shorter than the digest size of `alg` (reachable in exp: `TPM2_ChangeEPS` clears the
/// endorsement policy digest but not its algorithm). Such a policy is now reported as unset
/// (`TPM_ALG_NULL`) instead.
fn policy_digest_to_tpmt_ha(alg: tpm2::TpmiAlgHash, digest: &OwnedDigest) -> Option<TpmtHa<'_>> {
    TpmtHa::new(alg, digest.get_buffer().get(..alg.digest_size())?)
}

/// `TPMS_TAGGED_POLICY` whose `policyHash` may be `TPM_ALG_NULL` (`TPMT_HA+`).
///
/// PORTING: [`tpm2::TpmsTaggedPolicy::policy_hash`] is a non-optional [`TpmtHa`], but exp reports
/// a hierarchy without an authorization policy with `hashAlg = TPM_ALG_NULL` and no digest.
#[derive(Clone, Copy)]
struct TaggedPolicy<'d> {
    handle: Handle,
    policy_hash: Option<TpmtHa<'d>>,
}

/// `TPM2_GetCapability` response parameters for `TPM_CAP_AUTH_POLICIES`.
///
/// Encoded like a [`responses::GetCapability`] holding a `TPML_TAGGED_POLICY` of
/// [`TaggedPolicy`] entries.
struct AuthPoliciesRsp<'d> {
    more_data: bool,
    policies: &'d [TaggedPolicy<'d>],
}

impl Marshal for AuthPoliciesRsp<'_> {
    const MAX_SIZE: usize = bool::MAX_SIZE
        + TpmCap::MAX_SIZE
        + u32::MAX_SIZE
        + MAX_AUTH_POLICIES * (Handle::MAX_SIZE + <Option<TpmtHa>>::MAX_SIZE);
    type MaxBuffer = [u8; AuthPoliciesRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let policies = self.policies.iter().take(MAX_AUTH_POLICIES);
        let count = count_u32(policies.len());
        let mut offset = put(&self.more_data, dst, 0);
        offset = put(&TpmCap::AuthPolicies, dst, offset);
        offset = put(&count, dst, offset);
        for policy in policies {
            offset = put(&policy.handle, dst, offset);
            offset = put(&policy.policy_hash, dst, offset);
        }
        offset
    }
}

/// Marshals `value` into `dst` at `offset` and returns the offset just past it.
///
/// Leaves `dst` unchanged and returns `offset` if `value` does not fit.
fn put<const N: usize>(
    value: &impl Marshal<MaxBuffer = [u8; N]>,
    dst: &mut [u8],
    offset: usize,
) -> usize {
    let mut buf = [0u8; N];
    let len = value.marshal(&mut buf);
    let end = offset.saturating_add(len);
    match (buf.get(..len), dst.get_mut(offset..end)) {
        (Some(src), Some(out)) => {
            out.copy_from_slice(src);
            end
        }
        _ => offset,
    }
}
