//! Vendor-specific commands in the command capabilities: `TPM_PT_TOTAL_COMMANDS`,
//! `TPM_PT_LIBRARY_COMMANDS` and `TPM_PT_VENDOR_COMMANDS`, the `TPMA_CC` of the vendor
//! commands (`V` SET, `commandIndex` = low 16 bits of the command code) and the order of
//! `TPM_CAP_COMMANDS` and `TPM_CAP_AUDIT_COMMANDS` (TPM 2.0 Part 3, TPM2_GetCapability: the
//! vendor commands follow the library commands), including where a list starts for a
//! `property` beyond the library commands, with the `V` bit, or with other upper bits.

use crate::_common::{
    CAP_COMMANDS, audit_commands, get_cap, get_tpm_property, set_command_code_audit_status,
};
use testing::tpm::Tpm;
use tpm2::{Handle, TpmPt};

/// `TPM_CC_Vendor_TCG_Test`.
const CC_VENDOR_TCG_TEST: u32 = 0x2000_0000;
/// `TPM_CC_SetCommandCodeAuditStatus`.
const CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x140;
/// `TPM_CC_GetRandom`.
const CC_GET_RANDOM: u32 = 0x17B;
/// `TPMA_CC.V`.
const TPMA_CC_V: u32 = 1 << 29;
/// `TPMA_CC.nv`.
const TPMA_CC_NV: u32 = 1 << 22;
/// `TPM_ALG_NULL`.
const ALG_NULL: u16 = 0x0010;

/// The vendor commands of this TPM, in ascending order: `TPM2_Vendor_TCG_Test` and, in an
/// `ibmswtpm2` profile, the Nuvoton `NTC2_*` commands.
fn vendor_commands() -> Vec<u32> {
    let mut commands = vec![CC_VENDOR_TCG_TEST];
    if tpm2_impl::NTC2_VENDOR_COMMANDS {
        commands.extend([0x2000_0211, 0x2000_0212, 0x2000_0213]);
    }
    commands
}

/// Returns `(moreData, TPMA_CC list)` of `TPM2_GetCapability(TPM_CAP_COMMANDS, property,
/// count)`.
fn command_list(sim: &mut Tpm, property: u32, count: u32) -> (bool, Vec<u32>) {
    let (more, data) = get_cap(sim, CAP_COMMANDS, property, count).unwrap();
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let attrs = (0..n)
        .map(|i| u32::from_be_bytes(data[4 + 4 * i..8 + 4 * i].try_into().unwrap()))
        .collect();
    (more, attrs)
}

/// The command code of a `TPMA_CC`.
fn code_of(attr: u32) -> u32 {
    (attr & 0xFFFF) | (attr & TPMA_CC_V)
}

/// Every implemented command in `TPM_CAP_COMMANDS` order, read page by page.
fn all_commands(sim: &mut Tpm) -> Vec<u32> {
    let mut all = Vec::new();
    let mut property = 0;
    loop {
        let (more, attrs) = command_list(sim, property, 16);
        all.extend(attrs.iter().copied());
        if !more {
            return all;
        }
        property = code_of(*attrs.last().unwrap()) + 1;
    }
}

/// The command-count properties include the vendor commands
///
/// `TPM_PT_VENDOR_COMMANDS` is the number of vendor commands, and `TPM_PT_TOTAL_COMMANDS`
/// is `TPM_PT_LIBRARY_COMMANDS` plus `TPM_PT_VENDOR_COMMANDS`, which is the length of the
/// `TPM_CAP_COMMANDS` list.
#[test]
fn command_counts_include_vendor_commands() {
    let mut sim = Tpm::new();
    let total = get_tpm_property(&mut sim, TpmPt::TOTAL_COMMANDS);
    let library = get_tpm_property(&mut sim, TpmPt::LIBRARY_COMMANDS);
    let vendor = get_tpm_property(&mut sim, TpmPt::VENDOR_COMMANDS);
    assert_eq!(vendor as usize, vendor_commands().len());
    assert_eq!(total, library + vendor);
    assert_eq!(all_commands(&mut sim).len(), total as usize);
}

/// TPM_CAP_COMMANDS lists the library commands in order, then the vendor commands
///
/// The full list is in ascending `commandIndex` order with the library commands first; it
/// ends with the vendor commands, whose `TPMA_CC` has `V` SET and the low 16 bits of the
/// command code as `commandIndex` (`TPM2_Vendor_TCG_Test`: `V` only; the Nuvoton commands
/// also `nv`). No library command has `V` SET.
#[test]
fn vendor_commands_follow_library_commands() {
    let mut sim = Tpm::new();
    let all = all_commands(&mut sim);
    let vendor = vendor_commands();
    let (library, tail) = all.split_at(all.len() - vendor.len());
    assert!(library.iter().all(|a| a & TPMA_CC_V == 0));
    assert!(library.windows(2).all(|w| w[0] & 0xFFFF < w[1] & 0xFFFF));
    assert_eq!(tail.iter().map(|&a| code_of(a)).collect::<Vec<_>>(), vendor);
    assert_eq!(tail[0], TPMA_CC_V);
    for &attr in &tail[1..] {
        assert_eq!(attr & !0xFFFF, TPMA_CC_V | TPMA_CC_NV);
    }
}

/// A library property beyond the last library command continues with the vendor commands
///
/// Starting at the last library command lists it and then the first vendor command;
/// starting just after it, or at the largest library index `0xFFFF`, lists the vendor
/// commands only.
#[test]
fn library_property_continues_with_vendor_commands() {
    let mut sim = Tpm::new();
    let all = all_commands(&mut sim);
    let vendor = vendor_commands();
    let last_library = code_of(all[all.len() - vendor.len() - 1]);
    let (more, attrs) = command_list(&mut sim, last_library, 2);
    assert_eq!(more, vendor.len() > 1);
    assert_eq!(
        attrs.iter().map(|&a| code_of(a)).collect::<Vec<_>>(),
        [last_library, CC_VENDOR_TCG_TEST]
    );
    for property in [last_library + 1, 0xFFFF] {
        let (more, attrs) = command_list(&mut sim, property, 100);
        assert!(!more);
        assert_eq!(
            attrs.iter().map(|&a| code_of(a)).collect::<Vec<_>>(),
            vendor,
            "property {property:#x}"
        );
    }
}

/// A vendor property lists only the vendor commands from that index
///
/// `property = CC_VEND` lists every vendor command; `CC_VEND + 1` lists the vendor commands
/// with a larger `commandIndex` (none without the Nuvoton commands); `CC_VEND + 0xFFFF`
/// lists none. `propertyCount = 1` at `CC_VEND` reports `moreData` iff more vendor commands
/// follow.
#[test]
fn vendor_property_lists_vendor_commands_only() {
    let mut sim = Tpm::new();
    let vendor = vendor_commands();
    let (more, attrs) = command_list(&mut sim, CC_VENDOR_TCG_TEST, 100);
    assert!(!more);
    assert_eq!(
        attrs.iter().map(|&a| code_of(a)).collect::<Vec<_>>(),
        vendor
    );
    let (more, attrs) = command_list(&mut sim, CC_VENDOR_TCG_TEST + 1, 100);
    assert!(!more);
    assert_eq!(
        attrs.iter().map(|&a| code_of(a)).collect::<Vec<_>>(),
        vendor[1..]
    );
    assert_eq!(
        command_list(&mut sim, CC_VENDOR_TCG_TEST + 0xFFFF, 100),
        (false, vec![])
    );
    let (more, attrs) = command_list(&mut sim, CC_VENDOR_TCG_TEST, 1);
    assert_eq!(more, vendor.len() > 1);
    assert_eq!(attrs, [TPMA_CC_V]);
}

/// A property with upper bits other than V lists no command
///
/// A `property` that is not a command code (a bit set in 16..=28, 30 or 31) starts no list:
/// `TPM_CAP_COMMANDS` returns an empty list with `moreData` NO, even though vendor
/// commands have larger 32-bit codes.
#[test]
fn property_with_other_upper_bits_lists_nothing() {
    let mut sim = Tpm::new();
    for property in [
        0x0001_0000u32,
        0x1000_0000,
        0x2001_0000,
        0x4000_0000,
        0x8000_0000,
        0xFFFF_FFFF,
    ] {
        assert_eq!(
            command_list(&mut sim, property, 100),
            (false, vec![]),
            "property {property:#x}"
        );
    }
}

/// TPM_CAP_AUDIT_COMMANDS orders and starts audited vendor commands like TPM_CAP_COMMANDS
///
/// With `TPM2_GetRandom` and every vendor command audited, the audit list is
/// `SetCommandCodeAuditStatus, GetRandom`, then the vendor commands. A `property` after
/// `TPM2_GetRandom` lists the vendor commands, `CC_VEND + 1` the vendor commands after
/// `TPM2_Vendor_TCG_Test`, and a `property` with other upper bits nothing; `moreData` is
/// set when audited commands follow a full list.
#[test]
fn audit_commands_list_vendor_commands_last() {
    let mut sim = Tpm::new();
    let vendor = vendor_commands();
    let mut set = vec![CC_GET_RANDOM];
    set.extend(&vendor);
    assert_eq!(
        set_command_code_audit_status(&mut sim, Handle::RH_OWNER.0, ALG_NULL, &set, &[]),
        0
    );
    let mut expected = vec![CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_GET_RANDOM];
    expected.extend(&vendor);
    assert_eq!(audit_commands(&mut sim, 0, 254), (false, expected));
    assert_eq!(
        audit_commands(&mut sim, CC_GET_RANDOM + 1, 254),
        (false, vendor.clone())
    );
    assert_eq!(
        audit_commands(&mut sim, CC_VENDOR_TCG_TEST + 1, 254),
        (false, vendor[1..].to_vec())
    );
    assert_eq!(
        audit_commands(&mut sim, CC_GET_RANDOM, 1),
        (true, vec![CC_GET_RANDOM])
    );
    for property in [0x0001_0000u32, 0x1000_0000, 0x6000_0000] {
        assert_eq!(
            audit_commands(&mut sim, property, 254),
            (false, vec![]),
            "property {property:#x}"
        );
    }
}
