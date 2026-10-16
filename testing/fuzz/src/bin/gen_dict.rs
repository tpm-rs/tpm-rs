//! Generates `testing/fuzz/tpm2.dict`, the libFuzzer dictionary of the
//! `diff_conversation` target, from the `tpm2` crate's constants.
//!
//! The dictionary holds every value in its big-endian TPM wire form, which is
//! how the values appear inside `Step::Raw` bytes and `Segment::Bytes`
//! parameter segments:
//!
//! - `TPM_CC_*` (4 bytes), `TPM_ALG_*` (2), `TPM_RH_*` and `TPM_RS_PW` (4),
//!   `TPM_ST_*` (2), `TPM_ECC_*` curves (2), `TPM_SU_*` (2), `TPM_SE_*` (1) and
//!   `TPM_CAP_*` (4). These are read from the `#[doc(alias = "TPM_...")]`
//!   annotated constants of `crates/tpm2/src/constants.rs`, which is embedded
//!   at compile time, so a regenerated dictionary always follows the crate.
//! - `TPMA_OBJECT`, `TPMA_NV` and `TPMA_SESSION`: every named flag of the
//!   `tpm2` bitflags types ([`tpm2::TpmaObject`], [`tpm2::TpmaNv`],
//!   [`tpm2::TpmaSession`]), the `TPM_NT` index types placed in the `TPMA_NV`
//!   type field, and a few attribute combinations used by common templates.
//!
//! Usage (from the repository root):
//!
//! ```sh
//! cargo run --manifest-path testing/fuzz/Cargo.toml --bin gen_dict > testing/fuzz/tpm2.dict
//! ```
#![forbid(unsafe_code)]

#[path = "shared/constants.rs"]
mod constants;

use std::collections::HashSet;
use std::fmt::Write as _;

use tpm2::{TpmaNv, TpmaObject, TpmaSession};

use crate::constants::{CONSTANTS_RS, parse_aliased_constants};

/// The constant families taken from `constants.rs`: the alias prefix and the
/// size of the value on the wire in bytes.
const FAMILIES: &[(&str, usize)] = &[
    ("TPM_CC_", 4),
    ("TPM_ALG_", 2),
    ("TPM_RH_", 4),
    ("TPM_RS_", 4),
    ("TPM_ST_", 2),
    ("TPM_ECC_", 2),
    ("TPM_SU_", 2),
    ("TPM_SE_", 1),
    ("TPM_CAP_", 4),
];

/// The `TPM_NT` index types (`TPM_NT_ORDINARY` ... `TPM_NT_PIN_PASS`) and their
/// values, which `TPMA_NV` holds in bits 7:4.
const NV_TYPES: &[(&str, u32)] = &[
    ("ORDINARY", 0x0),
    ("COUNTER", 0x1),
    ("BITS", 0x2),
    ("EXTEND", 0x4),
    ("PIN_FAIL", 0x8),
    ("PIN_PASS", 0x9),
];

/// One dictionary entry: a keyword name and its wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// The libFuzzer keyword name (`[a-z0-9_]`).
    name: String,
    /// The value in big-endian wire form.
    bytes: Vec<u8>,
}

impl Entry {
    /// Creates an entry for `value` encoded big-endian in `size` bytes.
    fn new(name: &str, value: u64, size: usize) -> Self {
        let bytes = value.to_be_bytes()[8 - size..].to_vec();
        Self {
            name: name.to_ascii_lowercase(),
            bytes,
        }
    }

    /// Formats the entry as a libFuzzer dictionary line, e.g.
    /// `tpm_cc_startup="\x00\x00\x01\x44"`.
    fn to_line(&self) -> String {
        let mut line = format!("{}=\"", self.name);
        for b in &self.bytes {
            let _ = write!(line, "\\x{b:02x}");
        }
        line.push('"');
        line
    }
}

/// Builds the entries of the families in [`FAMILIES`] from the constants
/// source `src`.
fn constant_entries(src: &str) -> Vec<Entry> {
    let constants = parse_aliased_constants(src);
    let mut out = Vec::new();
    for (prefix, size) in FAMILIES {
        for (alias, value) in &constants {
            if alias.starts_with(prefix) && *value < (1u64 << (8 * size)) {
                out.push(Entry::new(alias, *value, *size));
            }
        }
    }
    out
}

/// Builds the `TPMA_OBJECT`, `TPMA_NV` and `TPMA_SESSION` entries.
fn attribute_entries() -> Vec<Entry> {
    let mut out = Vec::new();
    for (name, flag) in TpmaObject::all().iter_names() {
        out.push(Entry::new(&format!("TPMA_OBJECT_{name}"), flag.0.into(), 4));
    }
    // Attribute sets of the usual templates: a restricted storage parent, a
    // signing key, and a sealed data object.
    let common = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT | TpmaObject::USER_WITH_AUTH;
    let origin = common | TpmaObject::SENSITIVE_DATA_ORIGIN;
    let combos = [
        (
            "STORAGE_PARENT",
            origin | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
        ),
        ("SIGNING_KEY", origin | TpmaObject::SIGN_ENCRYPT),
        ("SEALED_DATA", common),
    ];
    for (name, attrs) in combos {
        out.push(Entry::new(
            &format!("TPMA_OBJECT_{name}"),
            attrs.0.into(),
            4,
        ));
    }
    for (name, flag) in TpmaNv::all().iter_names() {
        out.push(Entry::new(&format!("TPMA_NV_{name}"), flag.0.into(), 4));
    }
    for (name, nt) in NV_TYPES {
        out.push(Entry::new(
            &format!("TPMA_NV_TPM_NT_{name}"),
            (nt << 4).into(),
            4,
        ));
    }
    // An owner-readable/writable ordinary index, and one authorized by its own
    // authValue.
    let owner_rw = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
    let auth_rw = TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD;
    out.push(Entry::new("TPMA_NV_OWNER_RW", owner_rw.0.into(), 4));
    out.push(Entry::new("TPMA_NV_AUTH_RW", auth_rw.0.into(), 4));
    for (name, flag) in TpmaSession::all().iter_names() {
        out.push(Entry::new(
            &format!("TPMA_SESSION_{name}"),
            flag.0.into(),
            1,
        ));
    }
    out
}

/// Builds the whole dictionary text: a header comment followed by one line per
/// entry, without duplicate byte strings (the first name wins).
fn dictionary(src: &str) -> String {
    let mut seen = HashSet::new();
    let mut text = String::from(
        "# libFuzzer dictionary for the tpm-rs diff_conversation fuzz target.\n\
         # Generated by `cargo run --manifest-path testing/fuzz/Cargo.toml --bin gen_dict`\n\
         # from the tpm2 crate's constants (big-endian wire form). Do not edit by hand.\n",
    );
    for entry in constant_entries(src).into_iter().chain(attribute_entries()) {
        if seen.insert(entry.bytes.clone()) {
            text.push_str(&entry.to_line());
            text.push('\n');
        }
    }
    text
}

fn main() {
    print!("{}", dictionary(CONSTANTS_RS));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2::{Alg, Handle, TpmCc, TpmSt};

    /// Looks up the parsed value of `alias` in the embedded constants.
    fn parsed(alias: &str) -> u64 {
        parse_aliased_constants(CONSTANTS_RS)
            .into_iter()
            .find(|(a, _)| a == alias)
            .unwrap_or_else(|| panic!("{alias} not found"))
            .1
    }

    /// The parsed source values agree with the compiled `tpm2` constants.
    #[test]
    fn parsed_values_match_compiled_constants() {
        assert_eq!(
            parsed("TPM_CC_CreatePrimary"),
            TpmCc::CreatePrimary.code().into()
        );
        assert_eq!(parsed("TPM_CC_NV_Write"), TpmCc::NVWrite.code().into());
        assert_eq!(parsed("TPM_ALG_SHA256"), Alg::SHA256.id().into());
        assert_eq!(parsed("TPM_ALG_ECC"), Alg::ECC.id().into());
        assert_eq!(parsed("TPM_ST_SESSIONS"), TpmSt::SESSIONS.id().into());
        assert_eq!(parsed("TPM_RH_OWNER"), Handle::RH_OWNER.0.into());
        assert_eq!(parsed("TPM_RS_PW"), Handle::RS_PW.0.into());
        assert_eq!(parsed("TPM_ECC_NIST_P256"), 0x0003);
        assert_eq!(parsed("TPM_SE_POLICY"), 0x01);
    }

    /// Every requested family is present with a plausible number of entries.
    #[test]
    fn every_family_is_present() {
        let entries = constant_entries(CONSTANTS_RS);
        let count = |p: &str| entries.iter().filter(|e| e.name.starts_with(p)).count();
        assert!(count("tpm_cc_") > 100);
        assert!(count("tpm_alg_") > 30);
        assert!(count("tpm_rh_") > 10);
        assert_eq!(count("tpm_rs_"), 1);
        assert!(count("tpm_st_") > 10);
        let attrs = attribute_entries();
        for p in ["tpma_object_", "tpma_nv_", "tpma_session_"] {
            assert!(attrs.iter().any(|e| e.name.starts_with(p)), "{p}");
        }
    }

    /// Values are encoded big-endian with the family's wire size.
    #[test]
    fn entries_are_big_endian() {
        let entries = constant_entries(CONSTANTS_RS);
        let startup = entries.iter().find(|e| e.name == "tpm_cc_startup").unwrap();
        assert_eq!(startup.bytes, [0x00, 0x00, 0x01, 0x44]);
        assert_eq!(startup.to_line(), r#"tpm_cc_startup="\x00\x00\x01\x44""#);
        let pw = entries.iter().find(|e| e.name == "tpm_rs_pw").unwrap();
        assert_eq!(pw.bytes, [0x40, 0x00, 0x00, 0x09]);
        let sha256 = entries.iter().find(|e| e.name == "tpm_alg_sha256").unwrap();
        assert_eq!(sha256.bytes, [0x00, 0x0b]);
        let attrs = attribute_entries();
        let cont = attrs
            .iter()
            .find(|e| e.name == "tpma_session_continue_session")
            .unwrap();
        assert_eq!(cont.bytes, [0x01]);
        let counter = attrs
            .iter()
            .find(|e| e.name == "tpma_nv_tpm_nt_counter")
            .unwrap();
        assert_eq!(counter.bytes, [0, 0, 0, 0x10]);
    }

    /// The dictionary has no duplicate byte strings and only valid lines.
    #[test]
    fn dictionary_is_well_formed() {
        let text = dictionary(CONSTANTS_RS);
        let mut seen = HashSet::new();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (name, value) = line.split_once('=').unwrap();
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{name}"
            );
            assert!(value.starts_with('"') && value.ends_with('"'), "{line}");
            assert!(seen.insert(value.to_string()), "duplicate {line}");
        }
        assert!(seen.len() > 200);
    }
}
