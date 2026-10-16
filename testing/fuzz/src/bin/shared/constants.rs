//! The `#[doc(alias = "TPM_...")]` annotated constants of the `tpm2` crate,
//! read from its source (`crates/tpm2/src/constants.rs`, embedded at compile
//! time), so tools can list them by their specification names. Shared by
//! `gen_dict` (the fuzzing dictionary) and `to_test` (command names).

/// The source of the `tpm2` constants, embedded at compile time.
pub const CONSTANTS_RS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/tpm2/src/constants.rs"
));

/// Parses the first hexadecimal literal (`0x...`, underscores allowed) in
/// `line`.
pub fn first_hex_literal(line: &str) -> Option<u64> {
    let start = line.find("0x")? + 2;
    let digits: String = line[start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '_')
        .filter(|c| *c != '_')
        .collect();
    u64::from_str_radix(&digits, 16).ok()
}

/// Extracts every `#[doc(alias = "TPM_...")]` constant of `src` with its value:
/// the first hexadecimal literal on the first non-attribute line after the
/// alias (e.g. `pub const STARTUP: Self = Self::new(0x00000144);` or
/// `NistP256 = 0x0003,`). Aliases without such a literal are skipped.
pub fn parse_aliased_constants(src: &str) -> Vec<(String, u64)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim().strip_prefix("#[doc(alias = \"") else {
            continue;
        };
        let Some(alias) = rest.split('"').next() else {
            continue;
        };
        let item = lines[i + 1..]
            .iter()
            .map(|l| l.trim())
            .find(|l| !l.starts_with("#["));
        if let Some(value) = item.and_then(first_hex_literal) {
            out.push((alias.to_string(), value));
        }
    }
    out
}

/// The specification name of command code `code` without the `TPM_CC_`
/// prefix (e.g. `CreatePrimary`), if `tpm2` defines it.
#[allow(dead_code)] // Used by `to_test` only.
pub fn command_name(code: u32) -> Option<String> {
    parse_aliased_constants(CONSTANTS_RS)
        .into_iter()
        .filter(|(alias, _)| !alias.ends_with("_FIRST") && !alias.ends_with("_LAST"))
        .find(|(alias, value)| alias.starts_with("TPM_CC_") && *value == u64::from(code))
        .map(|(alias, _)| alias["TPM_CC_".len()..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hexadecimal literal parser handles underscores and stops at the
    /// first non-digit.
    #[test]
    fn hex_literal_parsing() {
        assert_eq!(first_hex_literal("X = 0x0003,"), Some(3));
        assert_eq!(first_hex_literal("Handle(0x4000_0001);"), Some(0x4000_0001));
        assert_eq!(first_hex_literal("pub const A: u32 = 5;"), None);
    }

    /// Aliases are paired with the literal of the following item, skipping
    /// further attributes.
    #[test]
    fn alias_parsing() {
        let src = "#[doc(alias = \"TPM_X_A\")]\n#[allow(foo)]\nA = 0x0001,\n\
                   #[doc(alias = \"TPM_X_B\")]\npub const B: u32 = 7;\n";
        assert_eq!(
            parse_aliased_constants(src),
            vec![("TPM_X_A".to_string(), 1)]
        );
    }

    /// Command names come from the `TPM_CC_*` aliases.
    #[test]
    fn command_names() {
        assert_eq!(command_name(0x131).as_deref(), Some("CreatePrimary"));
        assert_eq!(command_name(0x157).as_deref(), Some("Load"));
        assert_eq!(command_name(0xFFFF_FFFF), None);
    }
}
