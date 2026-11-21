//! Matrix definition, threshold evaluation, and GitHub Markdown report formatter.

use std::fmt::Write as _;

use crate::elf::{SectionSizes, SymbolDelta};

/// Absolute growth threshold (`> 4 KiB`) that triggers a `⚠️` highlight and
/// auto-expanded symbol breakdown.
pub(crate) const WARN_ABS_BYTES: i64 = 4096;

/// Relative growth threshold (`> 5%`) that triggers a `⚠️` highlight and
/// auto-expanded symbol breakdown.
pub(crate) const WARN_PERCENT: i128 = 5;

/// Bare-metal target triples compiled for every harness workload.
pub(crate) const TARGETS: [&str; 3] = [
    "riscv32imac-unknown-none-elf",
    "thumbv7em-none-eabihf",
    "x86_64-unknown-none",
];

/// A single `(binary, feature profile)` workload built across [`TARGETS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Workload {
    pub(crate) bin: &'static str,
    pub(crate) profile_label: &'static str,
    pub(crate) cargo_features: &'static str,
}

pub(crate) const WORKLOADS: [Workload; 4] = [
    Workload {
        bin: "size-tpm2",
        profile_label: "v184",
        cargo_features: "v184",
    },
    Workload {
        bin: "size-tpm2",
        profile_label: "v185",
        cargo_features: "v185",
    },
    Workload {
        bin: "size-client",
        profile_label: "v185",
        cargo_features: "client",
    },
    Workload {
        bin: "size-server",
        profile_label: "v185",
        cargo_features: "server",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BaseMeasurement {
    Measured {
        sizes: SectionSizes,
        symbols: Vec<SymbolDelta>,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowStatus {
    Ok,
    Warn,
    New,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RowReport {
    pub(crate) bin: &'static str,
    pub(crate) profile: &'static str,
    pub(crate) target: &'static str,
    pub(crate) head: SectionSizes,
    pub(crate) base: BaseMeasurement,
}

impl RowReport {
    /// `(flash_delta, ram_delta)` in bytes (`head - base`), or `None` when `base` is `N/A`.
    pub(crate) fn deltas(&self) -> Option<(i64, i64)> {
        match &self.base {
            BaseMeasurement::Measured { sizes, .. } => Some((
                signed_diff(self.head.flash, sizes.flash),
                signed_diff(self.head.ram, sizes.ram),
            )),
            BaseMeasurement::Unavailable { .. } => None,
        }
    }

    pub(crate) fn status(&self) -> RowStatus {
        let BaseMeasurement::Measured { sizes: base, .. } = &self.base else {
            return RowStatus::New;
        };
        let flash_delta = signed_diff(self.head.flash, base.flash);
        let ram_delta = signed_diff(self.head.ram, base.ram);
        if is_regression_warn(base.flash, flash_delta) || is_regression_warn(base.ram, ram_delta) {
            RowStatus::Warn
        } else {
            RowStatus::Ok
        }
    }
}

pub(crate) fn signed_diff(head: u64, base: u64) -> i64 {
    let diff = i128::from(head) - i128::from(base);
    diff.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

/// Returns `true` when `delta_bytes > +4 KiB` or `delta_bytes > +5%` of a non-zero `base_bytes`.
pub(crate) fn is_regression_warn(base_bytes: u64, delta_bytes: i64) -> bool {
    if delta_bytes <= 0 {
        return false;
    }
    if delta_bytes > WARN_ABS_BYTES {
        return true;
    }
    base_bytes > 0 && i128::from(delta_bytes) * 100 > i128::from(base_bytes) * WARN_PERCENT
}

/// Checks whether any measured row's Flash or RAM growth exceeds `--fail-on-bytes`.
///
/// Missing (`Base: N/A`) rows never trigger failure so bootstrap and feature
/// additions remain unblocked.
pub(crate) fn check_fail_on_bytes(rows: &[RowReport], limit: u64) -> Result<(), String> {
    let limit_i128 = i128::from(limit);
    let mut offenders = Vec::new();
    for row in rows {
        let Some((flash_delta, ram_delta)) = row.deltas() else {
            continue;
        };
        if flash_delta > 0 && i128::from(flash_delta) > limit_i128 {
            offenders.push(format!(
                "{} ({}, {}) Flash: +{} B > {} B",
                row.bin,
                row.profile,
                row.target,
                format_u64(flash_delta as u64),
                format_u64(limit)
            ));
        }
        if ram_delta > 0 && i128::from(ram_delta) > limit_i128 {
            offenders.push(format!(
                "{} ({}, {}) RAM: +{} B > {} B",
                row.bin,
                row.profile,
                row.target,
                format_u64(ram_delta as u64),
                format_u64(limit)
            ));
        }
    }
    if offenders.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "binary size growth exceeded `--fail-on-bytes {limit}`:\n  - {}",
            offenders.join("\n  - ")
        ))
    }
}

/// Renders the complete GitHub-Flavored Markdown size summary.
pub(crate) fn render_markdown(base_label: &str, head_label: &str, rows: &[RowReport]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "## Freestanding Binary Size Report");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Comparing **head** `{head_label}` against **base** `{base_label}` (`opt-level = \"z\"`, `lto = true`, `codegen-units = 1`, `panic = \"abort\"`)."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Binary | Profile | Target | Flash (`.text`+`.rodata`+`.data`) | Flash Δ | RAM (`.data`+`.bss`) | RAM Δ | Status |"
    );
    let _ = writeln!(
        out,
        "| :--- | :--- | :--- | ---: | ---: | ---: | ---: | :--- |"
    );

    let mut unavailable_notes: Vec<String> = Vec::new();
    for row in rows {
        let (flash_delta_cell, ram_delta_cell) = match &row.base {
            BaseMeasurement::Measured { sizes: base, .. } => {
                let flash_delta = signed_diff(row.head.flash, base.flash);
                let ram_delta = signed_diff(row.head.ram, base.ram);
                (
                    format_delta_with_pct(flash_delta, base.flash),
                    format_delta_with_pct(ram_delta, base.ram),
                )
            }
            BaseMeasurement::Unavailable { reason } => {
                if !unavailable_notes.contains(reason) {
                    unavailable_notes.push(reason.clone());
                }
                (
                    String::from("Base: N/A (new)"),
                    String::from("Base: N/A (new)"),
                )
            }
        };
        let status_cell = match row.status() {
            RowStatus::Ok => "OK",
            RowStatus::Warn => "⚠️ >4 KiB / >5%",
            RowStatus::New => "new",
        };
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | {} B | {} | {} B | {} | {} |",
            row.bin,
            row.profile,
            row.target,
            format_u64(row.head.flash),
            flash_delta_cell,
            format_u64(row.head.ram),
            ram_delta_cell,
            status_cell,
        );
    }

    if !unavailable_notes.is_empty() {
        let _ = writeln!(out);
        for note in &unavailable_notes {
            let _ = writeln!(
                out,
                "> **Note (`Base: N/A`):** {}",
                sanitize_single_line(note)
            );
        }
    }

    for row in rows {
        let BaseMeasurement::Measured {
            sizes: base,
            symbols,
        } = &row.base
        else {
            continue;
        };
        let status = row.status();
        if symbols.is_empty() && status != RowStatus::Warn {
            continue;
        }
        let flash_delta = signed_diff(row.head.flash, base.flash);
        let ram_delta = signed_diff(row.head.ram, base.ram);
        let open_attr = if status == RowStatus::Warn {
            " open"
        } else {
            ""
        };
        let prefix = if status == RowStatus::Warn {
            "⚠️ "
        } else {
            ""
        };
        let _ = writeln!(out);
        let _ = writeln!(out, "<details{open_attr}>");
        let _ = writeln!(
            out,
            "<summary>{prefix}<code>{}</code> (<code>{}</code>, <code>{}</code>) — Flash {}, RAM {}</summary>",
            row.bin,
            row.profile,
            row.target,
            format_delta_with_pct(flash_delta, base.flash),
            format_delta_with_pct(ram_delta, base.ram),
        );
        let _ = writeln!(out);
        if symbols.is_empty() {
            let _ = writeln!(out, "_No individual symbol byte deltas reported._");
        } else {
            let _ = writeln!(out, "| Section | Symbol | Delta |");
            let _ = writeln!(out, "| :--- | :--- | ---: |");
            for sym in symbols {
                let _ = writeln!(
                    out,
                    "| `{}` | {} | {} |",
                    escape_gfm_table_code(&sym.section),
                    format_gfm_symbol_code(&sym.symbol),
                    format_signed_bytes(sym.delta_bytes),
                );
            }
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "</details>");
    }

    out
}

pub(crate) fn format_u64(val: u64) -> String {
    let digits = val.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (idx, ch) in digits.chars().enumerate() {
        if idx > 0 && (digits.len() - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn format_signed_bytes(delta: i64) -> String {
    if delta > 0 {
        format!("+{} B", format_u64(delta.unsigned_abs()))
    } else if delta < 0 {
        format!("-{} B", format_u64(delta.unsigned_abs()))
    } else {
        String::from("0 B")
    }
}

fn format_delta_with_pct(delta: i64, base_vm: u64) -> String {
    let bytes = format_signed_bytes(delta);
    if base_vm == 0 {
        if delta == 0 {
            String::from("0 B (0.0%)")
        } else {
            bytes
        }
    } else {
        // Compute tenths of a percent with integer arithmetic to stay locale-
        // and float-rounding-independent (`delta * 1000 / base`, rounded).
        let scaled = (i128::from(delta) * 1000
            + i128::from(base_vm) / 2 * i128::from(delta.signum()))
            / i128::from(base_vm);
        let abs_tenths = scaled.unsigned_abs();
        let whole = abs_tenths / 10;
        let frac = abs_tenths % 10;
        let sign = if delta > 0 {
            "+"
        } else if delta < 0 {
            "-"
        } else {
            ""
        };
        format!("{bytes} ({sign}{whole}.{frac}%)")
    }
}

fn sanitize_single_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("")
        .trim()
        .replace(['\r', '\n'], " ")
}

fn escape_gfm_table_code(text: &str) -> String {
    text.replace('|', "\\|").replace('`', "'")
}

fn format_gfm_symbol_code(symbol: &str) -> String {
    format!("`{}`", escape_gfm_table_code(symbol))
}
