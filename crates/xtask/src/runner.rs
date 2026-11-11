//! Orchestrates bare-metal Cargo builds, ELF section/symbol analysis, and step summary I/O.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::SizeArgs;
use crate::elf::{diff_symbols, first_nonempty_line, inspect_sections};
use crate::report::{
    BaseMeasurement, RowReport, TARGETS, WORKLOADS, Workload, check_fail_on_bytes, render_markdown,
};
use crate::vcs::{ResolvedTree, ScratchWorkspace};

const MAX_SYMBOL_DIFF_ROWS: usize = 20;

enum BaseState {
    Ready(ResolvedTree),
    MissingHarness { label: String, reason: String },
    Unavailable { label: String, reason: String },
}

impl BaseState {
    fn label(&self) -> &str {
        match self {
            Self::Ready(tree) => &tree.label,
            Self::MissingHarness { label, .. } | Self::Unavailable { label, .. } => label,
        }
    }
}

pub(crate) fn run_size(opts: &SizeArgs) -> Result<(), String> {
    let mut ws = ScratchWorkspace::new()?;
    let head = ws.checkout("head", &opts.head)?;

    let base_state = match ws.checkout("base", &opts.base) {
        Ok(tree) => {
            if tree.root.join("testing/size-harness/Cargo.toml").is_file() {
                BaseState::Ready(tree)
            } else {
                BaseState::MissingHarness {
                    reason: format!(
                        "`testing/size-harness` does not exist in base revision `{}`",
                        tree.label
                    ),
                    label: tree.label,
                }
            }
        }
        Err(reason) => BaseState::Unavailable {
            label: format!("{} (unavailable)", opts.base),
            reason,
        },
    };

    let elf_dir = ws.elf_dir().to_path_buf();
    let mut rows = Vec::with_capacity(TARGETS.len() * WORKLOADS.len());
    let mut build_idx = 0usize;

    for workload in WORKLOADS {
        for target in TARGETS {
            build_idx += 1;
            eprintln!(
                "[{build_idx}/{}] measuring {} ({}, {target})...",
                TARGETS.len() * WORKLOADS.len(),
                workload.bin,
                workload.profile_label,
            );

            // HEAD build & ELF inspection failures are always fatal (`exit 1`).
            let head_elf = build_harness_elf(&head, workload, target, &elf_dir, "head", build_idx)?;
            let head_sizes = inspect_sections(&head_elf)?;

            let base = match &base_state {
                BaseState::Ready(base_tree) => {
                    match build_harness_elf(
                        base_tree, workload, target, &elf_dir, "base", build_idx,
                    ) {
                        Ok(base_elf) => match inspect_sections(&base_elf) {
                            Ok(base_sizes) => {
                                let symbols =
                                    diff_symbols(&head_elf, &base_elf, MAX_SYMBOL_DIFF_ROWS)?;
                                BaseMeasurement::Measured {
                                    sizes: base_sizes,
                                    symbols,
                                }
                            }
                            Err(err) => BaseMeasurement::Unavailable { reason: err },
                        },
                        Err(err) => BaseMeasurement::Unavailable { reason: err },
                    }
                }
                BaseState::MissingHarness { reason, .. }
                | BaseState::Unavailable { reason, .. } => BaseMeasurement::Unavailable {
                    reason: reason.clone(),
                },
            };

            rows.push(RowReport {
                bin: workload.bin,
                profile: workload.profile_label,
                target,
                head: head_sizes,
                base,
            });
        }
    }

    let markdown = render_markdown(base_state.label(), &head.label, &rows);
    print!("{markdown}");

    if let Some(summary_path) = std::env::var_os("GITHUB_STEP_SUMMARY").filter(|v| !v.is_empty()) {
        append_step_summary(Path::new(&summary_path), &markdown)?;
    }

    if let Some(limit) = opts.fail_on_bytes {
        check_fail_on_bytes(&rows, limit)?;
    }
    Ok(())
}

fn build_harness_elf(
    tree: &ResolvedTree,
    workload: Workload,
    target: &str,
    elf_dir: &Path,
    slot: &str,
    idx: usize,
) -> Result<PathBuf, String> {
    let harness_dir = tree.root.join("testing/size-harness");
    let manifest_path = harness_dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Err(format!(
            "missing size harness manifest `{}`",
            manifest_path.display()
        ));
    }

    let cargo_bin = std::env::var_os("CARGO").unwrap_or_else(|| std::ffi::OsString::from("cargo"));
    let mut cmd = Command::new(cargo_bin);
    cmd.current_dir(&harness_dir);
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--target-dir")
        .arg(&tree.target_dir)
        .args(["--release", "--target", target, "--bin", workload.bin])
        .args([
            "--no-default-features",
            "--features",
            workload.cargo_features,
        ]);

    let config_path = harness_dir.join(".cargo/config.toml");
    if config_path.is_file() {
        cmd.arg("--config").arg(&config_path);
    }

    let output = cmd.output().map_err(|err| {
        format!(
            "failed to invoke cargo for `{}` ({target}): {err}",
            workload.bin
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if slot == "head" {
            return Err(format!(
                "HEAD build failed for `{}` (`{}`, `{target}`):\n{}",
                workload.bin,
                workload.profile_label,
                stderr.trim()
            ));
        }
        return Err(format!(
            "base build failed for `{}` (`{}`): {}",
            workload.bin,
            workload.profile_label,
            summarize_cargo_error(&stderr)
        ));
    }

    let built_elf = tree
        .target_dir
        .join(target)
        .join("release")
        .join(workload.bin);
    let saved_elf = elf_dir.join(format!(
        "{slot}-{idx:02}-{}-{}-{target}.elf",
        workload.bin, workload.profile_label
    ));
    fs::copy(&built_elf, &saved_elf).map_err(|err| {
        format!(
            "failed to copy built ELF `{}` to `{}`: {err}",
            built_elf.display(),
            saved_elf.display()
        )
    })?;
    Ok(saved_elf)
}

fn summarize_cargo_error(stderr: &str) -> &str {
    stderr
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("error"))
        .unwrap_or_else(|| first_nonempty_line(stderr))
}

fn append_step_summary(path: &Path, markdown: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| {
            format!(
                "failed to open GITHUB_STEP_SUMMARY `{}`: {err}",
                path.display()
            )
        })?;
    file.write_all(markdown.as_bytes()).map_err(|err| {
        format!(
            "failed to write GITHUB_STEP_SUMMARY `{}`: {err}",
            path.display()
        )
    })
}
