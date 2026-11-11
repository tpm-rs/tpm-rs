//! Pure unit tests for `xtask` CLI parsing, ELF32/ELF64 parsing, and Markdown reporting.
//!
//! All tests avoid spawning subprocesses or touching outside paths so they run
//! cleanly under `cargo +nightly miri test`.

use crate::cli::{Command, SizeArgs, parse_args};
use crate::elf::{
    SectionKind, SectionSizes, SymbolDelta, canonical_section_name, classify_section,
    demangle_and_normalize_symbol, diff_elf_symbols, parse_elf_sections,
};
use crate::report::{
    BaseMeasurement, RowReport, RowStatus, check_fail_on_bytes, format_u64, is_regression_warn,
    render_markdown,
};
use crate::vcs::map_git_rev_to_jj;

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn cli_defaults() {
    assert_eq!(parse_args(&args(&[])).unwrap(), Command::Help);
    assert_eq!(parse_args(&args(&["--help"])).unwrap(), Command::Help);
    assert_eq!(parse_args(&args(&["size", "-h"])).unwrap(), Command::Help);

    assert_eq!(
        parse_args(&args(&["size"])).unwrap(),
        Command::Size(SizeArgs {
            base: String::from("HEAD^1"),
            head: String::from("HEAD"),
            fail_on_bytes: None,
        })
    );
}

#[test]
fn cli_explicit_flags_and_equals_syntax() {
    let parsed = parse_args(&args(&[
        "size",
        "--base",
        "origin/main",
        "--head=WORKDIR",
        "--fail-on-bytes=4096",
    ]))
    .unwrap();

    assert_eq!(
        parsed,
        Command::Size(SizeArgs {
            base: String::from("origin/main"),
            head: String::from("WORKDIR"),
            fail_on_bytes: Some(4096),
        })
    );
}

#[test]
fn cli_rejects_invalid_arguments() {
    assert!(parse_args(&args(&["unknown"])).is_err());
    assert!(parse_args(&args(&["size", "--bogus"])).is_err());
    assert!(parse_args(&args(&["size", "--base"])).is_err());
    assert!(parse_args(&args(&["size", "--head="])).is_err());
    assert!(parse_args(&args(&["size", "--fail-on-bytes", "-1"])).is_err());
    assert!(parse_args(&args(&["size", "--fail-on-bytes=abc"])).is_err());
}

#[test]
fn jj_revision_mapping() {
    assert_eq!(map_git_rev_to_jj("HEAD"), "@");
    assert_eq!(map_git_rev_to_jj("HEAD^1"), "@-");
    assert_eq!(map_git_rev_to_jj("HEAD~1"), "@-");
    assert_eq!(map_git_rev_to_jj("HEAD^"), "@-");
    assert_eq!(map_git_rev_to_jj("main"), "main");
}

#[test]
fn section_classification_separates_flash_ram_and_metadata() {
    assert_eq!(classify_section(".text"), Some(SectionKind::Flash));
    assert_eq!(classify_section(".text.startup"), Some(SectionKind::Flash));
    assert_eq!(classify_section(".rodata"), Some(SectionKind::Flash));
    assert_eq!(classify_section(".srodata.cst8"), Some(SectionKind::Flash));
    assert_eq!(classify_section(".data.rel.ro"), Some(SectionKind::Flash));
    assert_eq!(
        classify_section(".data.rel.ro.local"),
        Some(SectionKind::Flash)
    );

    assert_eq!(classify_section(".data"), Some(SectionKind::Ram));
    assert_eq!(classify_section(".sdata.foo"), Some(SectionKind::Ram));
    assert_eq!(classify_section(".bss"), Some(SectionKind::Ram));
    assert_eq!(classify_section(".sbss.bar"), Some(SectionKind::Ram));
    assert_eq!(classify_section(".tdata"), Some(SectionKind::Ram));
    assert_eq!(classify_section(".tbss"), Some(SectionKind::Ram));

    assert_eq!(classify_section(".eh_frame"), None);
    assert_eq!(classify_section(".ARM.exidx"), None);
    assert_eq!(classify_section(".relro_padding"), None);
    assert_eq!(classify_section(".symtab"), None);

    assert_eq!(canonical_section_name(".text.foo"), Some(".text"));
    assert_eq!(canonical_section_name(".srodata.cst4"), Some(".rodata"));
    assert_eq!(
        canonical_section_name(".data.rel.ro.local"),
        Some(".data.rel.ro")
    );
    assert_eq!(canonical_section_name(".sdata.bar"), Some(".data"));
    assert_eq!(canonical_section_name(".sbss.baz"), Some(".bss"));
    assert_eq!(canonical_section_name(".eh_frame"), None);
}

#[test]
fn symbol_demangling_strips_crate_disambiguators_and_normalizes_anon_labels() {
    // Rust v0 mangled symbol with crate disambiguator `Cs699aW27ccdS_`:
    // both disambiguators demangle via `{:#}` to identical human-readable paths.
    let v0_base = "_RNvCs699aW27ccdS_9size_tpm214measure_crypto";
    let v0_head = "_RNvCs11111111111_9size_tpm214measure_crypto";
    assert_eq!(
        demangle_and_normalize_symbol(v0_base),
        "size_tpm2::measure_crypto"
    );
    assert_eq!(
        demangle_and_normalize_symbol(v0_head),
        "size_tpm2::measure_crypto"
    );

    // Legacy mangled symbol with trailing `17h<hex>E` hash:
    let legacy = "_ZN4tpm26crypto4hash17h0123456789abcdefE";
    assert_eq!(demangle_and_normalize_symbol(legacy), "tpm2::crypto::hash");

    // Compiler anonymous constants and machine outliner labels:
    assert_eq!(
        demangle_and_normalize_symbol(".Lanon.0123456789abcdef.42"),
        "[compiler constants & jump tables]"
    );
    assert_eq!(
        demangle_and_normalize_symbol(".Lswitch.table.foo"),
        "[compiler constants & jump tables]"
    );
    assert_eq!(
        demangle_and_normalize_symbol("OUTLINED_FUNCTION_19"),
        "[compiler-outlined functions]"
    );
}

#[derive(Clone)]
struct SyntheticSection<'a> {
    name: &'a str,
    sh_type: u32,
    sh_flags: u64,
    sh_size: u64,
}

#[derive(Clone)]
struct SyntheticSymbol<'a> {
    name: &'a str,
    st_value: u64,
    st_size: u64,
    st_info: u8,
    st_shndx: u16,
}

fn push_cstr(buf: &mut Vec<u8>, s: &str) -> u32 {
    let offset = u32::try_from(buf.len()).unwrap();
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
    offset
}

fn build_synthetic_elf32_le(
    sections: &[SyntheticSection<'_>],
    symbols: &[SyntheticSymbol<'_>],
) -> Vec<u8> {
    let mut shstrtab = vec![0u8];
    let mut sh_names = Vec::with_capacity(sections.len());
    for sec in sections {
        sh_names.push(push_cstr(&mut shstrtab, sec.name));
    }
    let shstrtab_name = push_cstr(&mut shstrtab, ".shstrtab");
    let strtab_sec_name = push_cstr(&mut shstrtab, ".strtab");
    let symtab_sec_name = push_cstr(&mut shstrtab, ".symtab");

    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 16]; // Null symbol 0
    for sym in symbols {
        let st_name = push_cstr(&mut strtab, sym.name);
        symtab.extend_from_slice(&st_name.to_le_bytes());
        symtab.extend_from_slice(&(sym.st_value as u32).to_le_bytes());
        symtab.extend_from_slice(&(sym.st_size as u32).to_le_bytes());
        symtab.push(sym.st_info);
        symtab.push(0); // st_other
        symtab.extend_from_slice(&sym.st_shndx.to_le_bytes());
    }

    // Layout:
    // [0..52]: ELF32 header
    // [52..52+shstrtab.len()]: .shstrtab payload
    // [..+strtab.len()]: .strtab payload
    // [..+symtab.len()]: .symtab payload
    // [shoff..]: section headers:
    //   0: NULL
    //   1..=sections.len(): caller sections
    //   sections.len() + 1: .shstrtab
    //   sections.len() + 2: .strtab
    //   sections.len() + 3: .symtab
    let mut bytes = vec![0u8; 52];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 1; // ELFCLASS32
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT

    let shstrtab_off = bytes.len() as u32;
    bytes.extend_from_slice(&shstrtab);
    let strtab_off = bytes.len() as u32;
    bytes.extend_from_slice(&strtab);
    let symtab_off = bytes.len() as u32;
    bytes.extend_from_slice(&symtab);

    let shoff = bytes.len() as u32;
    let shstrndx = (sections.len() + 1) as u16;
    let strtab_ndx = (sections.len() + 2) as u32;
    let total_sections = (sections.len() + 4) as u16;

    bytes[32..36].copy_from_slice(&shoff.to_le_bytes()); // e_shoff
    bytes[46..48].copy_from_slice(&40u16.to_le_bytes()); // e_shentsize
    bytes[48..50].copy_from_slice(&total_sections.to_le_bytes()); // e_shnum
    bytes[50..52].copy_from_slice(&shstrndx.to_le_bytes()); // e_shstrndx

    let push_shdr32 = |out: &mut Vec<u8>,
                       sh_name: u32,
                       sh_type: u32,
                       sh_flags: u32,
                       sh_offset: u32,
                       sh_size: u32,
                       sh_link: u32,
                       sh_entsize: u32| {
        let start = out.len();
        out.resize(start + 40, 0);
        out[start..start + 4].copy_from_slice(&sh_name.to_le_bytes());
        out[start + 4..start + 8].copy_from_slice(&sh_type.to_le_bytes());
        out[start + 8..start + 12].copy_from_slice(&sh_flags.to_le_bytes());
        out[start + 16..start + 20].copy_from_slice(&sh_offset.to_le_bytes());
        out[start + 20..start + 24].copy_from_slice(&sh_size.to_le_bytes());
        out[start + 24..start + 28].copy_from_slice(&sh_link.to_le_bytes());
        out[start + 36..start + 40].copy_from_slice(&sh_entsize.to_le_bytes());
    };

    // 0: NULL section
    push_shdr32(&mut bytes, 0, 0, 0, 0, 0, 0, 0);
    // 1..=N: caller sections (size-only metadata; sh_offset = 0)
    for (sec, &sh_name) in sections.iter().zip(&sh_names) {
        push_shdr32(
            &mut bytes,
            sh_name,
            sec.sh_type,
            sec.sh_flags as u32,
            0,
            sec.sh_size as u32,
            0,
            0,
        );
    }
    // .shstrtab (SHT_STRTAB = 3)
    push_shdr32(
        &mut bytes,
        shstrtab_name,
        3,
        0,
        shstrtab_off,
        shstrtab.len() as u32,
        0,
        0,
    );
    // .strtab (SHT_STRTAB = 3)
    push_shdr32(
        &mut bytes,
        strtab_sec_name,
        3,
        0,
        strtab_off,
        strtab.len() as u32,
        0,
        0,
    );
    // .symtab (SHT_SYMTAB = 2)
    push_shdr32(
        &mut bytes,
        symtab_sec_name,
        2,
        0,
        symtab_off,
        symtab.len() as u32,
        strtab_ndx,
        16,
    );

    bytes
}

fn build_synthetic_elf64_le(sections: &[SyntheticSection<'_>]) -> Vec<u8> {
    let mut shstrtab = vec![0u8];
    let mut sh_names = Vec::with_capacity(sections.len());
    for sec in sections {
        sh_names.push(push_cstr(&mut shstrtab, sec.name));
    }
    let shstrtab_name = push_cstr(&mut shstrtab, ".shstrtab");

    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT

    let shstrtab_off = bytes.len() as u64;
    bytes.extend_from_slice(&shstrtab);
    let shoff = bytes.len() as u64;
    let shstrndx = (sections.len() + 1) as u16;
    let total_sections = (sections.len() + 2) as u16;

    bytes[40..48].copy_from_slice(&shoff.to_le_bytes()); // e_shoff
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    bytes[60..62].copy_from_slice(&total_sections.to_le_bytes()); // e_shnum
    bytes[62..64].copy_from_slice(&shstrndx.to_le_bytes()); // e_shstrndx

    let push_shdr64 = |out: &mut Vec<u8>,
                       sh_name: u32,
                       sh_type: u32,
                       sh_flags: u64,
                       sh_offset: u64,
                       sh_size: u64| {
        let start = out.len();
        out.resize(start + 64, 0);
        out[start..start + 4].copy_from_slice(&sh_name.to_le_bytes());
        out[start + 4..start + 8].copy_from_slice(&sh_type.to_le_bytes());
        out[start + 8..start + 16].copy_from_slice(&sh_flags.to_le_bytes());
        out[start + 24..start + 32].copy_from_slice(&sh_offset.to_le_bytes());
        out[start + 32..start + 40].copy_from_slice(&sh_size.to_le_bytes());
    };

    push_shdr64(&mut bytes, 0, 0, 0, 0, 0);
    for (sec, &sh_name) in sections.iter().zip(&sh_names) {
        push_shdr64(
            &mut bytes,
            sh_name,
            sec.sh_type,
            sec.sh_flags,
            0,
            sec.sh_size,
        );
    }
    push_shdr64(
        &mut bytes,
        shstrtab_name,
        3,
        0,
        shstrtab_off,
        shstrtab.len() as u64,
    );
    bytes
}

#[test]
fn elf32_and_elf64_section_totals_sum_only_allocatable_flash_and_ram() {
    let sections = [
        // 1: .text (SHF_ALLOC = 0x2)
        SyntheticSection {
            name: ".text",
            sh_type: 1,
            sh_flags: 0x6,
            sh_size: 40_040,
        },
        // 2: .eh_frame (SHF_ALLOC = 0x2, but excluded by classify_section)
        SyntheticSection {
            name: ".eh_frame",
            sh_type: 1,
            sh_flags: 0x2,
            sh_size: 8_624,
        },
        // 3: .rodata
        SyntheticSection {
            name: ".rodata",
            sh_type: 1,
            sh_flags: 0x2,
            sh_size: 1_140,
        },
        // 4: .srodata.cst4
        SyntheticSection {
            name: ".srodata.cst4",
            sh_type: 1,
            sh_flags: 0x2,
            sh_size: 20,
        },
        // 5: .data
        SyntheticSection {
            name: ".data",
            sh_type: 1,
            sh_flags: 0x3,
            sh_size: 32,
        },
        // 6: .bss (SHT_NOBITS = 8, SHF_ALLOC = 0x2)
        SyntheticSection {
            name: ".bss",
            sh_type: 8,
            sh_flags: 0x3,
            sh_size: 128,
        },
        // 7: Non-allocatable section with .text prefix (ignored because !SHF_ALLOC)
        SyntheticSection {
            name: ".text.debug_ignored",
            sh_type: 1,
            sh_flags: 0,
            sh_size: 9_999,
        },
    ];

    let elf32 = build_synthetic_elf32_le(&sections, &[]);
    let sizes32 = parse_elf_sections(&elf32).unwrap();
    assert_eq!(
        sizes32,
        SectionSizes {
            flash_vm: 41_200,
            ram_vm: 160,
        }
    );
    assert_eq!(sizes32.total_vm(), 41_360);

    let elf64 = build_synthetic_elf64_le(&sections);
    let sizes64 = parse_elf_sections(&elf64).unwrap();
    assert_eq!(sizes64, sizes32);

    assert!(parse_elf_sections(b"not an elf").is_err());
}

#[test]
fn elf_symbol_diff_demangles_deduplicates_thumb_aliases_and_accounts_remainders() {
    let base_sections = [
        // shndx 1: .text
        SyntheticSection {
            name: ".text",
            sh_type: 1,
            sh_flags: 0x6,
            sh_size: 1_868,
        },
        // shndx 2: .rodata (12 B .Lanon + 14 B .Lswitch.table = 26 B remainder)
        SyntheticSection {
            name: ".rodata",
            sh_type: 1,
            sh_flags: 0x2,
            sh_size: 26,
        },
        // shndx 3: .bss
        SyntheticSection {
            name: ".bss",
            sh_type: 8,
            sh_flags: 0x3,
            sh_size: 0,
        },
        // shndx 4: .eh_frame
        SyntheticSection {
            name: ".eh_frame",
            sh_type: 1,
            sh_flags: 0x2,
            sh_size: 100,
        },
    ];
    let base_symbols = [
        SyntheticSymbol {
            name: "_RNvCs699aW27ccdS_9size_tpm214measure_crypto",
            st_value: 0x1001, // Thumb bit 0 set
            st_size: 886,
            st_info: 0x12, // STB_GLOBAL | STT_FUNC
            st_shndx: 1,
        },
        // Duplicate alias at the same address (without Thumb bit 0) should be deduplicated:
        SyntheticSymbol {
            name: "_RNvCs699aW27ccdS_9size_tpm214measure_crypto",
            st_value: 0x1000,
            st_size: 886,
            st_info: 0x12,
            st_shndx: 1,
        },
        SyntheticSymbol {
            name: "_ZN4tpm210TpmtPublic7marshal17h1111111111111111E",
            st_value: 0x2000,
            st_size: 982,
            st_info: 0x12,
            st_shndx: 1,
        },
        SyntheticSymbol {
            name: ".Lanon.oldhash.1",
            st_value: 0x3000,
            st_size: 12,
            st_info: 0x01, // STT_OBJECT
            st_shndx: 2,
        },
        SyntheticSymbol {
            name: ".Lswitch.table.old",
            st_value: 0x3010,
            st_size: 14,
            st_info: 0x01,
            st_shndx: 2,
        },
    ];

    let head_sections = [
        // shndx 1: .text (432 + 1280 = 1712)
        SyntheticSection {
            name: ".text",
            sh_type: 1,
            sh_flags: 0x6,
            sh_size: 1_712,
        },
        // shndx 2: .rodata (12 B .Lanon + 22 B .Lswitch.table = 34 B remainder -> +8 B)
        SyntheticSection {
            name: ".rodata",
            sh_type: 1,
            sh_flags: 0x2,
            sh_size: 34,
        },
        // shndx 3: .bss (64 B GLOBAL_STATE)
        SyntheticSection {
            name: ".bss",
            sh_type: 8,
            sh_flags: 0x3,
            sh_size: 64,
        },
        // shndx 4: .eh_frame
        SyntheticSection {
            name: ".eh_frame",
            sh_type: 1,
            sh_flags: 0x2,
            sh_size: 176,
        },
    ];
    let head_symbols = [
        // Different crate disambiguator in head, still matches `size_tpm2::measure_crypto`!
        SyntheticSymbol {
            name: "_RNvCs99999999999_9size_tpm214measure_crypto",
            st_value: 0x1001,
            st_size: 432, // -454 B
            st_info: 0x12,
            st_shndx: 1,
        },
        SyntheticSymbol {
            name: "_ZN4tpm210TpmtPublic7marshal17h2222222222222222E",
            st_value: 0x2000,
            st_size: 1_280, // +298 B
            st_info: 0x12,
            st_shndx: 1,
        },
        SyntheticSymbol {
            name: ".Lanon.newhash.1",
            st_value: 0x3000,
            st_size: 12,
            st_info: 0x01,
            st_shndx: 2,
        },
        SyntheticSymbol {
            name: ".Lswitch.table.new",
            st_value: 0x3010,
            st_size: 22,
            st_info: 0x01,
            st_shndx: 2,
        },
        SyntheticSymbol {
            name: "GLOBAL_STATE",
            st_value: 0x4000,
            st_size: 64, // +64 B
            st_info: 0x11,
            st_shndx: 3,
        },
        // Ignored because it belongs to .eh_frame (shndx 4):
        SyntheticSymbol {
            name: "eh_frame_sym",
            st_value: 0x5000,
            st_size: 76,
            st_info: 0x01,
            st_shndx: 4,
        },
    ];

    let base_elf = build_synthetic_elf32_le(&base_sections, &base_symbols);
    let head_elf = build_synthetic_elf32_le(&head_sections, &head_symbols);

    let deltas = diff_elf_symbols(&head_elf, &base_elf, 10).unwrap();
    assert_eq!(
        deltas,
        vec![
            SymbolDelta {
                section: String::from(".text"),
                symbol: String::from("size_tpm2::measure_crypto"),
                delta_vm: -454,
            },
            SymbolDelta {
                section: String::from(".text"),
                symbol: String::from("tpm2::TpmtPublic::marshal"),
                delta_vm: 298,
            },
            SymbolDelta {
                section: String::from(".bss"),
                symbol: String::from("GLOBAL_STATE"),
                delta_vm: 64,
            },
            SymbolDelta {
                section: String::from(".rodata"),
                symbol: String::from("[compiler constants & jump tables]"),
                delta_vm: 8,
            },
        ]
    );

    let top1 = diff_elf_symbols(&head_elf, &base_elf, 1).unwrap();
    assert_eq!(top1.len(), 1);
    assert_eq!(top1[0].symbol, "size_tpm2::measure_crypto");
}

#[test]
fn regression_thresholds_match_4kib_and_5pct_spec() {
    // Exact +4096 B on a 200 KiB base (2.0%) is OK; +4097 B warns.
    assert!(!is_regression_warn(200_000, 4096));
    assert!(is_regression_warn(200_000, 4097));

    // Exact +5.0% (+50 B on 1000 B) is OK; +51 B (5.1%) warns.
    assert!(!is_regression_warn(1000, 50));
    assert!(is_regression_warn(1000, 51));

    // Shrinkage and zero delta never warn.
    assert!(!is_regression_warn(1000, 0));
    assert!(!is_regression_warn(1000, -8192));
}

#[test]
fn markdown_rendering_and_fail_on_bytes() {
    let rows = vec![
        RowReport {
            bin: "size-tpm2",
            profile: "v184",
            target: "riscv32imac-unknown-none-elf",
            head: SectionSizes {
                flash_vm: 46_000,
                ram_vm: 0,
            },
            base: BaseMeasurement::Measured {
                sizes: SectionSizes {
                    flash_vm: 40_000,
                    ram_vm: 0,
                },
                symbols: vec![SymbolDelta {
                    section: String::from(".text"),
                    symbol: String::from("closure_like(|x| x + 1)"),
                    delta_vm: 6000,
                }],
            },
        },
        RowReport {
            bin: "size-client",
            profile: "v185",
            target: "thumbv7em-none-eabihf",
            head: SectionSizes {
                flash_vm: 11_320,
                ram_vm: 16,
            },
            base: BaseMeasurement::Measured {
                sizes: SectionSizes {
                    flash_vm: 11_300,
                    ram_vm: 16,
                },
                symbols: vec![SymbolDelta {
                    section: String::from(".text"),
                    symbol: String::from("tpm2_client::run_command"),
                    delta_vm: 20,
                }],
            },
        },
        RowReport {
            bin: "size-server",
            profile: "v185",
            target: "x86_64-unknown-none",
            head: SectionSizes {
                flash_vm: 1600,
                ram_vm: 0,
            },
            base: BaseMeasurement::Unavailable {
                reason: String::from("`testing/size-harness` does not exist in base"),
            },
        },
    ];

    assert_eq!(rows[0].status(), RowStatus::Warn);
    assert_eq!(rows[1].status(), RowStatus::Ok);
    assert_eq!(rows[2].status(), RowStatus::New);

    let md = render_markdown("HEAD^1 (a67053cc6fc3)", "HEAD (deadbeefcafe)", &rows);
    assert!(md.contains("| `size-tpm2` | `v184` | `riscv32imac-unknown-none-elf` | 46,000 B | 0 B | 46,000 B | +6,000 B (+15.0%) | ⚠️ >4 KiB / >5% |"));
    assert!(md.contains("<details open>"));
    assert!(md.contains("<details>\n<summary><code>size-client</code>"));
    assert!(md.contains("`closure_like(\\|x\\| x + 1)`"));
    assert!(md.contains("Base: N/A (new)"));
    assert!(md.contains("`testing/size-harness` does not exist in base"));

    assert!(check_fail_on_bytes(&rows, 6000).is_ok());
    assert!(check_fail_on_bytes(&rows, 5999).is_err());
    assert_eq!(format_u64(0), "0");
    assert_eq!(format_u64(999), "999");
    assert_eq!(format_u64(1_234_567), "1,234,567");
}
