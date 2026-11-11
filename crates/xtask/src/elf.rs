//! Pure-Rust ELF32/ELF64 section and `.symtab` analyzer for `cargo xtask size`.
//!
//! Parses freestanding bare-metal ELF binaries (`riscv32imac-unknown-none-elf`,
//! `thumbv7em-none-eabihf`, and `x86_64-unknown-none`) directly in-process
//! without external C++ tooling, matching `SHF_ALLOC` Flash
//! (`.text` + `.rodata` + `.data`) and RAM (`.data` + `.bss`) section totals and
//! computing demangled per-symbol diffs across revisions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::report::signed_diff;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

pub(crate) const EM_ARM: u16 = 40;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHF_ALLOC: u64 = 0x2;
const SHN_LORESERVE: u16 = 0xff00;
const SHN_XINDEX: u16 = 0xffff;

const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;

/// Aggregate Flash and RAM sizes (in bytes) extracted from an ELF binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SectionSizes {
    /// Non-volatile Flash bytes (`.text`, `.rodata`, `.srodata`, `.data.rel.ro`, plus `.data`/`.sdata` initializers).
    pub(crate) flash: u64,
    /// Volatile SRAM bytes (`.data`, `.sdata`, `.bss`, `.sbss`).
    pub(crate) ram: u64,
}

/// Classification of an ELF section for embedded footprint accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionKind {
    FlashOnly,
    FlashAndRam,
    RamOnly,
}

/// Per-symbol size delta (in bytes) between a `base` and `head` ELF binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SymbolDelta {
    pub(crate) section: String,
    pub(crate) symbol: String,
    pub(crate) delta_bytes: i64,
}

struct SectionRule {
    prefix: &'static str,
    canonical: &'static str,
    kind: SectionKind,
}

/// Standard ELF and target-ABI section prefixes emitted by `rustc` / `rust-lld`
/// when linking freestanding `#![no_std]` binaries without a custom linker script.
///
/// Ordered from most-specific prefix (`.data.rel.ro`) to general (`.data`).
const SECTION_RULES: &[SectionRule] = &[
    // Executable code and `-ffunction-sections` subsections (`.text.<sym>`);
    // on ARM Cortex-M (`thumbv7em`), LLVM also embeds PC-relative literal pools in `.text`.
    SectionRule {
        prefix: ".text",
        canonical: ".text",
        kind: SectionKind::FlashOnly,
    },
    // System V ELF RELRO tables (e.g., relocated vtables on `x86_64-unknown-none`);
    // precedes `.data` so `.data.rel.ro` is not matched as mutable `.data`.
    SectionRule {
        prefix: ".data.rel.ro",
        canonical: ".data.rel.ro",
        kind: SectionKind::FlashOnly,
    },
    // Standard ELF read-only constants and mergeable constant pools (`.rodata.cst*`).
    SectionRule {
        prefix: ".rodata",
        canonical: ".rodata",
        kind: SectionKind::FlashOnly,
    },
    // RISC-V psABI `gp`-relative small read-only data (`riscv32imac-unknown-none-elf`).
    SectionRule {
        prefix: ".srodata",
        canonical: ".rodata",
        kind: SectionKind::FlashOnly,
    },
    // Non-zero initialized mutable statics (initializers in Flash, runtime copy in RAM).
    SectionRule {
        prefix: ".data",
        canonical: ".data",
        kind: SectionKind::FlashAndRam,
    },
    // RISC-V psABI `gp`-relative small initialized mutable data.
    SectionRule {
        prefix: ".sdata",
        canonical: ".data",
        kind: SectionKind::FlashAndRam,
    },
    // Zero-initialized mutable statics (`SHT_NOBITS`).
    SectionRule {
        prefix: ".bss",
        canonical: ".bss",
        kind: SectionKind::RamOnly,
    },
    // RISC-V psABI `gp`-relative small zero-initialized mutable data.
    SectionRule {
        prefix: ".sbss",
        canonical: ".bss",
        kind: SectionKind::RamOnly,
    },
];

fn lookup_section_rule(section: &str) -> Option<&'static SectionRule> {
    SECTION_RULES
        .iter()
        .find(|rule| matches_prefix(section, rule.prefix))
}

/// Classifies an ELF section name into Flash (ROM) and/or RAM (SRAM), ignoring
/// non-firmware metadata, ELF loader headers, unwind tables, and alignment padding.
pub(crate) fn classify_section(section: &str) -> Option<SectionKind> {
    lookup_section_rule(section).map(|rule| rule.kind)
}

/// Maps subsections (such as `.text.foo` or `.rodata.cst4`) to their canonical
/// parent section name for symbol diff grouping.
pub(crate) fn canonical_section_name(section: &str) -> Option<&'static str> {
    lookup_section_rule(section).map(|rule| rule.canonical)
}

fn matches_prefix(section: &str, base: &str) -> bool {
    section == base
        || section
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Reads an ELF file from disk and returns its allocatable Flash and RAM totals.
pub(crate) fn inspect_sections(elf_path: &Path) -> Result<SectionSizes, String> {
    let bytes = fs::read(elf_path)
        .map_err(|err| format!("failed to read ELF `{}`: {err}", elf_path.display()))?;
    parse_elf_sections(&bytes).map_err(|err| format!("invalid ELF `{}`: {err}", elf_path.display()))
}

/// Reads `head` and `base` ELF files from disk and returns the top `max_rows`
/// Flash/RAM symbol deltas sorted by descending absolute byte change.
pub(crate) fn diff_symbols(
    head_elf: &Path,
    base_elf: &Path,
    max_rows: usize,
) -> Result<Vec<SymbolDelta>, String> {
    let head_bytes = fs::read(head_elf)
        .map_err(|err| format!("failed to read ELF `{}`: {err}", head_elf.display()))?;
    let base_bytes = fs::read(base_elf)
        .map_err(|err| format!("failed to read ELF `{}`: {err}", base_elf.display()))?;
    diff_elf_symbols(&head_bytes, &base_bytes, max_rows).map_err(|err| {
        format!(
            "symbol diff failed for `{}` vs `{}`: {err}",
            head_elf.display(),
            base_elf.display()
        )
    })
}

/// Parses an ELF binary buffer and sums `sh_size` across allocatable Flash/RAM sections.
pub(crate) fn parse_elf_sections(bytes: &[u8]) -> Result<SectionSizes, String> {
    let parsed = ParsedElf::parse(bytes)?;
    let mut totals = SectionSizes::default();
    for sec in &parsed.sections {
        if sec.sh_flags & SHF_ALLOC == 0 {
            continue;
        }
        match classify_section(&sec.name) {
            Some(SectionKind::FlashOnly) => {
                totals.flash = totals.flash.saturating_add(sec.sh_size);
            }
            Some(SectionKind::FlashAndRam) => {
                totals.flash = totals.flash.saturating_add(sec.sh_size);
                totals.ram = totals.ram.saturating_add(sec.sh_size);
            }
            Some(SectionKind::RamOnly) => {
                totals.ram = totals.ram.saturating_add(sec.sh_size);
            }
            None => {}
        }
    }
    Ok(totals)
}

/// Computes per-symbol byte deltas (`head - base`) between two ELF buffers.
pub(crate) fn diff_elf_symbols(
    head_bytes: &[u8],
    base_bytes: &[u8],
    max_rows: usize,
) -> Result<Vec<SymbolDelta>, String> {
    let head_map = extract_elf_symbol_sizes(head_bytes)?;
    let base_map = extract_elf_symbol_sizes(base_bytes)?;

    let mut keys: BTreeSet<(String, String)> = head_map.keys().cloned().collect();
    keys.extend(base_map.keys().cloned());

    let mut deltas = Vec::new();
    for key in keys {
        let head_sz = head_map.get(&key).copied().unwrap_or(0);
        let base_sz = base_map.get(&key).copied().unwrap_or(0);
        let delta_bytes = signed_diff(head_sz, base_sz);
        if delta_bytes != 0 {
            deltas.push(SymbolDelta {
                section: key.0,
                symbol: key.1,
                delta_bytes,
            });
        }
    }

    deltas.sort_by(|a, b| {
        b.delta_bytes
            .unsigned_abs()
            .cmp(&a.delta_bytes.unsigned_abs())
            .then_with(|| a.section.cmp(&b.section))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });
    deltas.truncate(max_rows);
    Ok(deltas)
}

/// Demangles a symbol name and normalizes compiler-generated anonymous labels,
/// machine-outlined helpers, and numeric clone/static suffixes (`.0`, `.1`) so
/// sequential renumbering does not create diff noise.
pub(crate) fn demangle_and_normalize_symbol(raw: &str) -> String {
    if is_compiler_anon_label(raw) {
        return String::from("[compiler constants & jump tables]");
    }
    if raw.starts_with("OUTLINED_FUNCTION_") {
        return String::from("[compiler-outlined functions]");
    }
    let demangled = format!("{:#}", rustc_demangle::demangle(raw));
    strip_numeric_clone_suffix(&demangled).to_owned()
}

fn strip_numeric_clone_suffix(mut sym: &str) -> &str {
    while let Some((stem, suffix)) = sym.rsplit_once('.') {
        if !stem.is_empty() && !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
            sym = stem;
        } else {
            break;
        }
    }
    sym
}

fn is_compiler_anon_label(sym: &str) -> bool {
    sym.starts_with(".Lanon.")
        || sym.starts_with("anon.")
        || sym.starts_with(".Lswitch.table.")
        || sym.starts_with(".L__unnamed_")
        || sym.starts_with(".Lstr.")
        || sym.starts_with("str.")
        || sym.starts_with(".LBB")
        || sym.starts_with(".LBE")
        || sym.starts_with(".Ltmp")
        || sym.starts_with(".LCPI")
}

fn is_arch_mapping_symbol(sym: &str) -> bool {
    sym.starts_with("$x") || sym.starts_with("$d") || sym.starts_with("$t") || sym.starts_with("$a")
}

struct SectionSymCandidate {
    addr: u64,
    size: u64,
    demangled: String,
}

fn extract_elf_symbol_sizes(bytes: &[u8]) -> Result<BTreeMap<(String, String), u64>, String> {
    let parsed = ParsedElf::parse(bytes)?;

    let mut section_totals: BTreeMap<String, u64> = BTreeMap::new();
    for sec in &parsed.sections {
        if sec.sh_flags & SHF_ALLOC == 0 {
            continue;
        }
        if let Some(canon) = canonical_section_name(&sec.name) {
            let entry = section_totals.entry(String::from(canon)).or_insert(0);
            *entry = entry.saturating_add(sec.sh_size);
        }
    }

    let mut per_section_candidates: BTreeMap<usize, (&'static str, Vec<SectionSymCandidate>)> =
        BTreeMap::new();

    for sec in &parsed.sections {
        if sec.sh_type != SHT_SYMTAB {
            continue;
        }
        let strtab_idx = usize::try_from(sec.sh_link)
            .map_err(|_| String::from("ELF SHT_SYMTAB sh_link overflows usize"))?;
        let strtab_sec = parsed.sections.get(strtab_idx).ok_or_else(|| {
            format!(
                "ELF SHT_SYMTAB sh_link {} out of range (num sections: {})",
                sec.sh_link,
                parsed.sections.len()
            )
        })?;
        if strtab_sec.sh_type != SHT_STRTAB {
            return Err(format!(
                "ELF section {} linked by SHT_SYMTAB is not SHT_STRTAB",
                sec.sh_link
            ));
        }
        let strtab_bytes = parsed.section_slice(strtab_sec)?;
        let symtab_bytes = parsed.section_slice(sec)?;
        let expected_entsize: usize = match parsed.class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        };
        let entsize = if sec.sh_entsize == 0 {
            expected_entsize
        } else {
            usize::try_from(sec.sh_entsize)
                .map_err(|_| String::from("ELF SHT_SYMTAB sh_entsize overflows usize"))?
        };
        if entsize < expected_entsize || !symtab_bytes.len().is_multiple_of(entsize) {
            return Err(format!(
                "malformed SHT_SYMTAB size {} for entry size {entsize}",
                symtab_bytes.len()
            ));
        }

        for entry in symtab_bytes.chunks_exact(entsize) {
            let sym = parsed.parse_sym(entry)?;
            if sym.st_size == 0 || sym.st_shndx == 0 || sym.st_shndx >= SHN_LORESERVE {
                continue;
            }
            let st_type = sym.st_info & 0x0f;
            if st_type == STT_SECTION || st_type == STT_FILE {
                continue;
            }
            let shndx = usize::from(sym.st_shndx);
            let Some(target_sec) = parsed.sections.get(shndx) else {
                continue;
            };
            if target_sec.sh_flags & SHF_ALLOC == 0 {
                continue;
            }
            let Some(canon_sec) = canonical_section_name(&target_sec.name) else {
                continue;
            };
            let raw_name = read_c_string(strtab_bytes, sym.st_name)?;
            if raw_name.is_empty()
                || is_arch_mapping_symbol(raw_name)
                || is_compiler_anon_label(raw_name)
            {
                // Leave anonymous constant/jump-table bytes in the section's
                // unattributed remainder so they fold cleanly into
                // `[compiler constants & jump tables]`.
                continue;
            }

            // Strip ARM Thumb ISA indicator bit 0 on function symbols (`AAELF32` §5.5.3).
            // Gated to `EM_ARM` so 1-byte-aligned functions at odd addresses on
            // architectures such as `x86_64` (`opt-level = "z"`) are preserved verbatim.
            let norm_addr = if parsed.e_machine == EM_ARM && st_type == STT_FUNC {
                sym.st_value & !1
            } else {
                sym.st_value
            };

            let demangled = demangle_and_normalize_symbol(raw_name);
            per_section_candidates
                .entry(shndx)
                .or_insert_with(|| (canon_sec, Vec::new()))
                .1
                .push(SectionSymCandidate {
                    addr: norm_addr,
                    size: sym.st_size,
                    demangled,
                });
        }
    }

    let mut symbol_sizes: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut named_section_sums: BTreeMap<String, u64> = BTreeMap::new();

    for (_shndx, (canon_sec, mut candidates)) in per_section_candidates {
        // Order by ascending address, then descending span size so outer symbols
        // claim their full span before nested labels, then name for deterministic
        // attribution across identical-address aliases (e.g., ICF).
        candidates.sort_by(|a, b| {
            a.addr
                .cmp(&b.addr)
                .then_with(|| b.size.cmp(&a.size))
                .then_with(|| a.demangled.cmp(&b.demangled))
        });

        let mut cursor: u64 = 0;
        for cand in candidates {
            let end = cand.addr.saturating_add(cand.size);
            let eff_start = cand.addr.max(cursor);
            let attributed = end.saturating_sub(eff_start);
            if attributed == 0 {
                continue;
            }
            cursor = cursor.max(end);

            let key = (String::from(canon_sec), cand.demangled);
            let sym_entry = symbol_sizes.entry(key).or_insert(0);
            *sym_entry = sym_entry.saturating_add(attributed);

            let sec_sum = named_section_sums
                .entry(String::from(canon_sec))
                .or_insert(0);
            *sec_sum = sec_sum.saturating_add(attributed);
        }
    }

    for (canon_sec, total_size) in section_totals {
        let named_sum = named_section_sums.get(&canon_sec).copied().unwrap_or(0);
        let remainder = total_size.saturating_sub(named_sum);
        if remainder > 0 {
            let key = (
                canon_sec,
                String::from("[compiler constants & jump tables]"),
            );
            let entry = symbol_sizes.entry(key).or_insert(0);
            *entry = entry.saturating_add(remainder);
        }
    }

    Ok(symbol_sizes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn read_u16(self, bytes: &[u8], offset: usize) -> Result<u16, String> {
        let slice = bytes
            .get(offset..offset.saturating_add(2))
            .ok_or_else(|| format!("unexpected EOF reading u16 at offset {offset}"))?;
        let arr: [u8; 2] = [slice[0], slice[1]];
        Ok(match self {
            Self::Little => u16::from_le_bytes(arr),
            Self::Big => u16::from_be_bytes(arr),
        })
    }

    fn read_u32(self, bytes: &[u8], offset: usize) -> Result<u32, String> {
        let slice = bytes
            .get(offset..offset.saturating_add(4))
            .ok_or_else(|| format!("unexpected EOF reading u32 at offset {offset}"))?;
        let arr: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
        Ok(match self {
            Self::Little => u32::from_le_bytes(arr),
            Self::Big => u32::from_be_bytes(arr),
        })
    }

    fn read_u64(self, bytes: &[u8], offset: usize) -> Result<u64, String> {
        let slice = bytes
            .get(offset..offset.saturating_add(8))
            .ok_or_else(|| format!("unexpected EOF reading u64 at offset {offset}"))?;
        let arr: [u8; 8] = [
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ];
        Ok(match self {
            Self::Little => u64::from_le_bytes(arr),
            Self::Big => u64::from_be_bytes(arr),
        })
    }
}

#[derive(Debug, Clone)]
struct SectionHeader {
    name: String,
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

#[derive(Debug, Clone, Copy)]
struct SymEntry {
    st_name: u32,
    st_value: u64,
    st_size: u64,
    st_info: u8,
    st_shndx: u16,
}

struct ParsedElf<'a> {
    bytes: &'a [u8],
    class: ElfClass,
    endian: Endian,
    e_machine: u16,
    sections: Vec<SectionHeader>,
}

impl<'a> ParsedElf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < 16 || bytes[0..4] != ELF_MAGIC {
            return Err(String::from("missing `\\x7fELF` magic header"));
        }
        let class = match bytes[4] {
            ELFCLASS32 => ElfClass::Elf32,
            ELFCLASS64 => ElfClass::Elf64,
            other => return Err(format!("unsupported ELF class `{other}`")),
        };
        let endian = match bytes[5] {
            ELFDATA2LSB => Endian::Little,
            ELFDATA2MSB => Endian::Big,
            other => return Err(format!("unsupported ELF endianness `{other}`")),
        };

        let (e_shoff, e_shentsize, mut shnum, mut shstrndx) = match class {
            ElfClass::Elf32 => {
                if bytes.len() < 52 {
                    return Err(String::from("truncated ELF32 header"));
                }
                (
                    u64::from(endian.read_u32(bytes, 32)?),
                    usize::from(endian.read_u16(bytes, 46)?),
                    usize::from(endian.read_u16(bytes, 48)?),
                    usize::from(endian.read_u16(bytes, 50)?),
                )
            }
            ElfClass::Elf64 => {
                if bytes.len() < 64 {
                    return Err(String::from("truncated ELF64 header"));
                }
                (
                    endian.read_u64(bytes, 40)?,
                    usize::from(endian.read_u16(bytes, 58)?),
                    usize::from(endian.read_u16(bytes, 60)?),
                    usize::from(endian.read_u16(bytes, 62)?),
                )
            }
        };
        let e_machine = endian.read_u16(bytes, 18)?;

        if e_shoff == 0 {
            return Ok(Self {
                bytes,
                class,
                endian,
                e_machine,
                sections: Vec::new(),
            });
        }

        let min_shentsize = match class {
            ElfClass::Elf32 => 40,
            ElfClass::Elf64 => 64,
        };
        if e_shentsize < min_shentsize {
            return Err(format!(
                "invalid ELF e_shentsize {e_shentsize} (expected >= {min_shentsize})"
            ));
        }

        let shoff_usize =
            usize::try_from(e_shoff).map_err(|_| String::from("ELF e_shoff overflows usize"))?;

        // Handle extended section numbering in section header 0 if present.
        if shnum == 0 || shstrndx == usize::from(SHN_XINDEX) {
            let sh0 = bytes
                .get(shoff_usize..shoff_usize.saturating_add(e_shentsize))
                .ok_or_else(|| String::from("truncated ELF section header 0"))?;
            let sh0_hdr = parse_shdr(class, endian, sh0)?;
            if shnum == 0 {
                shnum = usize::try_from(sh0_hdr.sh_size)
                    .map_err(|_| String::from("extended ELF section count overflows usize"))?;
            }
            if shstrndx == usize::from(SHN_XINDEX) {
                shstrndx = usize::try_from(sh0_hdr.sh_link)
                    .map_err(|_| String::from("extended ELF shstrndx overflows usize"))?;
            }
        }

        let table_bytes = shnum
            .checked_mul(e_shentsize)
            .ok_or_else(|| String::from("ELF section header table size overflows usize"))?;
        let table_end = shoff_usize
            .checked_add(table_bytes)
            .ok_or_else(|| String::from("ELF section header table offset overflows usize"))?;
        let raw_table = bytes
            .get(shoff_usize..table_end)
            .ok_or_else(|| String::from("ELF section header table exceeds file length"))?;

        let mut sections = Vec::with_capacity(shnum);
        for chunk in raw_table.chunks_exact(e_shentsize) {
            sections.push(parse_shdr(class, endian, chunk)?);
        }

        if !sections.is_empty() && shstrndx < sections.len() {
            let shstr_sec = sections[shstrndx].clone();
            let shstr_bytes = section_slice_raw(bytes, &shstr_sec)?;
            for sec in &mut sections {
                sec.name = read_c_string(shstr_bytes, sec.sh_name)?.to_owned();
            }
        }

        Ok(Self {
            bytes,
            class,
            endian,
            e_machine,
            sections,
        })
    }

    fn section_slice(&self, sec: &SectionHeader) -> Result<&'a [u8], String> {
        section_slice_raw(self.bytes, sec)
    }

    fn parse_sym(&self, entry: &[u8]) -> Result<SymEntry, String> {
        match self.class {
            ElfClass::Elf32 => Ok(SymEntry {
                st_name: self.endian.read_u32(entry, 0)?,
                st_value: u64::from(self.endian.read_u32(entry, 4)?),
                st_size: u64::from(self.endian.read_u32(entry, 8)?),
                st_info: entry[12],
                st_shndx: self.endian.read_u16(entry, 14)?,
            }),
            ElfClass::Elf64 => Ok(SymEntry {
                st_name: self.endian.read_u32(entry, 0)?,
                st_info: entry[4],
                st_shndx: self.endian.read_u16(entry, 6)?,
                st_value: self.endian.read_u64(entry, 8)?,
                st_size: self.endian.read_u64(entry, 16)?,
            }),
        }
    }
}

fn parse_shdr(class: ElfClass, endian: Endian, chunk: &[u8]) -> Result<SectionHeader, String> {
    match class {
        ElfClass::Elf32 => Ok(SectionHeader {
            name: String::new(),
            sh_name: endian.read_u32(chunk, 0)?,
            sh_type: endian.read_u32(chunk, 4)?,
            sh_flags: u64::from(endian.read_u32(chunk, 8)?),
            sh_offset: u64::from(endian.read_u32(chunk, 16)?),
            sh_size: u64::from(endian.read_u32(chunk, 20)?),
            sh_link: endian.read_u32(chunk, 24)?,
            sh_entsize: u64::from(endian.read_u32(chunk, 36)?),
        }),
        ElfClass::Elf64 => Ok(SectionHeader {
            name: String::new(),
            sh_name: endian.read_u32(chunk, 0)?,
            sh_type: endian.read_u32(chunk, 4)?,
            sh_flags: endian.read_u64(chunk, 8)?,
            sh_offset: endian.read_u64(chunk, 24)?,
            sh_size: endian.read_u64(chunk, 32)?,
            sh_link: endian.read_u32(chunk, 40)?,
            sh_entsize: endian.read_u64(chunk, 56)?,
        }),
    }
}

fn section_slice_raw<'a>(bytes: &'a [u8], sec: &SectionHeader) -> Result<&'a [u8], String> {
    let start = usize::try_from(sec.sh_offset)
        .map_err(|_| String::from("ELF section offset overflows usize"))?;
    let len = usize::try_from(sec.sh_size)
        .map_err(|_| String::from("ELF section size overflows usize"))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| String::from("ELF section range overflows usize"))?;
    bytes.get(start..end).ok_or_else(|| {
        format!(
            "ELF section `{}` range {start}..{end} exceeds file length",
            sec.name
        )
    })
}

fn read_c_string(strtab: &[u8], offset: u32) -> Result<&str, String> {
    let start =
        usize::try_from(offset).map_err(|_| String::from("string table offset overflows usize"))?;
    let tail = strtab.get(start..).ok_or_else(|| {
        format!(
            "string table offset {start} exceeds length {}",
            strtab.len()
        )
    })?;
    let nul_pos = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| format!("unterminated string at string table offset {start}"))?;
    std::str::from_utf8(&tail[..nul_pos])
        .map_err(|err| format!("invalid UTF-8 in ELF string table at offset {start}: {err}"))
}

pub(crate) fn first_nonempty_line(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no stderr output)")
}
