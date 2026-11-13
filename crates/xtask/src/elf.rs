//! Pure-Rust ELF32/ELF64 section and `.symtab` analyzer for `cargo xtask size`.
//!
//! Parses freestanding bare-metal ELF binaries (`riscv32imac-unknown-none-elf`,
//! `thumbv7em-none-eabihf`, and `x86_64-unknown-none`) directly in-process
//! without external C++ tooling, matching `SHF_ALLOC` Flash (`.text` + `.rodata`)
//! and RAM (`.data` + `.bss`) section totals and computing demangled per-symbol
//! diffs across revisions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::report::signed_diff;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHF_ALLOC: u64 = 0x2;
const SHN_XINDEX: u16 = 0xffff;

const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;

/// Aggregate Flash and RAM VM sizes (in bytes) extracted from an ELF binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SectionSizes {
    /// Read-only / executable allocatable image bytes (`.text`, `.rodata`, `.srodata`, `.data.rel.ro`).
    pub(crate) flash_vm: u64,
    /// Read-write static memory bytes (`.data`, `.sdata`, `.bss`, `.sbss`, `.tdata`, `.tbss`).
    pub(crate) ram_vm: u64,
}

impl SectionSizes {
    pub(crate) const fn total_vm(self) -> u64 {
        self.flash_vm.saturating_add(self.ram_vm)
    }
}

/// Classification of an ELF section for embedded footprint accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionKind {
    Flash,
    Ram,
}

/// Per-symbol VM size delta between a `base` and `head` ELF binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SymbolDelta {
    pub(crate) section: String,
    pub(crate) symbol: String,
    pub(crate) delta_vm: i64,
}

/// Classifies an ELF section name into Flash (ROM) or RAM (SRAM), ignoring
/// non-firmware metadata, ELF loader headers, unwind tables, and alignment padding.
pub(crate) fn classify_section(section: &str) -> Option<SectionKind> {
    if matches_prefix(section, ".text")
        || matches_prefix(section, ".rodata")
        || matches_prefix(section, ".srodata")
        || matches_prefix(section, ".data.rel.ro")
    {
        Some(SectionKind::Flash)
    } else if matches_prefix(section, ".data")
        || matches_prefix(section, ".sdata")
        || matches_prefix(section, ".bss")
        || matches_prefix(section, ".sbss")
        || matches_prefix(section, ".tdata")
        || matches_prefix(section, ".tbss")
    {
        Some(SectionKind::Ram)
    } else {
        None
    }
}

/// Maps subsections (such as `.text.foo` or `.rodata.cst4`) to their canonical
/// parent section name for symbol diff grouping.
pub(crate) fn canonical_section_name(section: &str) -> Option<&'static str> {
    if matches_prefix(section, ".text") {
        Some(".text")
    } else if matches_prefix(section, ".data.rel.ro") {
        Some(".data.rel.ro")
    } else if matches_prefix(section, ".rodata") || matches_prefix(section, ".srodata") {
        Some(".rodata")
    } else if matches_prefix(section, ".data") || matches_prefix(section, ".sdata") {
        Some(".data")
    } else if matches_prefix(section, ".bss") || matches_prefix(section, ".sbss") {
        Some(".bss")
    } else if matches_prefix(section, ".tdata") {
        Some(".tdata")
    } else if matches_prefix(section, ".tbss") {
        Some(".tbss")
    } else {
        None
    }
}

fn matches_prefix(section: &str, base: &str) -> bool {
    section == base
        || section
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Reads an ELF file from disk and returns its allocatable Flash and RAM VM totals.
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
            Some(SectionKind::Flash) => {
                totals.flash_vm = totals.flash_vm.saturating_add(sec.sh_size)
            }
            Some(SectionKind::Ram) => totals.ram_vm = totals.ram_vm.saturating_add(sec.sh_size),
            None => {}
        }
    }
    Ok(totals)
}

/// Computes per-symbol VM byte deltas (`head - base`) between two ELF buffers.
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
        let delta_vm = signed_diff(head_sz, base_sz);
        if delta_vm != 0 {
            deltas.push(SymbolDelta {
                section: key.0,
                symbol: key.1,
                delta_vm,
            });
        }
    }

    deltas.sort_by(|a, b| {
        b.delta_vm
            .unsigned_abs()
            .cmp(&a.delta_vm.unsigned_abs())
            .then_with(|| a.section.cmp(&b.section))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });
    deltas.truncate(max_rows);
    Ok(deltas)
}

/// Demangles a symbol name and normalizes compiler-generated anonymous or
/// machine-outlined labels so sequential renumbering does not create diff noise.
pub(crate) fn demangle_and_normalize_symbol(raw: &str) -> String {
    if is_compiler_anon_label(raw) {
        return String::from("[compiler constants & jump tables]");
    }
    if raw.starts_with("OUTLINED_FUNCTION_") {
        return String::from("[compiler-outlined functions]");
    }
    format!("{:#}", rustc_demangle::demangle(raw))
}

fn is_compiler_anon_label(sym: &str) -> bool {
    sym.starts_with(".Lanon.")
        || sym.starts_with(".Lswitch.table.")
        || sym.starts_with(".L__unnamed_")
}

fn is_arch_mapping_symbol(sym: &str) -> bool {
    sym.starts_with("$x") || sym.starts_with("$d") || sym.starts_with("$t") || sym.starts_with("$a")
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

    let mut symbol_sizes: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut named_section_sums: BTreeMap<String, u64> = BTreeMap::new();
    let mut seen_spans: BTreeSet<(usize, u64, u64)> = BTreeSet::new();

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
            if sym.st_size == 0 || sym.st_shndx == 0 {
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

            // Strip ARM Thumb indicator bit 0 on function symbols when
            // deduplicating alias symbols at the exact same address span.
            let norm_addr = if st_type == STT_FUNC {
                sym.st_value & !1
            } else {
                sym.st_value
            };
            if !seen_spans.insert((shndx, norm_addr, sym.st_size)) {
                continue;
            }

            let demangled = demangle_and_normalize_symbol(raw_name);
            let key = (String::from(canon_sec), demangled);
            let sym_entry = symbol_sizes.entry(key).or_insert(0);
            *sym_entry = sym_entry.saturating_add(sym.st_size);

            let sec_sum = named_section_sums
                .entry(String::from(canon_sec))
                .or_insert(0);
            *sec_sum = sec_sum.saturating_add(sym.st_size);
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

        if e_shoff == 0 {
            return Ok(Self {
                bytes,
                class,
                endian,
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
