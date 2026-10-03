use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Zip,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInfo {
    pub machine: u16,
    pub sections: u16,
    pub characteristics: u16,
    pub optional_magic: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImport {
    pub library: String,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeAnalysis {
    pub info: PeInfo,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
}

#[derive(Debug, Clone, Copy)]
struct PeLayout {
    pe_offset: usize,
    coff_offset: usize,
    optional_offset: usize,
    optional_size: usize,
    optional_magic: u16,
    section_table: usize,
    size_of_headers: u32,
    number_of_directories: u32,
    directory_offset: usize,
    pointer_size: usize,
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data.get(offset..offset.checked_add(2).context("offset overflow")?)
        .context("truncated 16-bit field")?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data.get(offset..offset.checked_add(4).context("offset overflow")?)
        .context("truncated 32-bit field")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data.get(offset..offset.checked_add(8).context("offset overflow")?)
        .context("truncated 64-bit field")?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn pe_layout(data: &[u8]) -> Result<PeLayout> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        bail!("not a PE image");
    }
    let pe_offset = read_u32(data, 0x3c)? as usize;
    let signature_end = pe_offset.checked_add(4).context("PE offset overflow")?;
    if data.get(pe_offset..signature_end) != Some(b"PE\0\0".as_slice()) {
        bail!("invalid PE signature");
    }

    let coff_offset = signature_end;
    let coff_end = coff_offset.checked_add(20).context("COFF header overflow")?;
    if coff_end > data.len() {
        bail!("truncated COFF header");
    }
    let section_count = read_u16(data, coff_offset + 2)? as usize;
    let optional_size = read_u16(data, coff_offset + 16)? as usize;
    let optional_offset = coff_end;
    let optional_end = optional_offset.checked_add(optional_size)
        .context("optional-header overflow")?;
    if optional_end > data.len() {
        bail!("truncated PE optional header");
    }
    if optional_size < 2 {
        bail!("missing PE optional-header magic");
    }
    let optional_magic = read_u16(data, optional_offset)?;
    let (directory_relative, count_relative, pointer_size) = match optional_magic {
        0x10b => (96usize, 92usize, 4usize),
        0x20b => (112usize, 108usize, 8usize),
        _ => bail!("unsupported PE optional-header magic 0x{optional_magic:04x}"),
    };
    let minimum = directory_relative.checked_add(8).context("directory offset overflow")?;
    if optional_size < minimum || optional_size < count_relative + 4 {
        bail!("PE optional header is too short for standard fields");
    }
    let size_of_headers = read_u32(data, optional_offset + 60)?;
    let number_of_directories = read_u32(data, optional_offset + count_relative)?;
    let directory_offset = optional_offset + directory_relative;
    let section_table = optional_end;
    let section_bytes = section_count.checked_mul(40).context("section table overflow")?;
    let section_end = section_table.checked_add(section_bytes).context("section table overflow")?;
    if section_end > data.len() {
        bail!("truncated PE section table");
    }

    Ok(PeLayout {
        pe_offset,
        coff_offset,
        optional_offset,
        optional_size,
        optional_magic,
        section_table,
        size_of_headers,
        number_of_directories,
        directory_offset,
        pointer_size,
    })
}

pub fn parse_pe(data: &[u8]) -> Result<PeInfo> {
    let layout = pe_layout(data)?;
    Ok(PeInfo {
        machine: read_u16(data, layout.coff_offset)?,
        sections: read_u16(data, layout.coff_offset + 2)?,
        characteristics: read_u16(data, layout.coff_offset + 18)?,
        optional_magic: Some(layout.optional_magic),
    })
}

fn c_string(data: &[u8], offset: usize) -> Result<String> {
    let tail = data.get(offset..).context("string offset outside file")?;
    let end = tail.iter().position(|b| *b == 0).context("unterminated PE string")?;
    let bytes = &tail[..end];
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn rva_to_offset(data: &[u8], layout: &PeLayout, sections: &[PeSection], rva: u32) -> Result<usize> {
    if rva < layout.size_of_headers {
        let offset = rva as usize;
        if offset < data.len() {
            return Ok(offset);
        }
        bail!("PE header RVA points beyond file");
    }

    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        let end = section.virtual_address.checked_add(span).unwrap_or(u32::MAX);
        if rva >= section.virtual_address && rva < end {
            let delta = rva - section.virtual_address;
            if delta >= section.raw_size {
                bail!("RVA points into an uninitialized section tail");
            }
            let offset = section.raw_offset.checked_add(delta)
                .context("RVA-to-file offset overflow")? as usize;
            if offset >= data.len() {
                bail!("RVA maps beyond file");
            }
            return Ok(offset);
        }
    }
    bail!("RVA 0x{rva:08x} is not mapped by PE headers or sections")
}

fn read_thunk(data: &[u8], offset: usize, pointer_size: usize) -> Result<u64> {
    if pointer_size == 4 {
        Ok(read_u32(data, offset)? as u64)
    } else {
        read_u64(data, offset)
    }
}

fn parse_imports(data: &[u8], layout: &PeLayout, sections: &[PeSection]) -> Result<Vec<PeImport>> {
    // IMAGE_DIRECTORY_ENTRY_IMPORT is directory index 1.
    if layout.number_of_directories <= 1 {
        return Ok(Vec::new());
    }
    if layout.optional_size < (layout.directory_offset - layout.optional_offset) + 16 {
        bail!("PE optional header does not contain the import directory");
    }
    let import_rva = read_u32(data, layout.directory_offset + 8)?;
    let import_size = read_u32(data, layout.directory_offset + 12)?;
    if import_rva == 0 && import_size == 0 {
        return Ok(Vec::new());
    }
    if import_rva == 0 || import_size < 20 {
        bail!("invalid PE import directory bounds");
    }

    let table_offset = rva_to_offset(data, layout, sections, import_rva)?;
    let descriptor_limit = ((import_size as usize) / 20).min(1024);
    let mut imports = Vec::new();
    let mut terminated = false;

    for i in 0..descriptor_limit {
        let descriptor = table_offset.checked_add(i * 20).context("import table overflow")?;
        let original_thunk = read_u32(data, descriptor)?;
        let name_rva = read_u32(data, descriptor + 12)?;
        let first_thunk = read_u32(data, descriptor + 16)?;
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            terminated = true;
            break;
        }
        if name_rva == 0 {
            bail!("PE import descriptor has no library name");
        }
        let name_offset = rva_to_offset(data, layout, sections, name_rva)?;
        let library = c_string(data, name_offset)?;
        let thunk_rva = if original_thunk != 0 { original_thunk } else { first_thunk };
        let thunk_offset = rva_to_offset(data, layout, sections, thunk_rva)?;
        let mut symbols = Vec::new();
        let mut thunk_terminated = false;

        for thunk_index in 0..4096usize {
            let at = thunk_offset.checked_add(thunk_index.checked_mul(layout.pointer_size).context("thunk index overflow")?)
                .context("thunk table overflow")?;
            let value = read_thunk(data, at, layout.pointer_size)?;
            if value == 0 {
                thunk_terminated = true;
                break;
            }
            let ordinal_flag = if layout.pointer_size == 4 { 0x8000_0000u64 } else { 0x8000_0000_0000_0000u64 };
            if value & ordinal_flag != 0 {
                symbols.push(format!("#{}", value & 0xffff));
            } else {
                let hint_name_rva = u32::try_from(value).context("import-by-name RVA exceeds 32 bits")?;
                let hint_name = rva_to_offset(data, layout, sections, hint_name_rva)?;
                let symbol_offset = hint_name.checked_add(2).context("import name offset overflow")?;
                symbols.push(c_string(data, symbol_offset)?);
            }
            if symbols.len() >= 4096 {
                bail!("PE import thunk table exceeds safety limit");
            }
        }
        if !thunk_terminated {
            bail!("PE import thunk table has no terminator within safety limit");
        }
        imports.push(PeImport { library, symbols });
    }
    if !terminated && descriptor_limit == 0 {
        bail!("PE import directory has no descriptors");
    }
    // A table that ends exactly at the declared boundary need not include the
    // null descriptor, so do not reject it solely for lacking a terminator.
    let _ = terminated;
    Ok(imports)
}

/// Parse PE section metadata and import descriptors without changing the input.
/// Rejects truncated tables and out-of-file RVAs rather than returning partial data.
pub fn analyze_pe(data: &[u8]) -> Result<PeAnalysis> {
    let layout = pe_layout(data)?;
    let info = parse_pe(data)?;
    let mut sections = Vec::with_capacity(info.sections as usize);

    for i in 0..info.sections as usize {
        let offset = layout.section_table.checked_add(i * 40).context("section offset overflow")?;
        let raw_name = &data[offset..offset + 8];
        let name_end = raw_name.iter().position(|b| *b == 0).unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        let virtual_size = read_u32(data, offset + 8)?;
        let virtual_address = read_u32(data, offset + 12)?;
        let raw_size = read_u32(data, offset + 16)?;
        let raw_offset = read_u32(data, offset + 20)?;
        let characteristics = read_u32(data, offset + 36)?;

        if raw_size != 0 {
            let raw_end = (raw_offset as usize).checked_add(raw_size as usize)
                .context("section raw-data range overflow")?;
            if raw_offset == 0 || raw_end > data.len() {
                bail!("section {name:?} raw-data range lies outside the file");
            }
        }
        virtual_address.checked_add(virtual_size.max(raw_size))
            .context("section virtual range overflow")?;

        sections.push(PeSection {
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            characteristics,
        });
    }

    let imports = parse_imports(data, &layout, &sections)?;
    Ok(PeAnalysis { info, sections, imports })
}

/// Remove PE debug-directory discoverability and COFF symbol-table references.
///
/// This intentionally does not rewrite executable instructions. The operation is
/// limited to well-bounded PE header fields and rejects malformed optional headers.
/// Authenticode signatures may become invalid after any PE header modification.
pub fn strip_pe_debug_metadata(data: &mut [u8]) -> Result<bool> {
    let info = parse_pe(data)?;
    let pe = read_u32(data, 0x3c)? as usize;
    let coff = pe + 4;
    let optional_size = read_u16(data, coff + 16)? as usize;
    let optional = coff + 20;
    let optional_end = optional.checked_add(optional_size).context("PE optional-header overflow")?;
    if optional_end > data.len() {
        bail!("truncated PE optional header");
    }

    let magic = info.optional_magic.context("missing PE optional-header magic")?;
    let (directory_relative, count_relative) = match magic {
        0x10b => (96usize, 92usize),
        0x20b => (112usize, 108usize),
        _ => bail!("unsupported PE optional-header magic 0x{magic:04x}"),
    };
    if optional_size < count_relative + 4 || optional_size < directory_relative + 7 * 8 {
        bail!("PE optional header does not contain the debug data directory");
    }
    // Validate every field before changing any bytes so an error never leaves a
    // partially transformed input buffer behind.
    let directory_count = read_u32(data, optional + count_relative)?;
    let debug = optional + directory_relative + 6 * 8;
    let characteristics_offset = coff + 18;
    let characteristics = read_u16(data, characteristics_offset)?;

    let mut changed = false;
    for range in [coff + 4..coff + 8, coff + 8..coff + 16] {
        if data[range.clone()].iter().any(|b| *b != 0) {
            data[range].fill(0);
            changed = true;
        }
    }

    let stripped = characteristics | 0x0200;
    if stripped != characteristics {
        data[characteristics_offset..characteristics_offset + 2].copy_from_slice(&stripped.to_le_bytes());
        changed = true;
    }

    if directory_count > 6 && data[debug..debug + 8].iter().any(|b| *b != 0) {
        data[debug..debug + 8].fill(0);
        changed = true;
    }
    Ok(changed)
}

pub fn zip_has_manifest(data: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"META-INF/";
    data.windows(NEEDLE.len()).any(|w| w == NEEDLE)
}

#[cfg(test)]
mod pe_debug_tests {
    use super::*;

    fn minimal_pe(pe32_plus: bool) -> Vec<u8> {
        let pe = 0x80usize;
        let optional_size = if pe32_plus { 0xF0usize } else { 0xE0usize };
        let section_table = pe + 24 + optional_size;
        let mut data = vec![0u8; section_table + 40 + 0x200];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        data[pe..pe + 4].copy_from_slice(b"PE\0\0");
        data[pe + 4..pe + 6].copy_from_slice(&(if pe32_plus { 0x8664u16 } else { 0x014cu16 }).to_le_bytes());
        data[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        data[pe + 20..pe + 22].copy_from_slice(&(optional_size as u16).to_le_bytes());
        data[pe + 22..pe + 24].copy_from_slice(&0x0002u16.to_le_bytes());
        let opt = pe + 24;
        data[opt..opt + 2].copy_from_slice(&(if pe32_plus { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
        data[opt + 60..opt + 64].copy_from_slice(&(section_table as u32).to_le_bytes());
        let (count, dirs) = if pe32_plus { (opt + 108, opt + 112) } else { (opt + 92, opt + 96) };
        data[count..count + 4].copy_from_slice(&16u32.to_le_bytes());
        data[dirs + 6 * 8..dirs + 6 * 8 + 4].copy_from_slice(&0x1234u32.to_le_bytes());
        data[dirs + 6 * 8 + 4..dirs + 6 * 8 + 8].copy_from_slice(&28u32.to_le_bytes());
        data[pe + 4..pe + 8].copy_from_slice(&0x12345678u32.to_le_bytes());
        data[pe + 8..pe + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[pe + 12..pe + 16].copy_from_slice(&3u32.to_le_bytes());

        let section = section_table;
        data[section..section + 8].copy_from_slice(b".text\0\0\0");
        data[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
        data[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[section + 20..section + 24].copy_from_slice(&(section_table as u32 + 40).to_le_bytes());
        data[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        data
    }

    #[test]
    fn parses_pe_sections_and_empty_import_table() {
        let data = minimal_pe(false);
        let analysis = analyze_pe(&data).unwrap();
        assert_eq!(analysis.info.machine, 0x014c);
        assert_eq!(analysis.sections.len(), 1);
        assert_eq!(analysis.sections[0].name, ".text");
        assert!(analysis.imports.is_empty());
    }

    #[test]
    fn strips_pe32_debug_metadata_idempotently() {
        let mut data = minimal_pe(false);
        assert!(strip_pe_debug_metadata(&mut data).unwrap());
        assert!(!strip_pe_debug_metadata(&mut data).unwrap());
        let pe = 0x80usize;
        assert_eq!(&data[pe + 4..pe + 16], &[0; 12]);
        assert_eq!(read_u16(&data, pe + 22).unwrap() & 0x0200, 0x0200);
        assert_eq!(&data[pe + 24 + 96 + 6 * 8..pe + 24 + 96 + 7 * 8], &[0; 8]);
    }

    #[test]
    fn strips_pe32_plus_debug_metadata() {
        let mut data = minimal_pe(true);
        assert!(strip_pe_debug_metadata(&mut data).unwrap());
        let pe = 0x80usize;
        assert_eq!(&data[pe + 24 + 112 + 6 * 8..pe + 24 + 112 + 7 * 8], &[0; 8]);
    }

    #[test]
    fn rejects_truncated_optional_header() {
        let mut data = minimal_pe(false);
        data.truncate(0x80 + 24 + 10);
        assert!(strip_pe_debug_metadata(&mut data).is_err());
    }

    #[test]
    fn rejects_section_raw_range_outside_file() {
        let mut data = minimal_pe(false);
        let section = 0x80 + 24 + 0xE0;
        data[section + 20..section + 24].copy_from_slice(&0xfffffff0u32.to_le_bytes());
        assert!(analyze_pe(&data).is_err());
    }
}
