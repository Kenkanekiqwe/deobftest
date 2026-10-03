use anyhow::{bail, Result};

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

pub fn parse_pe(data: &[u8]) -> Result<PeInfo> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        bail!("not a PE image")
    }
    let off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    if off.checked_add(24).is_none() || data.len() < off + 24 || &data[off..off + 4] != b"PE\0\0" {
        bail!("invalid PE header")
    }
    let machine = u16::from_le_bytes(data[off + 4..off + 6].try_into().unwrap());
    let sections = u16::from_le_bytes(data[off + 6..off + 8].try_into().unwrap());
    let opt_size = u16::from_le_bytes(data[off + 20..off + 22].try_into().unwrap()) as usize;
    let characteristics = u16::from_le_bytes(data[off + 22..off + 24].try_into().unwrap());
    let optional_magic = if opt_size >= 2 && data.len() >= off + 26 {
        Some(u16::from_le_bytes(
            data[off + 24..off + 26].try_into().unwrap(),
        ))
    } else {
        None
    };
    Ok(PeInfo {
        machine,
        sections,
        characteristics,
        optional_magic,
    })
}

/// Remove PE debug-directory discoverability and COFF symbol-table references.
///
/// This intentionally does not rewrite executable instructions. The operation is
/// limited to well-bounded PE header fields and rejects malformed optional headers.
/// Authenticode signatures may become invalid after any PE header modification.
pub fn strip_pe_debug_metadata(data: &mut [u8]) -> Result<bool> {
    let info = parse_pe(data)?;
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe + 4;
    let optional_size = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap()) as usize;
    let optional = coff + 20;
    let optional_end = optional.checked_add(optional_size).ok_or_else(|| anyhow::anyhow!("PE optional-header overflow"))?;
    if optional_end > data.len() {
        bail!("truncated PE optional header");
    }

    // COFF timestamp, pointer to symbol table, and symbol count.
    let mut changed = false;
    for range in [coff + 4..coff + 8, coff + 8..coff + 16] {
        if data[range.clone()].iter().any(|b| *b != 0) {
            data[range].fill(0);
            changed = true;
        }
    }

    // IMAGE_FILE_DEBUG_STRIPPED (0x0200).
    let characteristics_offset = coff + 18;
    let characteristics = u16::from_le_bytes(data[characteristics_offset..characteristics_offset + 2].try_into().unwrap());
    let stripped = characteristics | 0x0200;
    if stripped != characteristics {
        data[characteristics_offset..characteristics_offset + 2].copy_from_slice(&stripped.to_le_bytes());
        changed = true;
    }

    // IMAGE_DIRECTORY_ENTRY_DEBUG is index 6. Directory array starts at
    // optional-header + 96 for PE32 and +112 for PE32+.
    let magic = info.optional_magic.ok_or_else(|| anyhow::anyhow!("missing PE optional-header magic"))?;
    let (directory_offset, count_offset) = match magic {
        0x10b => (optional + 96, optional + 92),
        0x20b => (optional + 112, optional + 108),
        _ => bail!("unsupported PE optional-header magic 0x{magic:04x}"),
    };
    if optional_size < count_offset - optional || optional_size < (directory_offset + 7 * 8) - optional {
        bail!("PE optional header does not contain the debug data directory");
    }
    let directory_count = u32::from_le_bytes(data[count_offset..count_offset + 4].try_into().unwrap());
    if directory_count > 6 {
        let debug = directory_offset + 6 * 8;
        if data[debug..debug + 8].iter().any(|b| *b != 0) {
            data[debug..debug + 8].fill(0);
            changed = true;
        }
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
        let mut data = vec![0u8; pe + 24 + optional_size + 40];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        data[pe..pe + 4].copy_from_slice(b"PE\0\0");
        data[pe + 4..pe + 6].copy_from_slice(&(if pe32_plus { 0x8664u16 } else { 0x014cu16 }).to_le_bytes());
        data[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        data[pe + 20..pe + 22].copy_from_slice(&(optional_size as u16).to_le_bytes());
        data[pe + 22..pe + 24].copy_from_slice(&0x0002u16.to_le_bytes());
        let opt = pe + 24;
        data[opt..opt + 2].copy_from_slice(&(if pe32_plus { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
        let (count, dirs) = if pe32_plus { (opt + 108, opt + 112) } else { (opt + 92, opt + 96) };
        data[count..count + 4].copy_from_slice(&16u32.to_le_bytes());
        data[dirs + 6 * 8..dirs + 6 * 8 + 4].copy_from_slice(&0x1234u32.to_le_bytes());
        data[dirs + 6 * 8 + 4..dirs + 6 * 8 + 8].copy_from_slice(&28u32.to_le_bytes());
        data[pe + 4..pe + 8].copy_from_slice(&0x12345678u32.to_le_bytes());
        data[pe + 8..pe + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[pe + 12..pe + 16].copy_from_slice(&3u32.to_le_bytes());
        data
    }

    #[test]
    fn strips_pe32_debug_metadata_idempotently() {
        let mut data = minimal_pe(false);
        assert!(strip_pe_debug_metadata(&mut data).unwrap());
        assert!(!strip_pe_debug_metadata(&mut data).unwrap());
        let pe = 0x80usize;
        assert_eq!(&data[pe + 4..pe + 16], &[0; 12]);
        assert_eq!(u16::from_le_bytes(data[pe + 22..pe + 24].try_into().unwrap()) & 0x0200, 0x0200);
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
}
