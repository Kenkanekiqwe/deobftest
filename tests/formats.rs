use deobf::core::{parse_pe, zip_has_manifest};

#[test]
fn parses_pe_header() {
    let pe_offset = 0x40usize;
    let optional_size = 0xF0usize;
    let section_count = 3usize;
    let section_table = pe_offset + 24 + optional_size;
    let mut data = vec![0u8; section_table + section_count * 40];

    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    data[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

    let coff = pe_offset + 4;
    data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&(section_count as u16).to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());

    let optional = coff + 20;
    data[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    data[optional + 60..optional + 64].copy_from_slice(&(section_table as u32).to_le_bytes());
    data[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());

    let info = parse_pe(&data).unwrap();
    assert_eq!(info.machine, 0x8664);
    assert_eq!(info.sections, section_count as u16);
    assert_eq!(info.optional_magic, Some(0x20b));
}

#[test]
fn detects_jar_manifest_marker() {
    assert!(zip_has_manifest(b"prefixMETA-INF/MANIFEST.MF"));
    assert!(!zip_has_manifest(b"plain archive"));
}
