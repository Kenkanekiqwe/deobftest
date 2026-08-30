use deobf::core::{parse_pe, zip_has_manifest};

#[test]
fn parses_pe_header() {
    let mut data = vec![0u8; 0x80];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&(0x40u32).to_le_bytes());
    data[0x40..0x44].copy_from_slice(b"PE\0\0");
    data[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    data[0x46..0x48].copy_from_slice(&3u16.to_le_bytes());
    data[0x54..0x56].copy_from_slice(&0x20bu16.to_le_bytes());
    let info = parse_pe(&data).unwrap();
    assert_eq!(info.machine, 0x8664);
    assert_eq!(info.sections, 3);
    assert_eq!(info.optional_magic, Some(0x20b));
}

#[test]
fn detects_jar_manifest_marker() {
    assert!(zip_has_manifest(b"prefixMETA-INF/MANIFEST.MF"));
    assert!(!zip_has_manifest(b"plain archive"));
}
