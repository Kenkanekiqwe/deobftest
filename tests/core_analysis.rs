use deobf::core::{analyze, detect, ArtifactKind, Architecture, ResourceLimits};

#[test]
fn detects_common_formats() {
    assert_eq!(detect(b"MZ\x90\0"), ArtifactKind::Pe);
    assert_eq!(detect(b"\x7fELF\x02\0\0\0"), ArtifactKind::Elf);
    assert_eq!(detect(b"PK\x03\x04payload"), ArtifactKind::Zip);
    assert_eq!(detect(b"plain"), ArtifactKind::Raw);
}

#[test]
fn analyzes_pe_architecture() {
    let mut pe = vec![0u8; 0x80];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&(0x40u32).to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    let result = analyze(&pe).unwrap();
    assert_eq!(result.kind, ArtifactKind::Pe);
    assert_eq!(result.architecture, Architecture::X86_64);
    assert!(result.executable);
}

#[test]
fn rejects_oversized_input() {
    let limits = ResourceLimits { max_input_size: 4, max_chunk_size: 1 };
    assert!(limits.validate(5).is_err());
    assert!(limits.validate(4).is_ok());
}
