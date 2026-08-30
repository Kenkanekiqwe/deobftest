use deobf::core::{artifact, integrity};

#[test]
fn detects_common_formats() {
    assert_eq!(artifact::detect(b"MZ\0\0"), deobf::core::ArtifactKind::Pe);
    assert_eq!(artifact::detect(b"\x7fELF\0\0"), deobf::core::ArtifactKind::Elf);
    assert_eq!(
        artifact::detect(b"\xfe\xed\xfa\xce\0\0"),
        deobf::core::ArtifactKind::MachO
    );
    assert_eq!(
        artifact::detect(b"PK\x03\x04META-INF/MANIFEST.MF"),
        deobf::core::ArtifactKind::Jar
    );
    assert_eq!(artifact::detect(b"hello"), deobf::core::ArtifactKind::Unknown);
}

#[test]
fn integrity_round_trip() {
    let data = b"deobf integrity test";
    let digest = integrity::hash(data);
    assert!(integrity::verify(data, &digest).is_ok());
    assert!(integrity::verify(b"modified", &digest).is_err());
}

#[test]
fn artifact_inspection_returns_digest_and_size() {
    let data = b"MZpayload";
    let info = artifact::inspect(data).expect("valid artifact");
    assert_eq!(info.kind, deobf::core::ArtifactKind::Pe);
    assert_eq!(info.size, data.len() as u64);
}
