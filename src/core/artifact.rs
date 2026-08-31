use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    Pe,
    Elf,
    MachO,
    Jar,
    Zip,
    Raw,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Jar => "jar",
            Self::Zip => "zip",
            Self::Raw => "raw",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInfo {
    pub kind: ArtifactKind,
    pub size: u64,
    pub digest: [u8; 32],
}

pub fn inspect(data: &[u8]) -> Result<ArtifactInfo> {
    if data.is_empty() {
        bail!("artifact is empty");
    }
    let kind = detect(data);
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    Ok(ArtifactInfo { kind, size: data.len() as u64, digest: *hasher.finalize().as_bytes() })
}

pub fn detect(data: &[u8]) -> ArtifactKind {
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return ArtifactKind::Pe;
    }
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return ArtifactKind::Elf;
    }
    if data.len() >= 4 {
        let magic = &data[..4];
        if matches!(magic, b"\xfe\xed\xfa\xce" | b"\xce\xfa\xed\xfe" | b"\xfe\xed\xfa\xcf" | b"\xcf\xfa\xed\xfe") {
            return ArtifactKind::MachO;
        }
    }
    if data.len() >= 4 && &data[..4] == b"PK\x03\x04" {
        if zip_contains(data, b"META-INF/MANIFEST.MF") {
            return ArtifactKind::Jar;
        }
        return ArtifactKind::Zip;
    }
    ArtifactKind::Raw
}

fn zip_contains(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| window == needle)
}
