use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    let digest = *hasher.finalize().as_bytes();

    Ok(ArtifactInfo {
        kind,
        size: data.len() as u64,
        digest,
    })
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
        // A JAR is a ZIP container. We deliberately classify it as ZIP here;
        // callers that need Java-specific handling can inspect the ZIP entries.
        return ArtifactKind::Zip;
    }

    ArtifactKind::Raw
}
