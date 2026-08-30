use anyhow::{bail, Result};

use super::artifact::{detect, ArtifactKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Arm64,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Analysis {
    pub kind: ArtifactKind,
    pub architecture: Architecture,
    pub executable: bool,
    pub has_debug_markers: bool,
    pub has_archive_signature: bool,
}

pub fn analyze(data: &[u8]) -> Result<Analysis> {
    if data.is_empty() {
        bail!("artifact is empty");
    }

    let kind = detect(data);
    let architecture = match kind {
        ArtifactKind::Pe => pe_architecture(data),
        ArtifactKind::Elf => elf_architecture(data),
        _ => Architecture::Unknown,
    };

    let executable = matches!(kind, ArtifactKind::Pe | ArtifactKind::Elf | ArtifactKind::MachO);
    let has_archive_signature = data.windows(4).any(|w| w == b"PK\x03\x04");
    let has_debug_markers = [b".debug_info".as_slice(), b".debug_line", b"RSDS", b"CodeView"]
        .iter()
        .any(|needle| data.windows(needle.len()).any(|w| w == *needle));

    Ok(Analysis {
        kind,
        architecture,
        executable,
        has_debug_markers,
        has_archive_signature,
    })
}

fn pe_architecture(data: &[u8]) -> Architecture {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Architecture::Unknown;
    }
    let pe_offset = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    if pe_offset.checked_add(6).is_none() || data.len() < pe_offset + 6 || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Architecture::Unknown;
    }
    match u16::from_le_bytes(data[pe_offset + 4..pe_offset + 6].try_into().unwrap()) {
        0x014c => Architecture::X86,
        0x8664 => Architecture::X86_64,
        0x01c4 | 0x01c0 => Architecture::Arm,
        0xaa64 => Architecture::Arm64,
        _ => Architecture::Unknown,
    }
}

fn elf_architecture(data: &[u8]) -> Architecture {
    if data.len() < 20 || &data[..4] != b"\x7fELF" {
        return Architecture::Unknown;
    }
    match u16::from_le_bytes(data[18..20].try_into().unwrap()) {
        3 => Architecture::X86,
        62 => Architecture::X86_64,
        40 => Architecture::Arm,
        183 => Architecture::Arm64,
        _ => Architecture::Unknown,
    }
}
