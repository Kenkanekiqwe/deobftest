use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatKind {
    Generic,
    Jar,
    Pe,
    Elf,
    MachO,
}

pub trait FormatAdapter: Send + Sync {
    fn kind(&self) -> FormatKind;
    fn detect(&self, data: &[u8]) -> bool;
    fn validate(&self, data: &[u8]) -> Result<()>;
}

pub struct GenericAdapter;

impl FormatAdapter for GenericAdapter {
    fn kind(&self) -> FormatKind {
        FormatKind::Generic
    }

    fn detect(&self, _: &[u8]) -> bool {
        true
    }

    fn validate(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            bail!("artifact is empty");
        }
        Ok(())
    }
}

pub struct JarAdapter;

impl FormatAdapter for JarAdapter {
    fn kind(&self) -> FormatKind {
        FormatKind::Jar
    }

    fn detect(&self, data: &[u8]) -> bool {
        data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06")
    }

    fn validate(&self, data: &[u8]) -> Result<()> {
        if !self.detect(data) {
            bail!("input does not have a ZIP/JAR signature");
        }
        Ok(())
    }
}

pub struct PeAdapter;

impl FormatAdapter for PeAdapter {
    fn kind(&self) -> FormatKind {
        FormatKind::Pe
    }

    fn detect(&self, data: &[u8]) -> bool {
        data.len() >= 2 && &data[..2] == b"MZ"
    }

    fn validate(&self, data: &[u8]) -> Result<()> {
        if data.len() < 0x40 || !self.detect(data) {
            bail!("input does not have a valid PE DOS header");
        }
        let pe_offset = u32::from_le_bytes([
            data[0x3c],
            data[0x3d],
            data[0x3e],
            data[0x3f],
        ]) as usize;
        if pe_offset.checked_add(4).is_none()
            || pe_offset + 4 > data.len()
            || &data[pe_offset..pe_offset + 4] != b"PE\0\0"
        {
            bail!("PE signature is missing or out of bounds");
        }
        Ok(())
    }
}

pub struct ElfAdapter;

impl FormatAdapter for ElfAdapter {
    fn kind(&self) -> FormatKind {
        FormatKind::Elf
    }

    fn detect(&self, data: &[u8]) -> bool {
        data.starts_with(b"\x7fELF")
    }

    fn validate(&self, data: &[u8]) -> Result<()> {
        if !self.detect(data) {
            bail!("input does not have an ELF signature");
        }
        Ok(())
    }
}

pub struct MachOAdapter;

impl FormatAdapter for MachOAdapter {
    fn kind(&self) -> FormatKind {
        FormatKind::MachO
    }

    fn detect(&self, data: &[u8]) -> bool {
        matches!(
            data.get(..4),
            Some(b"\xfe\xed\xfa\xce")
                | Some(b"\xce\xfa\xed\xfe")
                | Some(b"\xfe\xed\xfa\xcf")
                | Some(b"\xcf\xfa\xed\xfe")
        )
    }

    fn validate(&self, data: &[u8]) -> Result<()> {
        if !self.detect(data) {
            bail!("input does not have a Mach-O signature");
        }
        Ok(())
    }
}

pub fn detect_format(data: &[u8]) -> FormatKind {
    let adapters: [&dyn FormatAdapter; 4] = [
        &JarAdapter,
        &PeAdapter,
        &ElfAdapter,
        &MachOAdapter,
    ];
    adapters
        .into_iter()
        .find(|adapter| adapter.detect(data))
        .map(|adapter| adapter.kind())
        .unwrap_or(FormatKind::Generic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_signatures() {
        assert_eq!(detect_format(b"MZ"), FormatKind::Pe);
        assert_eq!(detect_format(b"PK\x03\x04"), FormatKind::Jar);
        assert_eq!(detect_format(b"\x7fELF"), FormatKind::Elf);
        assert_eq!(detect_format(b"\xfe\xed\xfa\xce"), FormatKind::MachO);
        assert_eq!(detect_format(b"hello"), FormatKind::Generic);
    }

    #[test]
    fn rejects_truncated_pe() {
        assert!(PeAdapter.validate(b"MZ").is_err());
    }
}
