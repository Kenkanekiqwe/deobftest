use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat { Pe, Elf, MachO, Zip, Raw }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInfo {
    pub machine: u16,
    pub sections: u16,
    pub characteristics: u16,
    pub optional_magic: Option<u16>,
}

pub fn parse_pe(data: &[u8]) -> Result<PeInfo> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { bail!("not a PE image") }
    let off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    if off.checked_add(24).is_none() || data.len() < off + 24 || &data[off..off+4] != b"PE\0\0" {
        bail!("invalid PE header")
    }
    let machine = u16::from_le_bytes(data[off+4..off+6].try_into().unwrap());
    let sections = u16::from_le_bytes(data[off+6..off+8].try_into().unwrap());
    let opt_size = u16::from_le_bytes(data[off+20..off+22].try_into().unwrap()) as usize;
    let characteristics = u16::from_le_bytes(data[off+22..off+24].try_into().unwrap());
    let optional_magic = if opt_size >= 2 && data.len() >= off + 26 {
        Some(u16::from_le_bytes(data[off+24..off+26].try_into().unwrap()))
    } else { None };
    Ok(PeInfo { machine, sections, characteristics, optional_magic })
}

pub fn zip_has_manifest(data: &[u8]) -> bool {
    data.windows(8).any(|w| w == b"META-INF/")
}
