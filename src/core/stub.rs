use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::{env, fs};

/// Trailer appended after a Windows PE stub and the authenticated DEOBF container.
/// Layout (64 bytes at EOF):
///   0..8   magic `DEOBFS01`
///   8..16  container offset (u64 LE)
///   16..24 container size (u64 LE)
///   24     runtime kind: 0=pe, 1=jar, 2=python
///   25..32 reserved
///   32..64 BLAKE3(b"DEOBF-STUB-V1" || container)
///
/// Optional auto-key record sits between the container and the trailer:
///   0..8   magic `DEOBFK01`
///   8      version = 1
///   9      flags: bit0 = raw AEAD key present
///   10..16 reserved
///   16..48 32-byte XChaCha20-Poly1305 key
pub const STUB_MAGIC: &[u8; 8] = b"DEOBFS01";
pub const STUB_TRAILER_LEN: usize = 64;
pub const KIND_PE: u8 = 0;
pub const KIND_JAR: u8 = 1;
pub const KIND_PYTHON: u8 = 2;
pub const KEY_MAGIC: &[u8; 8] = b"DEOBFK01";
pub const KEY_RECORD_LEN: usize = 48;
pub const AUTO_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StubTrailer {
    pub container_offset: u64,
    pub container_size: u64,
    pub kind: u8,
}

pub fn parse_trailer(file: &[u8]) -> Option<StubTrailer> {
    if file.len() < STUB_TRAILER_LEN {
        return None;
    }
    let trailer = &file[file.len() - STUB_TRAILER_LEN..];
    if &trailer[0..8] != STUB_MAGIC {
        return None;
    }
    let container_offset = u64::from_le_bytes(trailer[8..16].try_into().ok()?);
    let container_size = u64::from_le_bytes(trailer[16..24].try_into().ok()?);
    let kind = trailer[24];
    if !matches!(kind, KIND_PE | KIND_JAR | KIND_PYTHON) {
        return None;
    }
    let start = usize::try_from(container_offset).ok()?;
    let size = usize::try_from(container_size).ok()?;
    let end = start.checked_add(size)?;
    let trailer_at = file.len() - STUB_TRAILER_LEN;
    if end > trailer_at || start > trailer_at {
        return None;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"DEOBF-STUB-V1");
    hasher.update(&file[start..end]);
    if hasher.finalize().as_bytes() != &trailer[32..64] {
        return None;
    }
    Some(StubTrailer {
        container_offset,
        container_size,
        kind,
    })
}

pub fn extract_container(file: &[u8]) -> Option<&[u8]> {
    let trailer = parse_trailer(file)?;
    let start = trailer.container_offset as usize;
    let end = start + trailer.container_size as usize;
    Some(&file[start..end])
}

pub fn extract(file: &[u8]) -> Option<(Vec<u8>, u8)> {
    let trailer = parse_trailer(file)?;
    let start = trailer.container_offset as usize;
    let end = start + trailer.container_size as usize;
    Some((file[start..end].to_vec(), trailer.kind))
}

pub fn encode_key_record(key: &[u8; AUTO_KEY_LEN]) -> [u8; KEY_RECORD_LEN] {
    let mut rec = [0u8; KEY_RECORD_LEN];
    rec[0..8].copy_from_slice(KEY_MAGIC);
    rec[8] = 1;
    rec[9] = 1;
    rec[16..48].copy_from_slice(key);
    rec
}

pub fn parse_key_record(bytes: &[u8]) -> Option<[u8; AUTO_KEY_LEN]> {
    if bytes.len() != KEY_RECORD_LEN {
        return None;
    }
    if &bytes[0..8] != KEY_MAGIC {
        return None;
    }
    if bytes[8] != 1 {
        return None;
    }
    if bytes[9] & 1 == 0 {
        return None;
    }
    let mut key = [0u8; AUTO_KEY_LEN];
    key.copy_from_slice(&bytes[16..48]);
    Some(key)
}

/// Locate a packer-style auto-key: overlay record on a stub PE, or a trailing
/// record on a raw DEOBF container (JAR/Python/legacy-extension packages).
pub fn extract_embedded_key(file: &[u8]) -> Option<[u8; AUTO_KEY_LEN]> {
    if let Some(trailer) = parse_trailer(file) {
        let container_end = usize::try_from(trailer.container_offset)
            .ok()?
            .checked_add(usize::try_from(trailer.container_size).ok()?)?;
        let trailer_at = file.len() - STUB_TRAILER_LEN;
        if trailer_at >= container_end + KEY_RECORD_LEN {
            return parse_key_record(&file[trailer_at - KEY_RECORD_LEN..trailer_at]);
        }
        return None;
    }
    if file.len() >= KEY_RECORD_LEN {
        return parse_key_record(&file[file.len() - KEY_RECORD_LEN..]);
    }
    None
}

fn stub_prefix(image: &[u8]) -> &[u8] {
    match parse_trailer(image) {
        Some(trailer) => &image[..trailer.container_offset as usize],
        None => image,
    }
}

pub fn wrap_stub(
    stub: &[u8],
    container: &[u8],
    kind: u8,
    embedded_key: Option<&[u8; AUTO_KEY_LEN]>,
) -> Result<Vec<u8>> {
    if !matches!(kind, KIND_PE | KIND_JAR | KIND_PYTHON) {
        bail!("unsupported stub runtime kind {kind}");
    }
    let stub = stub_prefix(stub);
    if stub.len() < 2 || &stub[..2] != b"MZ" {
        bail!("runtime stub is not a Windows PE image");
    }
    let extra = if embedded_key.is_some() {
        KEY_RECORD_LEN
    } else {
        0
    };
    let mut out = Vec::with_capacity(stub.len() + container.len() + extra + STUB_TRAILER_LEN);
    out.extend_from_slice(stub);
    let offset = out.len() as u64;
    out.extend_from_slice(container);
    if let Some(key) = embedded_key {
        out.extend_from_slice(&encode_key_record(key));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"DEOBF-STUB-V1");
    hasher.update(container);
    let digest = hasher.finalize();
    let mut trailer = [0u8; STUB_TRAILER_LEN];
    trailer[0..8].copy_from_slice(STUB_MAGIC);
    trailer[8..16].copy_from_slice(&offset.to_le_bytes());
    trailer[16..24].copy_from_slice(&(container.len() as u64).to_le_bytes());
    trailer[24] = kind;
    trailer[32..64].copy_from_slice(digest.as_bytes());
    out.extend_from_slice(&trailer);
    Ok(out)
}

/// Locate a PE image that contains `run_embedded_stub`.
/// Prefer the compile-time embedded tiny stub so Protect never wraps the iced GUI exe.
pub fn load_stub_image() -> Result<Vec<u8>> {
    #[cfg(deobf_embedded_stub)]
    {
        const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/deobf-stub.bin"));
        if EMBEDDED.len() >= 2 && EMBEDDED.starts_with(b"MZ") {
            return Ok(stub_prefix(EMBEDDED).to_vec());
        }
    }

    if let Ok(path) = env::var("DEOBF_STUB_PATH") {
        let bytes = fs::read(&path).with_context(|| format!("read DEOBF_STUB_PATH {path}"))?;
        return Ok(stub_prefix(&bytes).to_vec());
    }
    let exe = env::current_exe().context("resolve current executable")?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = exe.parent() {
        for name in ["deobf-stub.exe", "deobf-stub"] {
            candidates.push(dir.join(name));
        }
        if let Some(parent) = dir.parent() {
            for name in ["deobf-stub.exe", "deobf-stub"] {
                candidates.push(parent.join(name));
            }
        }
        // Sibling deobf.exe only when no embedded stub (avoid wrapping the iced GUI image).
        #[cfg(not(deobf_embedded_stub))]
        {
            for name in ["deobf.exe", "deobf"] {
                candidates.push(dir.join(name));
            }
            if let Some(parent) = dir.parent() {
                for name in ["deobf.exe", "deobf"] {
                    candidates.push(parent.join(name));
                }
            }
        }
    }
    for candidate in candidates {
        if candidate == exe || !candidate.is_file() {
            continue;
        }
        if let Ok(bytes) = fs::read(&candidate) {
            if bytes.len() >= 2 && bytes.starts_with(b"MZ") && parse_trailer(&bytes).is_none() {
                return Ok(bytes);
            }
        }
    }
    #[cfg(not(deobf_embedded_stub))]
    {
        let stem = exe.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if matches!(stem, "deobf" | "deobf-gui" | "deobf-stub") {
            let bytes = fs::read(&exe).with_context(|| format!("read {}", exe.display()))?;
            if bytes.len() >= 2 && bytes.starts_with(b"MZ") {
                return Ok(stub_prefix(&bytes).to_vec());
            }
        }
    }
    bail!(
        "Windows runtime stub not found (looked for embedded stub, deobf-stub next to {}, or DEOBF_STUB_PATH)",
        exe.display()
    )
}

pub fn load_stub_or_fallback() -> Vec<u8> {
    load_stub_image()
        .ok()
        .filter(|bytes| bytes.len() >= 2 && bytes.starts_with(b"MZ"))
        .unwrap_or_else(fallback_pe_stub)
}

/// Tiny x64 PE that calls kernel32!ExitProcess(0). Used when a full DEOBF
/// loader binary is not available so Protect still writes a launchable PE.
pub fn fallback_pe_stub() -> Vec<u8> {
    const FILE_ALIGN: usize = 0x200;
    const SECTION_ALIGN: usize = 0x1000;
    let mut image = vec![0u8; 0x600];

    // DOS header
    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());

    // PE signature + COFF
    let pe = 0x40usize;
    image[pe..pe + 4].copy_from_slice(b"PE\0\0");
    image[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    image[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes()); // sections
    image[pe + 20..pe + 22].copy_from_slice(&0x00f0u16.to_le_bytes()); // optional header size
    image[pe + 22..pe + 24].copy_from_slice(&0x0023u16.to_le_bytes()); // relocs stripped, executable, LA

    // Optional header PE32+
    let opt = pe + 24;
    image[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    image[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    image[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
    image[opt + 32..opt + 36].copy_from_slice(&(SECTION_ALIGN as u32).to_le_bytes());
    image[opt + 36..opt + 40].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes());
    image[opt + 40..opt + 42].copy_from_slice(&6u16.to_le_bytes()); // MajorOperatingSystemVersion
    image[opt + 48..opt + 50].copy_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
    image[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    image[opt + 60..opt + 64].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes()); // SizeOfHeaders
    image[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // CONSOLE subsystem
    image[opt + 70..opt + 72].copy_from_slice(&0x0100u16.to_le_bytes()); // NX_COMPAT
    image[opt + 72..opt + 80].copy_from_slice(&0x10_0000u64.to_le_bytes()); // StackReserve
    image[opt + 80..opt + 88].copy_from_slice(&0x1000u64.to_le_bytes()); // StackCommit
    image[opt + 88..opt + 96].copy_from_slice(&0x10_0000u64.to_le_bytes()); // HeapReserve
    image[opt + 96..opt + 104].copy_from_slice(&0x1000u64.to_le_bytes()); // HeapCommit
    image[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
                                                                       // DataDirectory[1] import
    image[opt + 120..opt + 124].copy_from_slice(&0x2000u32.to_le_bytes());
    image[opt + 124..opt + 128].copy_from_slice(&40u32.to_le_bytes());

    // .text section header
    let s1 = opt + 240;
    image[s1..s1 + 5].copy_from_slice(b".text");
    image[s1 + 8..s1 + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
    image[s1 + 12..s1 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    image[s1 + 16..s1 + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    image[s1 + 20..s1 + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    image[s1 + 36..s1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // .idata section header
    let s2 = s1 + 40;
    image[s2..s2 + 6].copy_from_slice(b".idata");
    image[s2 + 8..s2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[s2 + 12..s2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    image[s2 + 16..s2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[s2 + 20..s2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    image[s2 + 36..s2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // .text: sub rsp,28h; xor ecx,ecx; call [rip+IAT]
    // RIP after the call instruction = 0x100C; IAT RVA = 0x2038; rel = 0x102C
    let text = [
        0x48, 0x83, 0xEC, 0x28, 0x31, 0xC9, 0xFF, 0x15, 0x2C, 0x10, 0x00, 0x00,
    ];
    image[0x200..0x200 + text.len()].copy_from_slice(&text);

    // .idata at file offset 0x400 = RVA 0x2000
    let idata = 0x400usize;
    // Import directory[0]
    image[idata..idata + 4].copy_from_slice(&0x2028u32.to_le_bytes()); // OriginalFirstThunk / INT
    image[idata + 12..idata + 16].copy_from_slice(&0x2058u32.to_le_bytes()); // Name
    image[idata + 16..idata + 20].copy_from_slice(&0x2038u32.to_le_bytes()); // FirstThunk / IAT
                                                                             // INT at 0x2028
    image[idata + 0x28..idata + 0x30].copy_from_slice(&0x2048u64.to_le_bytes());
    // IAT at 0x2038
    image[idata + 0x38..idata + 0x40].copy_from_slice(&0x2048u64.to_le_bytes());
    // Hint/Name at 0x2048
    image[idata + 0x48..idata + 0x4A].copy_from_slice(&0u16.to_le_bytes());
    image[idata + 0x4A..idata + 0x4A + 12].copy_from_slice(b"ExitProcess\0");
    // DLL name at 0x2058
    image[idata + 0x58..idata + 0x58 + 13].copy_from_slice(b"kernel32.dll\0");

    image
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_and_extract_roundtrip() {
        let stub = fallback_pe_stub();
        assert!(stub.starts_with(b"MZ"));
        let container = b"DEOBF01\0fake-container-bytes";
        let wrapped = wrap_stub(&stub, container, KIND_PE, None).unwrap();
        assert!(wrapped.starts_with(b"MZ"));
        let (got, kind) = extract(&wrapped).unwrap();
        assert_eq!(kind, KIND_PE);
        assert_eq!(got, container);
        assert!(extract_embedded_key(&wrapped).is_none());
    }

    #[test]
    fn wrap_embeds_auto_key_between_container_and_trailer() {
        let stub = fallback_pe_stub();
        let container = b"DEOBF01\0fake-container-bytes";
        let key = [0x5Au8; AUTO_KEY_LEN];
        let wrapped = wrap_stub(&stub, container, KIND_PE, Some(&key)).unwrap();
        assert!(wrapped.starts_with(b"MZ"));
        let (got, kind) = extract(&wrapped).unwrap();
        assert_eq!(kind, KIND_PE);
        assert_eq!(got, container);
        assert_eq!(extract_embedded_key(&wrapped).unwrap(), key);
    }

    #[test]
    fn trailing_key_record_on_raw_container() {
        let mut file = b"DEOBF01\0not-a-stub".to_vec();
        let key = [0x11u8; AUTO_KEY_LEN];
        file.extend_from_slice(&encode_key_record(&key));
        assert_eq!(extract_embedded_key(&file).unwrap(), key);
    }

    #[test]
    fn rejects_tampered_trailer() {
        let stub = fallback_pe_stub();
        let mut wrapped = wrap_stub(&stub, b"payload", KIND_PE, None).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 1;
        assert!(extract(&wrapped).is_none());
    }
}
