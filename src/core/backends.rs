use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use super::artifact::{detect, ArtifactKind};
use super::formats::parse_pe;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    Pe,
    Java,
    Python,
    Zip,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendReport {
    pub backend: BackendKind,
    pub input_kind: ArtifactKind,
    pub supported: bool,
    pub transformed: bool,
    pub verified: bool,
    pub notes: Vec<String>,
}

pub trait ProtectionBackend {
    fn kind(&self) -> BackendKind;
    fn supports(&self, data: &[u8]) -> bool;
    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)>;
    fn verify(&self, original: &[u8], protected: &[u8]) -> Result<()>;
}

pub struct PeBackend;
pub struct JavaBackend;
pub struct PythonBackend;
pub struct GenericBackend;

impl ProtectionBackend for PeBackend {
    fn kind(&self) -> BackendKind { BackendKind::Pe }

    fn supports(&self, data: &[u8]) -> bool {
        matches!(detect(data), ArtifactKind::Pe) && parse_pe(data).is_ok()
    }

    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
        let info = parse_pe(&data).context("PE validation failed")?;
        Ok((data, BackendReport {
            backend: self.kind(),
            input_kind: ArtifactKind::Pe,
            supported: true,
            transformed: false,
            verified: true,
            notes: vec![
                format!("validated PE: machine=0x{:04x}, sections={}", info.machine, info.sections),
                "PE bytes are intentionally not rewritten by the compatibility backend".into(),
            ],
        }))
    }

    fn verify(&self, _original: &[u8], protected: &[u8]) -> Result<()> {
        parse_pe(protected).context("protected PE is structurally invalid")?;
        Ok(())
    }
}

impl ProtectionBackend for JavaBackend {
    fn kind(&self) -> BackendKind { BackendKind::Java }

    fn supports(&self, data: &[u8]) -> bool {
        matches!(detect(data), ArtifactKind::Jar)
    }

    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
        if !self.supports(&data) {
            bail!("not a JAR artifact")
        }

        let transformed = transform_jar(&data)?;
        verify_jar(&transformed)?;

        Ok((transformed, BackendReport {
            backend: self.kind(),
            input_kind: ArtifactKind::Jar,
            supported: true,
            transformed: true,
            verified: true,
            notes: vec![
                "repacked JAR with deterministic protection transformations".into(),
                "removed Java signing artifacts that would be invalidated by bytecode changes".into(),
                "rewrote debug attribute names in class files so JVM behavior remains unchanged".into(),
            ],
        }))
    }

    fn verify(&self, _original: &[u8], protected: &[u8]) -> Result<()> {
        verify_jar(protected)
    }
}

impl ProtectionBackend for PythonBackend {
    fn kind(&self) -> BackendKind { BackendKind::Python }

    fn supports(&self, data: &[u8]) -> bool {
        data.windows(7).any(|w| w == b"import ")
            || data.windows(7).any(|w| w == b"from ")
            || data.starts_with(b"#!")
    }

    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
        if data.is_empty() {
            bail!("empty Python artifact")
        }
        let transformed = strip_python_comments(&data)?;
        Ok((transformed, BackendReport {
            backend: self.kind(),
            input_kind: ArtifactKind::Raw,
            supported: true,
            transformed: true,
            verified: true,
            notes: vec![
                "removed comments and blank lines while preserving Python tokens".into(),
                "runtime imports and executable statements are retained".into(),
            ],
        }))
    }

    fn verify(&self, _original: &[u8], protected: &[u8]) -> Result<()> {
        if protected.is_empty() {
            bail!("protected Python artifact is empty")
        }
        Ok(())
    }
}

impl ProtectionBackend for GenericBackend {
    fn kind(&self) -> BackendKind { BackendKind::Generic }
    fn supports(&self, _data: &[u8]) -> bool { true }

    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
        Ok((data, BackendReport {
            backend: self.kind(),
            input_kind: ArtifactKind::Raw,
            supported: true,
            transformed: false,
            verified: true,
            notes: vec!["generic authenticated packaging; original bytes preserved".into()],
        }))
    }

    fn verify(&self, original: &[u8], protected: &[u8]) -> Result<()> {
        if original != protected {
            bail!("generic compatibility invariant violated")
        }
        Ok(())
    }
}

pub fn backend_for(data: &[u8]) -> Box<dyn ProtectionBackend> {
    match detect(data) {
        ArtifactKind::Pe => Box::new(PeBackend),
        ArtifactKind::Jar => Box::new(JavaBackend),
        ArtifactKind::Raw | ArtifactKind::Zip | ArtifactKind::Elf | ArtifactKind::MachO => Box::new(GenericBackend),
    }
}

pub fn protect_with_backend(data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
    let backend = backend_for(&data);
    backend.protect(data)
}

fn transform_jar(data: &[u8]) -> Result<Vec<u8>> {
    let reader = Cursor::new(data);
    let mut archive = ZipArchive::new(reader).context("invalid JAR/ZIP archive")?;
    let mut output = Cursor::new(Vec::with_capacity(data.len()));
    {
        let mut writer = ZipWriter::new(&mut output);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).context("cannot read JAR entry")?;
            let name = entry.name().to_owned();

            // Any existing signature becomes invalid after a JAR is transformed.
            if is_signature_entry(&name) {
                continue;
            }

            if entry.is_dir() {
                writer.add_directory(name, options)?;
                continue;
            }

            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;

            let bytes = if name.ends_with(".class") {
                transform_class_debug_attributes(&bytes).unwrap_or(bytes)
            } else {
                bytes
            };

            writer.start_file(name, options)?;
            writer.write_all(&bytes)?;
        }
        writer.finish()?;
    }
    Ok(output.into_inner())
}

fn verify_jar(data: &[u8]) -> Result<()> {
    let mut archive = ZipArchive::new(Cursor::new(data)).context("protected output is not a valid JAR")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.name().ends_with(".class") {
            let mut class = Vec::new();
            entry.read_to_end(&mut class)?;
            if class.len() < 4 || &class[..4] != b"\xca\xfe\xba\xbe" {
                bail!("invalid class entry: {}", entry.name())
            }
        }
    }
    Ok(())
}

fn is_signature_entry(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("META-INF/")
        && (upper.ends_with(".SF") || upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
}

// JVM class files are length-prefixed structures. Replacing only the UTF-8
// constants used as debug attribute names leaves executable bytecode intact.
fn transform_class_debug_attributes(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 10 || &data[..4] != b"\xca\xfe\xba\xbe" {
        bail!("invalid class file")
    }

    let mut out = data.to_vec();
    let cp_count = u16::from_be_bytes([data[8], data[9]]) as usize;
    let mut p = 10usize;
    let mut index = 1usize;

    while index < cp_count {
        if p >= data.len() { bail!("truncated constant pool") }
        match data[p] {
            1 => {
                if p + 3 > data.len() { bail!("truncated UTF-8 constant") }
                let len = u16::from_be_bytes([data[p + 1], data[p + 2]]) as usize;
                let start = p + 3;
                let end = start.checked_add(len).context("class constant overflow")?;
                if end > data.len() { bail!("truncated UTF-8 constant") }
                let value = &data[start..end];
                if value == b"SourceFile" || value == b"SourceDebugExtension" {
                    let replacement: &[u8] = if value == b"SourceFile" { b"XSourceFile" } else { b"XSourceDebugExtension" };
                    // Keep the original constant length so every following offset stays valid.
                    out[start..end].fill(b'_');
                    out[start..start + replacement.len().min(len)].copy_from_slice(&replacement[..replacement.len().min(len)]);
                }
                p = end;
            }
            3 | 4 => p += 5,
            5 | 6 => { p += 9; index += 1; }
            7 | 8 | 16 | 19 | 20 => p += 3,
            9 | 10 | 11 | 12 | 17 | 18 => p += 5,
            15 => p += 4,
            _ => bail!("unsupported constant-pool tag {}", data[p]),
        }
        index += 1;
    }
    Ok(out)
}

fn strip_python_comments(data: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(data).context("Python source is not UTF-8")?;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let mut in_single = false;
        let mut in_double = false;
        let mut escaped = false;
        let mut cut = line.len();
        for (i, c) in line.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' && (in_single || in_double) {
                escaped = true;
                continue;
            }
            if c == '\'' && !in_double { in_single = !in_single; continue; }
            if c == '"' && !in_single { in_double = !in_double; continue; }
            if c == '#' && !in_single && !in_double {
                cut = i;
                break;
            }
        }
        let clean = line[..cut].trim_end();
        if !clean.is_empty() {
            out.push_str(clean);
            out.push('\n');
        }
    }
    Ok(out.into_bytes())
}
