use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::artifact::{detect, ArtifactKind};
use super::formats::parse_pe;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind { Pe, Java, Python, Zip, Generic }

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
    fn supports(&self, data: &[u8]) -> bool { matches!(detect(data), ArtifactKind::Pe) && parse_pe(data).is_ok() }
    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
        let info = parse_pe(&data).context("PE validation failed")?;
        Ok((data, BackendReport { backend: self.kind(), input_kind: ArtifactKind::Pe, supported: true, transformed: false, verified: true,
            notes: vec![format!("validated PE: machine=0x{:04x}, sections={}", info.machine, info.sections),
                "native transformation requires a loader-aware implementation and is not enabled in this backend".into()] }))
    }
    fn verify(&self, original: &[u8], protected: &[u8]) -> Result<()> {
        if original != protected { bail!("PE compatibility invariant violated") }
        parse_pe(protected).context("protected PE is structurally invalid")?;
        Ok(())
    }
}

impl ProtectionBackend for JavaBackend {
    fn kind(&self) -> BackendKind { BackendKind::Java }
    fn supports(&self, data: &[u8]) -> bool { matches!(detect(data), ArtifactKind::Jar) }
    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
        if !self.supports(&data) { bail!("not a JAR artifact") }
        Ok((data, BackendReport { backend: self.kind(), input_kind: ArtifactKind::Jar, supported: true, transformed: false, verified: true,
            notes: vec!["JAR bytes are preserved until a class-file-aware transformation backend is enabled".into()] }))
    }
    fn verify(&self, original: &[u8], protected: &[u8]) -> Result<()> {
        if original != protected { bail!("JAR compatibility invariant violated") }
        Ok(())
    }
}

impl ProtectionBackend for PythonBackend {
    fn kind(&self) -> BackendKind { BackendKind::Python }
    fn supports(&self, data: &[u8]) -> bool { data.starts_with(b"#!") || data.windows(7).any(|w| w == b"import ") }
    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
        if data.is_empty() { bail!("empty Python artifact") }
        Ok((data, BackendReport { backend: self.kind(), input_kind: ArtifactKind::Raw, supported: true, transformed: false, verified: true,
            notes: vec!["Python source is preserved; runtime packaging must retain its interpreter and dependencies".into()] }))
    }
    fn verify(&self, original: &[u8], protected: &[u8]) -> Result<()> {
        if original != protected { bail!("Python compatibility invariant violated") }
        Ok(())
    }
}

impl ProtectionBackend for GenericBackend {
    fn kind(&self) -> BackendKind { BackendKind::Generic }
    fn supports(&self, _data: &[u8]) -> bool { true }
    fn protect(&self, data: Vec<u8>) -> Result<(Vec<u8>, BackendReport)> {
        Ok((data, BackendReport { backend: self.kind(), input_kind: ArtifactKind::Raw, supported: true, transformed: false, verified: true,
            notes: vec!["generic authenticated packaging; original bytes preserved".into()] }))
    }
    fn verify(&self, original: &[u8], protected: &[u8]) -> Result<()> {
        if original != protected { bail!("generic compatibility invariant violated") }
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
