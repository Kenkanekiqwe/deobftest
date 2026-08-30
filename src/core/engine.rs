use anyhow::{Context, Result};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use super::artifact::ArtifactKind;
use super::pipeline::Pipeline;
use super::{analyze, Analysis, IntegrityGuard, ProtectionProfile, SizeInvariant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineOptions {
    pub profile: String,
    pub verify: bool,
    pub add_integrity: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self { profile: "balanced".into(), verify: true, add_integrity: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJson {
    pub kind: String,
    pub architecture: String,
    pub executable: bool,
    pub has_debug_markers: bool,
    pub has_archive_signature: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    pub analysis: AnalysisJson,
    pub input_size: u64,
    pub output_size: u64,
    pub elapsed_ms: u128,
    pub input_hash: String,
    pub output_hash: String,
    pub passes: Vec<String>,
}

impl From<Analysis> for AnalysisJson {
    fn from(a: Analysis) -> Self {
        Self {
            kind: format!("{:?}", a.kind),
            architecture: format!("{:?}", a.architecture),
            executable: a.executable,
            has_debug_markers: a.has_debug_markers,
            has_archive_signature: a.has_archive_signature,
        }
    }
}

fn profile(name: &str) -> ProtectionProfile {
    match name.to_ascii_lowercase().as_str() {
        "safe" => ProtectionProfile::safe(),
        "maximum" | "max" => ProtectionProfile::maximum(),
        _ => ProtectionProfile::balanced(),
    }
}

fn digest(data: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize().to_hex().to_string()
}

pub fn analyze_only(data: &[u8]) -> Result<AnalysisJson> {
    Ok(analyze(data)?.into())
}

pub fn protect(data: Vec<u8>, options: &EngineOptions) -> Result<(Vec<u8>, EngineResult)> {
    let started = Instant::now();
    let analysis = analyze(&data).context("artifact analysis failed")?;
    let selected = profile(&options.profile);
    let mut pipeline = Pipeline::new().add(SizeInvariant);
    if options.add_integrity {
        pipeline = pipeline.add(IntegrityGuard);
    }
    if options.verify {
        pipeline = pipeline.add(super::pipeline::VerifyPass);
    }
    let passes = pipeline.names().into_iter().map(str::to_owned).collect();
    let input_size = data.len() as u64;
    let input_hash = digest(&data);
    let output = pipeline.run(data, &selected).context("protection pipeline failed")?;
    let output_size = output.len() as u64;
    let output_hash = digest(&output);
    Ok((output, EngineResult { analysis: analysis.into(), input_size, output_size, elapsed_ms: started.elapsed().as_millis(), input_hash, output_hash, passes }))
}

pub fn kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Pe => "PE",
        ArtifactKind::Elf => "ELF",
        ArtifactKind::MachO => "Mach-O",
        ArtifactKind::Jar => "JAR",
        ArtifactKind::Unknown => "Unknown",
    }
}
