use anyhow::{bail, Result};

use super::{Analysis, ArtifactKind, ProtectionProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub supported: bool,
    pub warnings: Vec<String>,
}

pub fn validate(analysis: &Analysis, profile: &ProtectionProfile) -> Result<ValidationReport> {
    profile.validate()?;

    let mut warnings = Vec::new();
    if analysis.kind == ArtifactKind::Raw {
        warnings.push("raw input has no executable format metadata".to_owned());
    }
    if analysis.has_debug_markers {
        warnings.push("debug-related markers were detected".to_owned());
    }
    if !analysis.executable && matches!(analysis.kind, ArtifactKind::Pe | ArtifactKind::Elf | ArtifactKind::MachO) {
        bail!("artifact metadata is inconsistent");
    }

    Ok(ValidationReport { supported: true, warnings })
}
