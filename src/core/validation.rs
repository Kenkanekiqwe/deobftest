use anyhow::Result;

use super::artifact::ArtifactKind;
use super::{Analysis, ProtectionProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub supported: bool,
    pub warnings: Vec<String>,
}

pub fn validate(analysis: &Analysis, profile: &ProtectionProfile) -> Result<ValidationReport> {
    profile.validate()?;

    let mut warnings = Vec::new();
    if analysis.kind == ArtifactKind::Unknown {
        warnings.push("input format is unknown; protection will use generic handling".to_owned());
    }
    if analysis.has_debug_markers {
        warnings.push("debug-related markers were detected".to_owned());
    }
    if !analysis.executable
        && matches!(
            analysis.kind,
            ArtifactKind::Pe | ArtifactKind::Elf | ArtifactKind::MachO
        )
    {
        return Ok(ValidationReport {
            supported: false,
            warnings: vec!["executable format was detected but executable metadata is incomplete".to_owned()],
        });
    }

    Ok(ValidationReport {
        supported: true,
        warnings,
    })
}
