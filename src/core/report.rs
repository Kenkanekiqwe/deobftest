use serde::Serialize;

use super::analyzer::{Analysis, Architecture};
use super::artifact::ArtifactKind;

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub format: String,
    pub architecture: String,
    pub executable: bool,
    pub debug_markers: bool,
    pub archive_signature: bool,
    pub warnings: Vec<String>,
}

impl From<Analysis> for AnalysisReport {
    fn from(a: Analysis) -> Self {
        let mut warnings = Vec::new();
        if a.has_debug_markers { warnings.push("debug metadata detected".into()); }
        if matches!(a.kind, ArtifactKind::Unknown) { warnings.push("unknown artifact format".into()); }
        if matches!(a.architecture, Architecture::Unknown) && a.executable { warnings.push("architecture could not be determined".into()); }
        Self {
            format: format!("{:?}", a.kind),
            architecture: format!("{:?}", a.architecture),
            executable: a.executable,
            debug_markers: a.has_debug_markers,
            archive_signature: a.has_archive_signature,
            warnings,
        }
    }
}
