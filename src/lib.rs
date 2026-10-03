pub mod core;

pub use crate::core::{
    analyze, analyze_only, analyze_pe_code, default_protected_output, default_runtime_output, has_auto_key, protect,
    protect_compatible, protect_file, run_embedded_stub, run_protected, unprotect_bytes,
    unprotect_file, verify_compatible, Analysis, AnalysisJson, Architecture, ArtifactInfo,
    ArtifactKind, CompatibilityManifest, ContainerInfo, EngineOptions, EngineResult, ExecutableSectionAnalysis, PeCodeAnalysis, Pass,
    Pipeline, ProtectionManifest, ProtectionProfile, ResourceLimits, RuntimeKind, Strength,
};
