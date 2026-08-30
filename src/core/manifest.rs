use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactKind { Unknown, Generic, Jar, Pe, Elf, MachO }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionManifest {
    pub format_version: u32,
    pub tool_version: String,
    pub artifact: ArtifactKind,
    pub profile: String,
    pub passes: Vec<String>,
    pub original_size: u64,
    pub content_hash: String,
}

impl ProtectionManifest {
    pub fn new(artifact: ArtifactKind, profile: impl Into<String>, size: u64, hash: impl Into<String>) -> Self {
        Self { format_version: 3, tool_version: env!("CARGO_PKG_VERSION").into(), artifact, profile: profile.into(), passes: Vec::new(), original_size: size, content_hash: hash.into() }
    }
}
