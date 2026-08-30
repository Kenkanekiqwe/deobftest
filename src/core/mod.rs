pub mod analyzer;
pub mod artifact;
pub mod integrity;
pub mod limits;
pub mod manifest;
pub mod pipeline;
pub mod profile;
pub mod validation;

pub use analyzer::{analyze, Analysis, Architecture};
pub use artifact::ArtifactInfo;
pub use limits::ResourceLimits;
pub use manifest::{ArtifactKind, ProtectionManifest};
pub use pipeline::{Pass, Pipeline};
pub use profile::{ProtectionProfile, Strength};
pub use validation::{validate, ValidationReport};
