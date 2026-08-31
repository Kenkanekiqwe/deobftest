use anyhow::{bail, Result};

use super::pipeline::Transform;
use super::ProtectionProfile;

/// A format-neutral validation pass. It intentionally does not rewrite
/// executable bytes: format-specific transformations must be implemented by
/// the corresponding backend so protected programs remain functional.
pub struct IntegrityGuard;

impl Transform for IntegrityGuard {
    fn name(&self) -> &'static str {
        "integrity-check"
    }

    fn apply(&self, data: Vec<u8>, _: &ProtectionProfile) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("artifact became empty during transformation");
        }
        Ok(data)
    }
}

pub struct SizeInvariant;

impl Transform for SizeInvariant {
    fn name(&self) -> &'static str {
        "size-invariant"
    }

    fn apply(&self, data: Vec<u8>, _: &ProtectionProfile) -> Result<Vec<u8>> {
        if data.len() > u32::MAX as usize {
            bail!("artifact exceeds supported size");
        }
        Ok(data)
    }
}

/// Records the selected backend capabilities without pretending that a
/// generic byte stream can safely undergo PE/Java/Python transformations.
/// The actual byte-level protection is supplied by the authenticated package
/// layer in `engine.rs`.
pub struct CapabilityGuard;

impl Transform for CapabilityGuard {
    fn name(&self) -> &'static str {
        "backend-capability-check"
    }

    fn apply(&self, data: Vec<u8>, profile: &ProtectionProfile) -> Result<Vec<u8>> {
        if profile.integrity && profile.verify_after_pass && data.is_empty() {
            bail!("invalid empty artifact");
        }
        Ok(data)
    }
}
