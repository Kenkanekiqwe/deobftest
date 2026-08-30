use anyhow::{bail, Result};

use super::pipeline::Transform;
use super::ProtectionProfile;

/// Validation-only pass. It deliberately does not mutate artifact bytes.
/// Integrity for protected packages is provided by the authenticated container
/// trailer in the protection engine, so this pass must never append metadata to
/// the payload itself.
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
