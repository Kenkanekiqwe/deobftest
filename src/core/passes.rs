use anyhow::{bail, Result};
use blake3::Hasher;

use super::pipeline::Transform;
use super::ProtectionProfile;

pub struct IntegrityGuard;

impl Transform for IntegrityGuard {
    fn name(&self) -> &'static str { "integrity-guard" }
    fn apply(&self, data: Vec<u8>, _: &ProtectionProfile) -> Result<Vec<u8>> {
        if data.is_empty() { bail!("artifact became empty during transformation"); }
        let mut h = Hasher::new();
        h.update(b"DEOBF-PASS-INTEGRITY");
        h.update(&data);
        let digest = h.finalize();
        let mut out = Vec::with_capacity(data.len() + 32);
        out.extend_from_slice(&data);
        out.extend_from_slice(digest.as_bytes());
        Ok(out)
    }
}

pub struct SizeInvariant;

impl Transform for SizeInvariant {
    fn name(&self) -> &'static str { "size-invariant" }
    fn apply(&self, data: Vec<u8>, _: &ProtectionProfile) -> Result<Vec<u8>> {
        if data.len() > u32::MAX as usize { bail!("artifact exceeds supported size"); }
        Ok(data)
    }
}
