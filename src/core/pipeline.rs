use anyhow::Result;

use super::ProtectionProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass { Analyze, StripDebug, ProtectStrings, RenameSymbols, Verify }

pub trait Transform {
    fn name(&self) -> &'static str;
    fn apply(&self, data: Vec<u8>, profile: &ProtectionProfile) -> Result<Vec<u8>>;
}

pub struct Pipeline { passes: Vec<Box<dyn Transform + Send + Sync>> }

impl Pipeline {
    pub fn new() -> Self { Self { passes: Vec::new() } }
    pub fn add<T: Transform + Send + Sync + 'static>(mut self, pass: T) -> Self { self.passes.push(Box::new(pass)); self }
    pub fn run(&self, mut data: Vec<u8>, profile: &ProtectionProfile) -> Result<Vec<u8>> {
        for pass in &self.passes { data = pass.apply(data, profile)?; }
        Ok(data)
    }
    pub fn names(&self) -> Vec<&'static str> { self.passes.iter().map(|p| p.name()).collect() }
}

impl Default for Pipeline { fn default() -> Self { Self::new() } }

pub struct IdentityPass;
impl Transform for IdentityPass {
    fn name(&self) -> &'static str { "identity" }
    fn apply(&self, data: Vec<u8>, _: &ProtectionProfile) -> Result<Vec<u8>> { Ok(data) }
}

pub struct VerifyPass;
impl Transform for VerifyPass {
    fn name(&self) -> &'static str { "verify" }
    fn apply(&self, data: Vec<u8>, _: &ProtectionProfile) -> Result<Vec<u8>> {
        if data.is_empty() { anyhow::bail!("input artifact is empty"); }
        Ok(data)
    }
}
