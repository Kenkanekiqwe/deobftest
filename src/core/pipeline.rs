use anyhow::{bail, Result};

use super::ProtectionProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    Analyze,
    StripDebug,
    ProtectStrings,
    RenameSymbols,
    Verify,
}

pub trait Transform {
    fn name(&self) -> &'static str;
    fn apply(&self, data: Vec<u8>, profile: &ProtectionProfile) -> Result<Vec<u8>>;
}

pub struct Pipeline {
    passes: Vec<Box<dyn Transform + Send + Sync>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    pub fn with<T: Transform + Send + Sync + 'static>(mut self, pass: T) -> Self {
        self.passes.push(Box::new(pass));
        self
    }

    pub fn push<T: Transform + Send + Sync + 'static>(&mut self, pass: T) {
        self.passes.push(Box::new(pass));
    }

    pub fn run(&self, mut data: Vec<u8>, profile: &ProtectionProfile) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("input artifact is empty");
        }

        for pass in &self.passes {
            data = pass.apply(data, profile)?;
        }
        Ok(data)
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.passes.iter().map(|pass| pass.name()).collect()
    }

    pub fn len(&self) -> usize {
        self.passes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

pub struct IdentityPass;

impl Transform for IdentityPass {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn apply(&self, data: Vec<u8>, _: &ProtectionProfile) -> Result<Vec<u8>> {
        Ok(data)
    }
}

pub struct VerifyPass;

impl Transform for VerifyPass {
    fn name(&self) -> &'static str {
        "verify"
    }

    fn apply(&self, data: Vec<u8>, _: &ProtectionProfile) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("input artifact is empty");
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_preserves_order() {
        let pipeline = Pipeline::new().with(IdentityPass).with(VerifyPass);
        assert_eq!(pipeline.names(), vec!["identity", "verify"]);
        assert_eq!(pipeline.len(), 2);
    }

    #[test]
    fn pipeline_rejects_empty_input() {
        let pipeline = Pipeline::new().with(VerifyPass);
        assert!(pipeline.run(Vec::new(), &ProtectionProfile::safe()).is_err());
    }
}
