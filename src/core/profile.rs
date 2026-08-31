use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Strength {
    Safe,
    Balanced,
    Maximum,
}

/// Protection capabilities exposed by the engine.  These flags describe
/// transformations that preserve the original program's runtime contract;
/// unsupported transformations must never be silently advertised as active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionProfile {
    pub name: String,
    pub strength: Strength,
    pub strip_debug: bool,
    pub protect_strings: bool,
    pub rename_symbols: bool,
    pub control_flow: bool,
    pub resource_protection: bool,
    pub anti_tamper: bool,
    pub verify_after_pass: bool,
    pub integrity: bool,
}

impl ProtectionProfile {
    pub fn safe() -> Self {
        Self {
            name: "safe".into(),
            strength: Strength::Safe,
            strip_debug: false,
            protect_strings: false,
            rename_symbols: false,
            control_flow: false,
            resource_protection: true,
            anti_tamper: true,
            verify_after_pass: true,
            integrity: true,
        }
    }

    pub fn balanced() -> Self {
        Self {
            name: "balanced".into(),
            strength: Strength::Balanced,
            strip_debug: true,
            protect_strings: true,
            rename_symbols: true,
            control_flow: true,
            resource_protection: true,
            anti_tamper: true,
            verify_after_pass: true,
            integrity: true,
        }
    }

    pub fn maximum() -> Self {
        Self {
            name: "maximum".into(),
            strength: Strength::Maximum,
            strip_debug: true,
            protect_strings: true,
            rename_symbols: true,
            control_flow: true,
            resource_protection: true,
            anti_tamper: true,
            verify_after_pass: true,
            integrity: true,
        }
    }

    pub fn from_strength(strength: Strength) -> Self {
        match strength {
            Strength::Safe => Self::safe(),
            Strength::Balanced => Self::balanced(),
            Strength::Maximum => Self::maximum(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.name.trim().is_empty() {
            anyhow::bail!("profile name must not be empty");
        }
        if !self.verify_after_pass {
            anyhow::bail!("verify_after_pass must remain enabled");
        }
        if !self.integrity {
            anyhow::bail!("integrity protection must remain enabled");
        }
        Ok(())
    }
}

impl Default for ProtectionProfile {
    fn default() -> Self {
        Self::balanced()
    }
}
