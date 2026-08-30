use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Strength {
    Safe,
    Balanced,
    Maximum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionProfile {
    pub name: String,
    pub strength: Strength,
    pub strip_debug: bool,
    pub protect_strings: bool,
    pub rename_symbols: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert!(ProtectionProfile::default().validate().is_ok());
        assert!(ProtectionProfile::maximum().validate().is_ok());
    }

    #[test]
    fn strength_factory_selects_profile() {
        assert_eq!(ProtectionProfile::from_strength(Strength::Safe).strength, Strength::Safe);
        assert_eq!(ProtectionProfile::from_strength(Strength::Balanced).strength, Strength::Balanced);
        assert_eq!(ProtectionProfile::from_strength(Strength::Maximum).strength, Strength::Maximum);
    }
}
