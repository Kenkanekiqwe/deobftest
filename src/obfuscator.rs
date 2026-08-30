//! Conservative, deterministic metadata obfuscation primitives.
//! This module is intentionally limited to transformations that preserve behavior.

use anyhow::{bail, Result};
use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub enum Profile {
    Low,
    Medium,
    High,
}

impl Profile {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => bail!("unknown profile: {value}; expected low, medium or high"),
        }
    }
}

/// Detects a Java archive without executing it.
pub fn is_jar(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .map(|x| x.eq_ignore_ascii_case("jar"))
        .unwrap_or(false)
}

/// Returns a safe output suffix for protected artifacts.
pub fn protected_name(path: &Path) -> String {
    let stem = path.file_name().and_then(|x| x.to_str()).unwrap_or("payload");
    format!("{stem}.deobf")
}
