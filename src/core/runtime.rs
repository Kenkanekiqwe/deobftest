use anyhow::{bail, Context, Result};
use std::{fs, path::{Path, PathBuf}, process::{Command, ExitStatus}};

use super::engine::unprotect_file;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    Pe,
    Jar,
    Python,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pe => "pe",
            Self::Jar => "jar",
            Self::Python => "python",
        }
    }
}

/// Decrypts a protected package only for the lifetime of the child process.
/// The plaintext payload is placed in a temporary directory and removed after exit.
pub fn run_protected(
    package: &Path,
    pass: &[u8],
    kind: RuntimeKind,
    interpreter: Option<&str>,
    args: &[String],
) -> Result<ExitStatus> {
    if !package.is_file() {
        bail!("protected package does not exist: {}", package.display());
    }

    let root = std::env::temp_dir().join(format!("deobf-runtime-{}", std::process::id()));
    fs::create_dir_all(&root).context("create runtime directory")?;
    let payload = root.join(match kind {
        RuntimeKind::Pe => "payload.exe",
        RuntimeKind::Jar => "payload.jar",
        RuntimeKind::Python => "payload.py",
    });

    let result = (|| -> Result<ExitStatus> {
        unprotect_file(package, &payload, pass).context("authenticated package restore")?;
        let status = match kind {
            RuntimeKind::Pe => Command::new(&payload).args(args).status(),
            RuntimeKind::Jar => Command::new(interpreter.unwrap_or("java"))
                .arg("-jar").arg(&payload).args(args).status(),
            RuntimeKind::Python => Command::new(interpreter.unwrap_or("python"))
                .arg(&payload).args(args).status(),
        }
        .with_context(|| format!("launch protected {} payload", kind.as_str()))?;
        Ok(status)
    })();

    let _ = fs::remove_dir_all(&root);
    result
}

pub fn default_runtime_output(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("protected");
    parent.join(format!("{stem}.deobf"))
}
