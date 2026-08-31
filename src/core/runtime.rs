use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
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

/// Restores a protected package into a unique temporary directory, executes it,
/// and removes the temporary payload afterwards. The package itself remains
/// encrypted at rest; the original artifact is never rewritten in-place.
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
    if pass.is_empty() {
        bail!("password must not be empty");
    }

    let root = unique_runtime_dir()?;
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
                .arg("-jar")
                .arg(&payload)
                .args(args)
                .status(),
            RuntimeKind::Python => Command::new(interpreter.unwrap_or("python"))
                .arg(&payload)
                .args(args)
                .status(),
        }
        .with_context(|| format!("launch protected {} payload", kind.as_str()))?;

        Ok(status)
    })();

    // Windows can keep a native executable locked until its process exits.
    // `run_protected` waits for the child, so cleanup is safe here. If an
    // interpreter keeps a handle open, leaving the directory is preferable to
    // deleting an unrelated path; the directory is uniquely generated per run.
    let cleanup = fs::remove_dir_all(&root);
    if let Err(error) = cleanup {
        if result.is_ok() {
            return Err(error).with_context(|| format!("cleanup runtime directory {}", root.display()));
        }
    }

    result
}

fn unique_runtime_dir() -> Result<PathBuf> {
    let mut random = [0u8; 12];
    OsRng.fill_bytes(&mut random);
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(std::env::temp_dir().join(format!("deobf-runtime-{}-{suffix}", std::process::id())))
}

pub fn default_runtime_output(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("protected");
    parent.join(format!("{stem}.deobf"))
}
