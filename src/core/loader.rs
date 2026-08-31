use anyhow::{Context, Result};
use std::{path::Path, process::{Command, ExitStatus}};

use super::{artifact::{detect, ArtifactKind}, engine::unprotect_file};

/// Windows-first runtime loader policy. It deliberately performs no debugger,
/// anti-VM, or process-hiding tricks: its job is to authenticate, restore and
/// launch the original artifact with predictable semantics.
#[derive(Debug, Clone)]
pub struct LoaderPolicy {
    pub java: String,
    pub python: String,
    pub working_directory: Option<std::path::PathBuf>,
}

impl Default for LoaderPolicy {
    fn default() -> Self {
        Self { java: "java".into(), python: "python".into(), working_directory: None }
    }
}

pub fn launch_restored(
    payload: &Path,
    kind: ArtifactKind,
    policy: &LoaderPolicy,
    args: &[String],
) -> Result<ExitStatus> {
    let cwd = policy.working_directory.as_deref();
    let mut command = match kind {
        ArtifactKind::Pe => Command::new(payload),
        ArtifactKind::Jar => {
            let mut c = Command::new(&policy.java);
            c.arg("-jar").arg(payload);
            c
        }
        ArtifactKind::Raw | ArtifactKind::Zip => {
            anyhow::bail!("generic/ZIP payload requires an explicit runtime command")
        }
        ArtifactKind::Elf | ArtifactKind::MachO => {
            anyhow::bail!("non-Windows executable formats are not supported by the Windows loader")
        }
    };
    if let Some(dir) = cwd { command.current_dir(dir); }
    if matches!(kind, ArtifactKind::Jar | ArtifactKind::Pe) { command.args(args); }
    command.status().context("launch restored protected payload")
}

pub fn launch_python(payload: &Path, policy: &LoaderPolicy, args: &[String]) -> Result<ExitStatus> {
    let mut command = Command::new(&policy.python);
    command.arg(payload).args(args);
    if let Some(dir) = policy.working_directory.as_deref() { command.current_dir(dir); }
    command.status().context("launch restored Python payload")
}

pub fn detect_restored(payload: &Path) -> Result<ArtifactKind> {
    let bytes = std::fs::read(payload).with_context(|| format!("read restored payload {}", payload.display()))?;
    Ok(detect(&bytes))
}

pub fn restore_and_detect(package: &Path, output: &Path, password: &[u8]) -> Result<ArtifactKind> {
    unprotect_file(package, output, password).context("authenticated package restore")?;
    detect_restored(output)
}
