use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::{fs, path::{Path, PathBuf}, process::{Command, ExitStatus}};

use super::engine::unprotect_file;
use super::stub::{self, KIND_JAR, KIND_PE, KIND_PYTHON};

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

    pub fn from_stub_kind(kind: u8) -> Option<Self> {
        match kind {
            KIND_PE => Some(Self::Pe),
            KIND_JAR => Some(Self::Jar),
            KIND_PYTHON => Some(Self::Python),
            _ => None,
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
    create_private_dir(&root).context("create runtime directory")?;

    let payload = root.join(match kind {
        RuntimeKind::Pe => "payload.exe",
        RuntimeKind::Jar => "payload.jar",
        RuntimeKind::Python => "payload.py",
    });

    let result = (|| -> Result<ExitStatus> {
        unprotect_file(package, &payload, pass).context("authenticated package restore")?;
        // Defense in depth: even though the containing directory is already
        // owner-only (0700), also lock the decrypted payload file itself down
        // to owner-only read/write in case of unusual ACL/umask setups.
        restrict_file_permissions(&payload).context("restrict decrypted payload permissions")?;

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

/// If this process image carries a DEOBF stub overlay, restore and launch it.
/// Returns `None` when the current executable is a normal CLI/GUI binary.
pub fn run_embedded_stub() -> Option<Result<i32>> {
    let exe = std::env::current_exe().ok()?;
    let bytes = fs::read(&exe).ok()?;
    let (container, kind_u8) = stub::extract(&bytes)?;
    let kind = RuntimeKind::from_stub_kind(kind_u8)?;
    Some(run_embedded_container(&container, kind))
}

fn run_embedded_container(container: &[u8], kind: RuntimeKind) -> Result<i32> {
    #[cfg(windows)]
    ensure_console();

    let pass = stub_password()?;
    let root = unique_runtime_dir()?;
    create_private_dir(&root).context("create stub runtime directory")?;
    let package = root.join("package.deobf");
    let result = (|| -> Result<i32> {
        fs::write(&package, container).with_context(|| format!("write {}", package.display()))?;
        let args: Vec<String> = std::env::args().skip(1).collect();
        let status = run_protected(&package, &pass, kind, None, &args)?;
        Ok(status.code().unwrap_or(1))
    })();
    let _ = fs::remove_file(&package);
    let _ = fs::remove_dir_all(&root);
    result.context("launch embedded protected payload")
}

fn stub_password() -> Result<Vec<u8>> {
    if let Ok(value) = std::env::var("DEOBF_PASSWORD") {
        if value.len() < 12 {
            bail!("password must contain at least 12 characters");
        }
        return Ok(value.into_bytes());
    }
    let password = rpassword::prompt_password("DEOBF password: ").context("read password")?;
    if password.len() < 12 {
        bail!("password must contain at least 12 characters");
    }
    Ok(password.into_bytes())
}

#[cfg(windows)]
fn ensure_console() {
    use windows_sys::Win32::System::Console::{AllocConsole, AttachConsole, ATTACH_PARENT_PROCESS};
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            let _ = AllocConsole();
        }
    }
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

// System temp directories (e.g. /tmp) are typically shared and
// world-traversable. Creating the runtime directory with default
// permissions (usually 0755, governed by umask) would let any other local
// user read the fully decrypted payload while the protected process runs,
// or after an unclean shutdown skips cleanup. Set 0700 atomically at
// creation time so there is no window where the directory is world- or
// group-accessible.
#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("create private directory {}", path.display()))
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create private directory {}", path.display()))
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Default Protect output: same filename and extension as the input, in a
/// `protected` subdirectory so the original is never overwritten.
pub fn default_protected_output(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("protected.bin");
    parent.join("protected").join(name)
}

/// Deprecated name kept for library compatibility. Same as `default_protected_output`.
pub fn default_runtime_output(input: &Path) -> PathBuf {
    default_protected_output(input)
}
