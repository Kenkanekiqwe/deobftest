use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;
use std::{path::PathBuf, process::ExitCode};
use zeroize::Zeroizing;

use deobf::core::stub;
use deobf::{
    analyze_only, default_protected_output, protect_file, run_embedded_stub, run_protected,
    unprotect_file, EngineOptions, RuntimeKind,
};

#[derive(Parser)]
#[command(
    name = "deobf",
    version,
    about = "DEOBF Windows software protection studio"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    Protect {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "balanced")]
        profile: String,
        /// Optional extra lock. Omit for packer-style auto-run (key embedded in the output).
        #[arg(long)]
        password: Option<String>,
    },
    Unprotect {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Required only for legacy passworded packages. Auto-keyed files restore without it.
        #[arg(long)]
        password: Option<String>,
    },
    Inspect {
        input: PathBuf,
    },
    Run {
        package: PathBuf,
        #[arg(value_enum)]
        kind: RunKind,
        #[arg(long)]
        interpreter: Option<String>,
        /// Required only for legacy passworded packages.
        #[arg(long)]
        password: Option<String>,
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RunKind {
    Pe,
    Jar,
    Python,
}

impl From<RunKind> for RuntimeKind {
    fn from(value: RunKind) -> Self {
        match value {
            RunKind::Pe => RuntimeKind::Pe,
            RunKind::Jar => RuntimeKind::Jar,
            RunKind::Python => RuntimeKind::Python,
        }
    }
}

fn password(value: Option<String>, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    let interactive = value.is_none();
    let password = match value {
        Some(value) => value,
        None => prompt_password("Password: ")?,
    };
    if confirm && interactive {
        let confirmation = prompt_password("Confirm password: ")?;
        if password != confirmation {
            bail!("passwords do not match");
        }
    }
    if password.len() < 12 {
        bail!("password must contain at least 12 characters");
    }
    Ok(Zeroizing::new(password.into_bytes()))
}

/// Protect default: empty password means generate and embed an auto-key.
fn protect_password(value: Option<String>) -> Result<Zeroizing<Vec<u8>>> {
    match value {
        Some(value) => password(Some(value), true),
        None => Ok(Zeroizing::new(Vec::new())),
    }
}

/// Unprotect/run: use the embedded auto-key when present; otherwise prompt or use --password.
fn package_password(input: &std::path::Path, value: Option<String>) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(value) = value {
        return password(Some(value), false);
    }
    let data = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    if stub::extract_embedded_key(&data).is_some() {
        return Ok(Zeroizing::new(Vec::new()));
    }
    password(None, false)
}

fn main() -> Result<ExitCode> {
    if let Some(result) = run_embedded_stub() {
        return match result {
            Ok(code) => Ok(ExitCode::from(u8::try_from(code).unwrap_or(1))),
            Err(err) => Err(err),
        };
    }

    let cli = Cli::parse();
    match cli.command {
        CommandKind::Protect {
            input,
            output,
            profile,
            password: value,
        } => {
            let pass = protect_password(value)?;
            let analysis = analyze_only(
                &std::fs::read(&input).with_context(|| format!("read {}", input.display()))?,
            )?;
            println!("Detected: {} / {}", analysis.kind, analysis.architecture);
            let output = output.unwrap_or_else(|| default_protected_output(&input));
            println!("Writing {}", output.display());
            let report = protect_file(
                &input,
                &output,
                &pass,
                &EngineOptions {
                    profile,
                    verify: true,
                    add_integrity: true,
                },
            )?;
            println!(
                "Protected: {} -> {} bytes",
                report.input_size, report.output_size
            );
            println!("Input SHA-256-style BLAKE3: {}", report.input_hash);
            println!("Package BLAKE3: {}", report.output_hash);
            if pass.is_empty() {
                println!("Unlock: embedded auto-key (no password prompt at runtime).");
            } else {
                println!("Unlock: extra password lock (runtime will prompt unless DEOBF_PASSWORD is set).");
            }
            if analysis.kind == "Pe" {
                println!(
                    "Runtime: output is a Windows PE stub; double-click it or use `deobf run`."
                );
            } else {
                println!("Runtime: original extension kept. JAR/Python still launch via `deobf run <file> <jar|python>` (no self-running stub yet).");
            }
        }
        CommandKind::Unprotect {
            input,
            output,
            password: value,
        } => {
            let pass = package_password(&input, value)?;
            unprotect_file(&input, &output, &pass)?;
            println!("Restored authenticated payload to {}", output.display());
        }
        CommandKind::Inspect { input } => {
            let data =
                std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
            if let Some(trailer) = stub::parse_trailer(&data) {
                println!("type: DEOBF protected executable");
                println!("runtime stub: present");
                println!(
                    "payload runtime: {}",
                    match trailer.kind {
                        stub::KIND_PE => "pe",
                        stub::KIND_JAR => "jar",
                        stub::KIND_PYTHON => "python",
                        _ => "unknown",
                    }
                );
                println!(
                    "unlock: {}",
                    if stub::extract_embedded_key(&data).is_some() {
                        "embedded auto-key"
                    } else {
                        "password"
                    }
                );
                println!("container size: {} bytes", trailer.container_size);
                println!("file size: {} bytes", data.len());
            } else if deobf::core::engine::is_deobf_container(&data)
                || stub::extract_embedded_key(&data).is_some()
            {
                println!("type: DEOBF package");
                println!("runtime stub: absent");
                println!(
                    "unlock: {}",
                    if stub::extract_embedded_key(&data).is_some() {
                        "embedded auto-key"
                    } else {
                        "password"
                    }
                );
                println!("size: {} bytes", data.len());
            } else {
                let analysis = analyze_only(&data)?;
                println!("type: {}", analysis.kind);
                println!("architecture: {}", analysis.architecture);
                println!("executable: {}", analysis.executable);
                println!("debug markers: {}", analysis.has_debug_markers);
                println!("archive signature: {}", analysis.has_archive_signature);
                println!("size: {} bytes", data.len());
            }
        }
        CommandKind::Run {
            package,
            kind,
            interpreter,
            password: value,
            args,
        } => {
            let pass = package_password(&package, value)?;
            let status =
                run_protected(&package, &pass, kind.into(), interpreter.as_deref(), &args)?;
            println!("Protected process exited with {}", status);
        }
    }
    Ok(ExitCode::SUCCESS)
}
