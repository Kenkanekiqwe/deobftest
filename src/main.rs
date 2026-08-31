use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;
use std::{path::PathBuf, process::ExitCode};
use zeroize::Zeroizing;

use deobf::{analyze_only, protect_file, run_protected, unprotect_file, EngineOptions, RuntimeKind};

#[derive(Parser)]
#[command(name = "deobf", version, about = "DEOBF Windows software protection studio")]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    Protect {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value = "balanced")]
        profile: String,
        #[arg(long)]
        password: Option<String>,
    },
    Unprotect {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
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

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        CommandKind::Protect { input, output, profile, password: value } => {
            let pass = password(value, true)?;
            let analysis = analyze_only(&std::fs::read(&input).with_context(|| format!("read {}", input.display()))?)?;
            println!("Detected: {} / {}", analysis.kind, analysis.architecture);
            let report = protect_file(
                &input,
                &output,
                &pass,
                &EngineOptions { profile, verify: true, add_integrity: true },
            )?;
            println!("Protected: {} -> {} bytes", report.input_size, report.output_size);
            println!("Input SHA-256-style BLAKE3: {}", report.input_hash);
            println!("Package BLAKE3: {}", report.output_hash);
            println!("Runtime: use `deobf run <package> <pe|jar|python>` to execute it.");
        }
        CommandKind::Unprotect { input, output, password: value } => {
            let pass = password(value, false)?;
            unprotect_file(&input, &output, &pass)?;
            println!("Restored authenticated payload to {}", output.display());
        }
        CommandKind::Inspect { input } => {
            let data = std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
            let analysis = analyze_only(&data)?;
            println!("type: {}", analysis.kind);
            println!("architecture: {}", analysis.architecture);
            println!("executable: {}", analysis.executable);
            println!("debug markers: {}", analysis.has_debug_markers);
            println!("archive signature: {}", analysis.has_archive_signature);
            println!("size: {} bytes", data.len());
        }
        CommandKind::Run { package, kind, interpreter, password: value, args } => {
            let pass = password(value, false)?;
            let status = run_protected(&package, &pass, kind.into(), interpreter.as_deref(), &args)?;
            println!("Protected process exited with {}", status);
        }
    }
    Ok(ExitCode::SUCCESS)
}
