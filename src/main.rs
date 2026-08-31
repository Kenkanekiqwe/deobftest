#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;
use std::{path::PathBuf, process::ExitCode};
use zeroize::Zeroizing;

use deobf::core::stub;
use deobf::{
    analyze_only, default_protected_output, has_auto_key, protect_file, run_embedded_stub,
    run_protected, unprotect_file, EngineOptions, RuntimeKind,
};

#[cfg(feature = "gui")]
mod gui;

#[derive(Parser)]
#[command(
    name = "deobf",
    version,
    about = "DEOBF Windows software protection studio"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CommandKind>,
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
    if has_auto_key(&data) {
        return Ok(Zeroizing::new(Vec::new()));
    }
    password(None, false)
}

#[cfg(all(windows, feature = "gui"))]
fn attach_parent_console() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{
        AllocConsole, AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS,
        STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    fn missing(id: u32) -> bool {
        unsafe {
            let handle = GetStdHandle(id);
            handle.is_null() || handle == (-1isize as _)
        }
    }

    // Keep pipes from `deobf protect ... | ...` and cargo tests; only attach when
    // the GUI subsystem left stdin/stdout disconnected (cmd.exe double-click / no-redir).
    if !missing(STD_OUTPUT_HANDLE) && !missing(STD_ERROR_HANDLE) {
        return;
    }

    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            let _ = AllocConsole();
        }
    }

    let bind = |name: &str, id: u32| {
        if !missing(id) {
            return;
        }
        if let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
        {
            unsafe {
                SetStdHandle(id, file.as_raw_handle() as _);
            }
            std::mem::forget(file);
        }
    };
    bind("CONIN$", STD_INPUT_HANDLE);
    bind("CONOUT$", STD_OUTPUT_HANDLE);
    bind("CONOUT$", STD_ERROR_HANDLE);
}

#[cfg(feature = "gui")]
fn launch_gui() -> Result<ExitCode> {
    gui::run().map_err(|err| anyhow::anyhow!("{err}"))?;
    Ok(ExitCode::SUCCESS)
}

fn main() -> Result<ExitCode> {
    if let Some(result) = run_embedded_stub() {
        return match result {
            Ok(code) => Ok(ExitCode::from(u8::try_from(code).unwrap_or(1))),
            Err(err) => Err(err),
        };
    }

    #[cfg(feature = "gui")]
    if std::env::args_os().len() <= 1 {
        return launch_gui();
    }

    #[cfg(all(windows, feature = "gui"))]
    attach_parent_console();

    let cli = Cli::parse();
    let command = match cli.command {
        Some(command) => command,
        None => {
            #[cfg(feature = "gui")]
            {
                return launch_gui();
            }
            #[cfg(not(feature = "gui"))]
            {
                use clap::CommandFactory;
                Cli::command().print_help()?;
                println!();
                return Ok(ExitCode::from(2));
            }
        }
    };
    match command {
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
            } else if analysis.kind == "Jar" {
                if pass.is_empty() {
                    println!(
                        "Runtime: output is a self-running JAR. Open it or run `java -jar` (no `deobf run` needed)."
                    );
                } else {
                    println!(
                        "Runtime: extra-lock JAR is not self-running; use `deobf run <file> jar`."
                    );
                }
            } else {
                let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext.eq_ignore_ascii_case("py")
                    || ext.eq_ignore_ascii_case("pyw")
                    || ext.eq_ignore_ascii_case("pyz")
                {
                    if pass.is_empty() {
                        println!(
                            "Runtime: output is a self-running Python file. Open it or run `python` / `py` (no `deobf run` needed)."
                        );
                    } else {
                        println!("Runtime: extra-lock Python is not self-running; use `deobf run <file> python`.");
                    }
                } else {
                    println!(
                        "Runtime: original extension kept. Launch extra-lock packages with `deobf run`."
                    );
                }
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
                    if has_auto_key(&data) {
                        "embedded auto-key"
                    } else {
                        "password"
                    }
                );
                println!("container size: {} bytes", trailer.container_size);
                println!("file size: {} bytes", data.len());
            } else if deobf::core::selfrun::is_selfrun_jar(&data) {
                println!("type: DEOBF protected JAR");
                println!("runtime stub: java loader");
                println!("unlock: embedded auto-key");
                println!("size: {} bytes", data.len());
            } else if deobf::core::selfrun::is_selfrun_python(&data) {
                println!("type: DEOBF protected Python");
                println!("runtime stub: python loader");
                println!("unlock: embedded auto-key");
                println!("size: {} bytes", data.len());
            } else if deobf::core::engine::is_deobf_container(&data) || has_auto_key(&data) {
                println!("type: DEOBF package");
                println!("runtime stub: absent");
                println!(
                    "unlock: {}",
                    if has_auto_key(&data) {
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
