#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    match deobf::run_embedded_stub() {
        Some(Ok(code)) => std::process::exit(code),
        Some(Err(err)) => {
            eprintln!("DEOBF runtime: {err:#}");
            std::process::exit(1);
        }
        None => {
            eprintln!("DEOBF runtime: this executable has no protected payload overlay.");
            std::process::exit(2);
        }
    }
}
