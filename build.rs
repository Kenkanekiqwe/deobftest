use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

fn is_mz(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic).is_ok() && magic == *b"MZ"
}

fn embed(src: &Path, out_dir: &Path) -> bool {
    if !src.is_file() || !is_mz(src) {
        return false;
    }
    let dest = out_dir.join("deobf-stub.bin");
    if fs::copy(src, &dest).is_err() {
        return false;
    }
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rustc-cfg=deobf_embedded_stub");
    true
}

fn main() {
    println!("cargo:rerun-if-env-changed=DEOBF_STUB_PATH");
    println!("cargo:rerun-if-env-changed=CARGO_BIN_FILE_DEOBF_STUB");
    println!("cargo:rustc-check-cfg=cfg(deobf_embedded_stub)");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    if let Ok(path) = env::var("DEOBF_STUB_PATH") {
        if embed(Path::new(&path), &out_dir) {
            return;
        }
    }

    if let Ok(path) = env::var("CARGO_BIN_FILE_DEOBF_STUB") {
        if embed(Path::new(&path), &out_dir) {
            return;
        }
    }

    // Conventional cargo output dirs next to this build. Do not invoke cargo
    // from here: that would recurse while compiling deobf / deobf-stub.
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(dir) = env::var("CARGO_TARGET_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    if let Ok(manifest) = env::var("CARGO_MANIFEST_DIR") {
        dirs.push(PathBuf::from(manifest).join("target"));
    }
    let mut cursor = out_dir.clone();
    for _ in 0..8 {
        if let Some(parent) = cursor.parent() {
            dirs.push(parent.to_path_buf());
            cursor = parent.to_path_buf();
        }
    }

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let target = env::var("TARGET").unwrap_or_default();
    let names = ["deobf-stub.exe", "deobf-stub"];
    for dir in &dirs {
        for name in names {
            let candidates = [
                dir.join(name),
                dir.join(&profile).join(name),
                dir.join(&target).join(&profile).join(name),
            ];
            for candidate in candidates {
                if embed(&candidate, &out_dir) {
                    return;
                }
            }
        }
    }
}
