use deobf::core::selfrun;
use deobf::core::stub::{self, KIND_PE};
use deobf::{default_protected_output, protect_file, unprotect_file, EngineOptions};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn sample_pe() -> Vec<u8> {
    let mut data = vec![0u8; 0x80];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&(0x40u32).to_le_bytes());
    data[0x40..0x44].copy_from_slice(b"PE\0\0");
    data[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    data[0x46..0x48].copy_from_slice(&3u16.to_le_bytes());
    data[0x54..0x56].copy_from_slice(&0x20bu16.to_le_bytes());
    data
}

fn password() -> &'static [u8] {
    b"correct horse battery staple"
}

#[test]
fn default_output_keeps_original_filename_and_extension() {
    assert_eq!(
        default_protected_output(PathBuf::from("C:/app/foo.exe").as_path()),
        PathBuf::from("C:/app/protected/foo.exe")
    );
    assert_eq!(
        default_protected_output(PathBuf::from("/tmp/tool.jar").as_path()),
        PathBuf::from("/tmp/protected/tool.jar")
    );
    assert_eq!(
        default_protected_output(PathBuf::from("script.py").as_path()),
        PathBuf::from("protected/script.py")
    );
}

#[test]
fn protect_pe_writes_exe_not_deobf() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("foo.exe");
    let output = dir.path().join("protected").join("foo.exe");
    fs::write(&input, sample_pe()).unwrap();

    let report = protect_file(&input, &output, password(), &EngineOptions::default()).unwrap();
    assert!(output.exists(), "expected {}", output.display());
    assert_eq!(output.extension().and_then(|e| e.to_str()), Some("exe"));
    let bytes = fs::read(&output).unwrap();
    assert!(
        bytes.starts_with(b"MZ"),
        "protected PE must remain a PE image"
    );
    assert!(
        stub::parse_trailer(&bytes).is_some(),
        "protected PE must carry a DEOBF overlay"
    );
    assert!(report.passes.iter().any(|p| p.contains("windows-stub")));
    assert!(
        stub::extract_embedded_key(&bytes).is_none(),
        "passworded extra-lock must not embed a raw key"
    );

    let restored = dir.path().join("restored.exe");
    unprotect_file(&output, &restored, password()).unwrap();
    assert_eq!(fs::read(restored).unwrap(), sample_pe());
}

#[test]
fn protect_pe_auto_key_needs_no_password() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("foo.exe");
    let output = dir.path().join("protected").join("foo.exe");
    fs::write(&input, sample_pe()).unwrap();

    let report = protect_file(&input, &output, b"", &EngineOptions::default()).unwrap();
    let bytes = fs::read(&output).unwrap();
    assert!(bytes.starts_with(b"MZ"));
    assert!(stub::parse_trailer(&bytes).is_some());
    assert!(
        stub::extract_embedded_key(&bytes).is_some(),
        "auto-key must be embedded next to the container"
    );
    assert!(report
        .passes
        .iter()
        .any(|p| p.contains("embedded-auto-key")));

    let restored = dir.path().join("restored.exe");
    unprotect_file(&output, &restored, b"").unwrap();
    assert_eq!(fs::read(restored).unwrap(), sample_pe());
}

#[test]
fn protect_python_keeps_py_extension() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("app.py");
    let output = dir.path().join("protected").join("app.py");
    fs::write(&input, b"print('hello from deobf')\n").unwrap();
    protect_file(&input, &output, password(), &EngineOptions::default()).unwrap();
    assert_eq!(output.extension().and_then(|e| e.to_str()), Some("py"));
    let restored = dir.path().join("out.py");
    unprotect_file(&output, &restored, password()).unwrap();
    assert_eq!(fs::read(restored).unwrap(), b"print('hello from deobf')\n");
}

#[test]
fn protect_python_auto_key_unprotects_without_password() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("app.py");
    let output = dir.path().join("protected").join("app.py");
    fs::write(&input, b"print('hello from deobf')\n").unwrap();
    protect_file(&input, &output, b"", &EngineOptions::default()).unwrap();
    let bytes = fs::read(&output).unwrap();
    let text = std::str::from_utf8(&bytes).expect("protected python must be utf-8");
    assert!(text.contains("# DEOBF-PY-V1"));
    assert!(selfrun::is_selfrun_python(&bytes));
    assert!(selfrun::embedded_key(&bytes).is_some());
    let restored = dir.path().join("out.py");
    unprotect_file(&output, &restored, b"").unwrap();
    assert_eq!(fs::read(restored).unwrap(), b"print('hello from deobf')\n");
}

#[test]
fn legacy_deobf_package_still_unprotects() {
    let exe = env!("CARGO_BIN_EXE_deobf");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("notes.txt");
    let packaged = dir.path().join("notes.deobf");
    let output = dir.path().join("roundtrip.txt");
    fs::write(&input, b"legacy-container-bytes").unwrap();
    let result = Command::new(exe)
        .args([
            "protect",
            input.to_str().unwrap(),
            "-o",
            packaged.to_str().unwrap(),
            "--password",
            "correct horse battery staple",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "protect failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(exe)
        .args([
            "unprotect",
            packaged.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--password",
            "correct horse battery staple",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "unprotect failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(output).unwrap(), b"legacy-container-bytes");
}

fn write_stub_file(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("tiny-stub.exe");
    fs::write(&path, stub::fallback_pe_stub()).unwrap();
    path
}

#[test]
fn cli_protect_pe_without_dash_o_writes_protected_foo_exe() {
    let exe = env!("CARGO_BIN_EXE_deobf");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("foo.exe");
    fs::write(&input, sample_pe()).unwrap();
    let stub_path = write_stub_file(dir.path());
    let result = Command::new(exe)
        .args([
            "protect",
            input.to_str().unwrap(),
            "--password",
            "correct horse battery staple",
        ])
        .env("DEOBF_STUB_PATH", &stub_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "protect failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let output = dir.path().join("protected").join("foo.exe");
    assert!(output.is_file(), "expected {}", output.display());
    let bytes = fs::read(&output).unwrap();
    assert!(bytes.starts_with(b"MZ"));
    assert_eq!(stub::extract(&bytes).unwrap().1, KIND_PE);
}

#[test]
fn cli_protect_without_password_embeds_auto_key() {
    let exe = env!("CARGO_BIN_EXE_deobf");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("foo.exe");
    fs::write(&input, sample_pe()).unwrap();
    let stub_path = write_stub_file(dir.path());
    let result = Command::new(exe)
        .args(["protect", input.to_str().unwrap()])
        .env("DEOBF_STUB_PATH", &stub_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "protect without --password failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let output = dir.path().join("protected").join("foo.exe");
    let bytes = fs::read(&output).unwrap();
    assert!(bytes.starts_with(b"MZ"));
    assert!(stub::extract_embedded_key(&bytes).is_some());
    assert!(String::from_utf8_lossy(&result.stdout).contains("embedded auto-key"));

    let restored = dir.path().join("restored.exe");
    let result = Command::new(exe)
        .args([
            "unprotect",
            output.to_str().unwrap(),
            "-o",
            restored.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "unprotect without --password failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(restored).unwrap(), sample_pe());
}

#[test]
fn fallback_pe_is_parseable() {
    let pe = stub::fallback_pe_stub();
    let info = deobf::core::parse_pe(&pe).expect("fallback stub must be a valid PE");
    assert_eq!(info.machine, 0x8664);
}

#[test]
fn passworded_package_does_not_unprotect_without_password() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("notes.txt");
    let packaged = dir.path().join("notes.deobf");
    fs::write(&input, b"secret").unwrap();
    protect_file(&input, &packaged, password(), &EngineOptions::default()).unwrap();
    let restored = dir.path().join("out.txt");
    let err = unprotect_file(&packaged, &restored, b"").unwrap_err();
    assert!(format!("{err:#}").contains("password"));
}

fn which(names: &[&str]) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
            #[cfg(windows)]
            {
                let exe = dir.join(format!("{name}.exe"));
                if exe.is_file() {
                    return Some(exe);
                }
            }
        }
    }
    None
}

fn zip_contains(data: &[u8], name: &[u8]) -> bool {
    data.windows(name.len()).any(|w| w == name)
}

#[test]
fn protect_python_auto_key_is_runnable() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("app.py");
    let output = dir.path().join("protected").join("app.py");
    fs::write(&input, b"print(\"hello-deobf\")\n").unwrap();
    let report = protect_file(&input, &output, b"", &EngineOptions::default()).unwrap();
    assert!(report.passes.iter().any(|p| p.contains("python-loader")));
    let bytes = fs::read(&output).unwrap();
    assert!(std::str::from_utf8(&bytes).is_ok());
    assert!(selfrun::is_selfrun_python(&bytes));
    let restored = dir.path().join("out.py");
    unprotect_file(&output, &restored, b"").unwrap();
    assert_eq!(fs::read(&restored).unwrap(), b"print(\"hello-deobf\")\n");

    if let Some(py) = which(&["python", "python3", "py"]) {
        let result = Command::new(&py).arg(&output).output().unwrap();
        assert!(
            result.status.success(),
            "python stub failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("hello-deobf"),
            "unexpected stdout: {stdout:?}"
        );
    }
}

#[test]
fn protect_jar_auto_key_is_self_running_zip() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hello.jar");
    let original = fs::read(&fixture).expect("tests/fixtures/hello.jar must be vendored");
    assert!(original.starts_with(b"PK"), "fixture must be a zip/jar");

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("app.jar");
    let output = dir.path().join("protected").join("app.jar");
    fs::write(&input, &original).unwrap();
    let report = protect_file(&input, &output, b"", &EngineOptions::default()).unwrap();
    assert!(report.passes.iter().any(|p| p.contains("jar-loader")));

    let bytes = fs::read(&output).unwrap();
    assert!(bytes.starts_with(b"PK"), "protected JAR must start with PK");
    assert!(zip_contains(&bytes, b"deobf/Loader.class"));
    assert!(zip_contains(&bytes, b"deobf/payload.bin"));
    assert!(zip_contains(&bytes, b"deobf/key.bin"));
    assert!(zip_contains(&bytes, b"Main-Class: deobf.Loader"));
    assert!(selfrun::is_selfrun_jar(&bytes));
    assert!(selfrun::embedded_key(&bytes).is_some());

    let restored = dir.path().join("restored.jar");
    unprotect_file(&output, &restored, b"").unwrap();
    let restored_bytes = fs::read(&restored).unwrap();
    assert!(
        restored_bytes.starts_with(b"PK"),
        "unprotect must restore a JAR"
    );
    assert!(zip_contains(&restored_bytes, b"Hello.class"));
    assert!(zip_contains(&restored_bytes, b"META-INF/MANIFEST.MF"));

    if let Some(java) = which(&["java"]) {
        let result = Command::new(&java)
            .arg("-jar")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "java -jar protected failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("hello-deobf"),
            "unexpected stdout: {stdout:?}"
        );
    }
}

#[test]
fn protect_python_zipapp_stays_runnable_zip() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hello.pyz");
    let original = fs::read(&fixture).expect("tests/fixtures/hello.pyz must be vendored");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("app.pyz");
    let output = dir.path().join("protected").join("app.pyz");
    fs::write(&input, &original).unwrap();
    protect_file(&input, &output, b"", &EngineOptions::default()).unwrap();
    let bytes = fs::read(&output).unwrap();
    assert!(
        bytes.starts_with(b"PK"),
        "protected pyz must remain a zipapp"
    );
    assert!(selfrun::is_selfrun_python(&bytes));
    let restored = dir.path().join("out.pyz");
    unprotect_file(&output, &restored, b"").unwrap();
    let restored_bytes = fs::read(&restored).unwrap();
    assert!(restored_bytes.starts_with(b"PK"));
    assert!(zip_contains(&restored_bytes, b"__main__.py"));

    if let Some(py) = which(&["python", "python3", "py"]) {
        let result = Command::new(&py).arg(&output).output().unwrap();
        assert!(
            result.status.success(),
            "python zipapp stub failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("hello-deobf"));
    }
}
