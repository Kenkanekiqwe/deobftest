use std::fs;
use std::process::Command;

#[test]
fn binary_roundtrip() {
    let exe = env!("CARGO_BIN_EXE_deobf");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.bin");
    let protected = dir.path().join("input.deobf");
    let output = dir.path().join("output.bin");
    let data: Vec<u8> = (0..=255).cycle().take(3 * 1024 * 1024 + 123).collect();
    fs::write(&input, &data).unwrap();

    let result = Command::new(exe)
        .args([
            "protect",
            input.to_str().unwrap(),
            "-o",
            protected.to_str().unwrap(),
            "--password",
            "correct horse battery staple",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "protect failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );

    let result = Command::new(exe)
        .args([
            "unprotect",
            protected.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--password",
            "correct horse battery staple",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "unprotect failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(output).unwrap(), data);
}
