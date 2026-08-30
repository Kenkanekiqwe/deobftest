# DEOBF

Custom file-protection container written in Rust for arbitrary binary files, including `.jar`, archives, media, documents and application assets.

## Security model

- Argon2id password-based key derivation.
- XChaCha20-Poly1305 authenticated encryption.
- Random 128-bit salt and 192-bit base nonce per protected file.
- 1 MiB independently authenticated chunks for large files.
- BLAKE3-derived per-chunk nonces.
- Authentication fails if the password is wrong or the container was modified.
- Hidden password input and practical secret zeroization.
- Temporary files used by `run-jar` are removed after execution.

## Build

```bash
cargo build --release
```

Windows output: `target/release/deobf.exe`.

## Usage

Protect any file:

```bash
deobf protect app.jar -o app.jar.deobf
```

Restore it:

```bash
deobf unprotect app.jar.deobf -o app.jar
```

Run a protected JAR through Java without manually restoring it:

```bash
deobf run-jar app.jar.deobf
```

Pass JVM/application arguments after `--`:

```bash
deobf run-jar app.jar.deobf -- --server.port=8080
```

Inspect metadata without decrypting:

```bash
deobf inspect app.jar.deobf
```

## Limitation

Client-side protection cannot make software permanently impossible to reverse-engineer. If a JAR is executed on a user's machine, its bytecode must eventually become available to the JVM. This project provides strong at-rest encryption and tamper detection.

For stronger Java IP protection, add a bytecode-obfuscation stage before encryption: identifier renaming, control-flow transformation, string protection and runtime integrity checks. The resulting JAR can then be wrapped by DEOBF.
