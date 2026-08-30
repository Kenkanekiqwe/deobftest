# DEOBF

Custom authenticated protection container for software you own or are authorized to protect.

## Current protection

- Argon2id password-based key derivation with per-container random salt.
- XChaCha20-Poly1305 authenticated encryption.
- Independent nonces derived for every chunk.
- Per-chunk authenticated metadata (AAD), preventing chunk reordering/substitution.
- Streaming/chunked processing for large files.
- Zstandard support in the dependency set for the compression pipeline.
- Randomized container material to reduce structural fingerprinting.
- Atomic output through a temporary file.
- No original filename or extension in the cryptographic header.
- Temporary JAR cleanup after execution.
- Backward-compatible v1 reading.

## Important limitation

No executable can be made mathematically impossible to reverse engineer when it executes on a machine controlled by an analyst. The goal is to raise the cost of extraction and analysis while preserving reliable execution.

## Java/JAR roadmap

The architecture separates the cryptographic container from format-specific transformation. The Java engine is intended to add behavior-preserving passes such as:

1. Symbol/identifier renaming with reflection-aware keep rules.
2. Debug and unnecessary metadata minimization.
3. String and constant protection.
4. Control-flow transformation where semantics can be verified.
5. Post-transform bytecode verification.
6. Deterministic build mode for reproducible protected artifacts.

## CLI

```text
deobf protect <input> -o <output> --password <password>
deobf unprotect <input> -o <output> --password <password>
deobf inspect <input>
deobf run-jar <input> --password <password> [-- <java args>]
```

## CI/CD

GitHub Actions checks formatting, compilation, tests and Clippy, then builds release binaries for Windows x64, Linux x64 and macOS arm64. Version tags (`v*`) publish a GitHub Release and SHA-256 checksums automatically.
