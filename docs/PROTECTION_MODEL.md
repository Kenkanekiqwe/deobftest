# DEOBF protection model

DEOBF is a Windows-first protection system. It separates **at-rest protection** from **runtime compatibility** so a protected artifact can remain usable without pretending that every file format can be transformed in-place by one generic algorithm.

## Current protection pipeline

1. Analyze the artifact and identify PE, JAR, ZIP, or raw data.
2. Apply the selected protection profile and integrity passes.
3. Derive a per-package key with Argon2id.
4. Encrypt data in authenticated chunks with XChaCha20-Poly1305.
5. Compress chunks with Zstandard when useful.
6. Authenticate the complete content with a final encrypted BLAKE3 digest.
7. Write the package atomically through a temporary file.
8. **Keep the original filename and extension** (`.exe` stays `.exe`, `.jar` stays `.jar`, `.py` stays `.py`). Default output is `protected/<original-name>` next to the input so the source is never overwritten.
9. **PE:** wrap the authenticated container in a Windows PE loader stub (overlay + `DEOBFS01` trailer). Double-clicking the output EXE prompts for the password, restores the payload into a private temp directory, launches it, then cleans up. The stub is the DEOBF runtime (`deobf-stub` / `deobf` / `deobf-gui`), not a code-virtualization engine.
10. **JAR / Python:** the original extension is kept so the file still looks like that type, but a self-running JAR/Python stub is not produced yet. Open/run those outputs from DEOBF Studio (Runtime) or `deobf run`.
11. Legacy `.deobf` containers remain readable via Restore / `unprotect`.
12. Remove the temporary runtime directory after process exit.

This is **packaging + authenticated encryption + a Windows loader stub**, not VMProtect-style native virtualization.

## Why format-specific backends are required

A universal byte-level encryptor cannot preserve the normal behavior of arbitrary formats. A Java JAR needs bytecode-aware transformations; a native PE needs loader-aware protection; Python source needs a Python-compatible packaging/runtime strategy. DEOBF therefore keeps the encrypted package layer generic and exposes runtime adapters by artifact type.

## Planned hardening layers

- PE: import/string protection, section-aware packing, integrity checks, optional control-flow transformations, and a native Windows loader stub.
- Java/JAR: bytecode-aware renaming, debug metadata stripping, string/resource protection, and configurable keep rules.
- Python: bytecode/package backend with explicit dependency/runtime preservation rather than blindly encrypting source text.
- All formats: signed manifests, build fingerprints, reproducible configuration, license/activation hooks, and per-build keys.

These transformations must be applied at the correct representation level. Encrypting a complete executable and then changing its extension is packaging, not native code virtualization.

## Design goals

The target architecture is:

`Analyzer -> Format backend -> Obfuscation passes -> Integrity -> Packager -> Runtime loader -> License policy`

Each backend must have a compatibility test proving that the protected output still performs the expected entry-point behavior.
