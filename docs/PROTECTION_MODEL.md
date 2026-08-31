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
8. At runtime, restore the payload into a temporary runtime directory and launch the requested PE/JAR/Python interpreter.
9. Remove the temporary runtime directory after process exit.

The package is therefore not meant to be opened as if it were the original PE/JAR/PY file. The supported model is **protect -> runtime launch**, or **protect -> restore** when an original-format file is explicitly required.

## Why format-specific backends are required

A universal byte-level encryptor cannot preserve the normal behavior of arbitrary formats. A Java JAR needs bytecode-aware transformations; a native PE needs loader-aware protection; Python source needs a Python-compatible packaging/runtime strategy. DEOBF therefore keeps the encrypted package layer generic and exposes runtime adapters by artifact type.

## Planned hardening layers

- PE: import/string protection, section-aware packing, integrity checks, optional control-flow transformations, and a native Windows loader stub.
- Java/JAR: bytecode-aware renaming, debug metadata stripping, string/resource protection, and configurable keep rules.
- Python: bytecode/package backend with explicit dependency/runtime preservation rather than blindly encrypting source text.
- All formats: signed manifests, build fingerprints, reproducible configuration, license/activation hooks, and per-build keys.

These transformations must be applied at the correct representation level. Encrypting a complete executable and then changing its extension is packaging, not native code virtualization.

## VMProtect-inspired design goals

VMProtect documents code virtualization, mutation, packing, memory/import protection, debugger detection, licensing, and virtual files as separate capabilities. DEOBF follows the same separation of concerns instead of implementing one oversized "encrypt everything" pass.

The target architecture is:

`Analyzer -> Format backend -> Obfuscation passes -> Integrity -> Packager -> Runtime loader -> License policy`

Each backend must have a compatibility test proving that the protected output still performs the expected entry-point behavior.
