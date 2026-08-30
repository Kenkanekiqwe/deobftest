# DEOBF

Custom authenticated protection container for owned software and data.

## Protection model

DEOBF v2 now combines:

- Argon2id password-based key derivation with a per-container random salt.
- XChaCha20-Poly1305 authenticated encryption.
- Independent nonces derived for every chunk.
- Per-chunk authenticated metadata (AAD), preventing chunk reordering or substitution.
- Zstandard compression before encryption.
- Random padding between chunks to reduce structural fingerprinting.
- An authenticated BLAKE3 content digest at the end of the container.
- Atomic output creation through a temporary file.
- No original filename, extension, or MIME type stored in the header.
- Runtime debugger detection for the `run-jar` launcher on supported Windows/Linux targets.
- Automatic cleanup of the temporary JAR after execution.
- Backward-compatible reading of DEOBF v1 containers.

## Important limitation

This protects the payload strongly while it is stored or transported. It cannot make executable code mathematically impossible to reverse: if code must execute on a machine controlled by another person, plaintext/code or an equivalent representation can eventually exist in memory.

For Java applications, the next protection layer should be a bytecode obfuscation pass before sealing the JAR. Suitable transformations include identifier renaming, metadata reduction, string encryption, constant indirection, and control-flow transformations, with a configurable keep-list for reflection/serialization APIs.

## CLI

```text
deobf protect <input> -o <output> --password <password>
deobf unprotect <input> -o <output> --password <password>
deobf inspect <input>
deobf run-jar <input> --password <password> [-- <java args>]
```

Use a strong password and keep it outside the protected artifact. DEOBF is intended for software you own or are authorized to protect.
