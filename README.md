# DEOBF

DEOBF is a modular software-protection toolkit for software you own or are authorized to protect.

The project is being rebuilt around a strict separation between **format adapters**, **transformation passes**, **runtime protection**, and the **authenticated container**. It is intentionally not marketed as an impossible-to-reverse-engineer solution: anything that executes on an analyst-controlled machine can ultimately be inspected.

## Current engine

The existing container already provides:

- Argon2id password-based key derivation with a per-container random salt.
- XChaCha20-Poly1305 authenticated encryption.
- Per-chunk nonces and authenticated metadata (AAD).
- Streaming processing for large files.
- Optional Zstandard compression in the protected payload.
- Randomized container material.
- Atomic writes through temporary files.
- Original filename and extension on Protect output (`.exe` stays `.exe`).
- PE outputs wrapped as a launchable Windows loader stub plus authenticated overlay.
- Backward-compatible reading of legacy `.deobf` packages.

## V3 architecture

The target architecture is:

```text
                 +-------------------+
                 |       CLI / API   |
                 +---------+---------+
                           |
                 +---------v---------+
                 | Protection Profile|
                 +---------+---------+
                           |
        +------------------+------------------+
        |                  |                  |
+-------v------+   +-------v------+   +-------v------+
| PE / Native  |   | JVM / JAR    |   | Generic data |
| adapter      |   | adapter      |   | adapter      |
+-------+------+   +-------+------+   +-------+------+
        |                  |                  |
        +------------------+------------------+
                           |
                 +---------v---------+
                 | Transformation    |
                 | pipeline          |
                 +---------+---------+
                           |
                 +---------v---------+
                 | Verification      |
                 | + integrity       |
                 +---------+---------+
                           |
                 +---------v---------+
                 | DEOBF container   |
                 | AEAD + metadata   |
                 +-------------------+
```

### Protection profiles

- **Safe** — minimal transformations, maximum compatibility.
- **Balanced** — stronger metadata and constant protection with verification.
- **Maximum** — the strongest behavior-preserving transformations supported by the selected format adapter.

Profiles must be explicit and composable; there will be no hidden global switches that silently change the output format.

### Planned format coverage

1. Generic binary/data files — authenticated container and secure packaging.
2. Java/JAR — behavior-preserving bytecode transformations, keep rules, metadata minimization and post-transform verification.
3. Native PE — executable-aware packaging and integrity protection, with transformations limited to code that can be validated safely.
4. ELF and Mach-O — platform-specific packaging/integrity support after the PE/JVM pipeline is stable.

## What this project will not claim

No legitimate protector can guarantee that protected code is unrecoverable at runtime. The objective is to increase the cost of static analysis, extraction and unauthorized modification while keeping protected software reliable.

The project also avoids features whose primary purpose is stealth, security-product evasion or destructive anti-analysis behavior.

## CLI

```text
deobf protect <input> [-o <output>]
deobf unprotect <input> -o <output>
deobf inspect <input>
deobf run <package> <pe|jar|python>
```

If `-o` is omitted, Protect writes `protected/<original-filename>` next to the input, keeping the original extension. PE files become a stub-wrapped EXE that prompts for the password and launches the payload. JAR and Python keep `.jar` / `.py` but are not self-running stubs yet (`deobf run`).

Passwords may be supplied interactively; command-line password arguments remain available for automation but are less desirable because process arguments can be observable by other local software. The PE stub also reads `DEOBF_PASSWORD`.

## Development

```text
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```
