# DEOBF

DEOBF is a modular software-protection toolkit for software you own or are authorized to protect.

The project is being rebuilt around a strict separation between **format adapters**, **transformation passes**, **runtime protection**, and the **authenticated container**. It is intentionally not marketed as an impossible-to-reverse-engineer solution: anything that executes on an analyst-controlled machine can ultimately be inspected.

## Current engine

The existing container already provides:

- Packer-style default: a random 32-byte AEAD key is generated at protect time and embedded next to the container. Double-clicking a protected PE runs with no password prompt.
- Optional extra password lock (`--password` / GUI checkbox, off by default) using Argon2id.
- XChaCha20-Poly1305 authenticated encryption.
- Per-chunk nonces and authenticated metadata (AAD).
- Streaming processing for large files.
- Optional Zstandard compression in the protected payload.
- Randomized container material.
- Atomic writes through temporary files.
- Original filename and extension on Protect output (`.exe` stays `.exe`).
- PE outputs wrapped as a launchable Windows loader stub plus authenticated overlay.
- JAR auto-key output stays a valid ZIP/JAR: apps double-click / `java -jar`; Minecraft/Bukkit/Fabric/Forge/Quilt mods keep metadata, assets, mixin JSON and nested-jar *wrappers* so they still drop into a mods folder. Original classes and nested-mod bytecode live only inside encrypted `deobf/payload.bin` (DEOBFW01). Nested jars are themselves DEOBF-wrapped (never copied plaintext). A vendored `deobf.Loader` decrypts in-process (no `java -jar` subprocess).
- Python auto-key output is a valid `.py` (or `.pyz` zipapp) that decrypts and execs the original with no extra packages.
- Backward-compatible reading of legacy passworded `.deobf` packages when a password is supplied.

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

## App

Download **`deobf.exe`** (one Windows application). Double-click it to open the Protection Studio GUI. From a terminal, the same binary is the CLI:

```text
deobf protect <input> [-o <output>]
deobf unprotect <input> -o <output>
deobf inspect <input>
deobf run <package> <pe|jar|python>
```

No separate `deobf-gui.exe` or `deobf-stub.exe` is shipped. The PE runtime stub used when protecting EXEs is compiled in at build time, so Protect does not need a sibling stub next to the app.

`deobf protect input.exe` (no `-p` / `--password`) is the default: it writes `protected/input.exe` with an embedded auto-key. Double-click the output and it decrypts via the existing AEAD runtime, launches the original, then cleans up. `deobf protect app.jar` writes `protected/app.jar`. Apps with a `Main-Class` still run via `java -jar` / double-click (`deobf.Loader` decrypts and invokes the original main in-process, including jar-in-jar). Mods keep `fabric.mod.json` / `mods.toml` / `plugin.yml` and boot through Fabric `preLaunch` (`deobf.Boot`), a Forge `ITransformationService` (`deobf.ForgeService`), or a Bukkit main proxy (`deobf.BukkitPlugin`). Nested mods stay encrypted; unprotect restores the full original inner JAR. `deobf protect app.py` writes a self-running `protected/app.py` (`python` / `py`). Optional `--password` extra-lock for JAR/Python still uses the authenticated container and `deobf run`.

`--password` is an optional extra lock. Legacy passworded `.deobf` files and extra-lock stubs still unprotect when a password is supplied (`--password` or a prompt). Auto-keyed files restore without prompting.

## Development

```text
cargo fmt --all -- --check
cargo test --no-default-features --locked
cargo check --features gui --bin deobf
cargo clippy --all-targets --locked -- -D warnings
```

GitHub Actions on every `main` push, tag, and `workflow_dispatch` builds one user artifact: `deobf-windows-x64.zip` containing `deobf.exe` plus `SHA256SUMS`. CI compiles the tiny `deobf-stub` first (no iced), then builds `deobf` with the GUI feature and embeds that stub via `DEOBF_STUB_PATH`. rust-cache + sccache and a faster CI release profile stay enabled. The first CI run after iced returns is slower; later pushes should hit cache.
