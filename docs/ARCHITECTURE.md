# DEOBF architecture

DEOBF is a protection toolkit built as a layered pipeline rather than a monolithic obfuscator.

## Layers

1. **Artifact detection** — identify PE, ELF, JAR/ZIP and raw inputs without mutating them.
2. **Analysis** — collect architecture, size, sections and metadata required by the selected profile.
3. **Policy** — validate limits and choose an explicit `safe`, `balanced` or `maximum` profile.
4. **Transforms** — independently testable passes with documented invariants.
5. **Container** — authenticated, versioned storage for protected payloads.
6. **Verification** — verify output before accepting it as successful.
7. **CLI/UI** — presentation and orchestration only; cryptography remains in the engine.

## Security rules

- Treat all UI and CLI paths/options as untrusted input and validate them in the engine.
- Keep passwords and derived keys in zeroizing memory where supported.
- Never silently downgrade a new artifact to a legacy format.
- Never replace the source when a transformation or verification fails.
- Clean up temporary outputs after failures.
- Never log passwords, derived keys or plaintext payloads.
- Cryptography protects container confidentiality/integrity; it does not make executing plaintext code impossible to reverse engineer.
- Runtime anti-analysis features are deliberately separate from the core transformation pipeline.

## Protection pipeline

`detect -> analyze -> validate -> select profile -> transform -> verify -> containerize -> verify output`

Each stage should be independently testable and report structured diagnostics.

## UI contract

The desktop UI exposes four high-level actions:

- **Analyze** — inspect a file without modifying it.
- **Protect** — select a profile, run the engine, and show progress.
- **Verify** — validate an existing protected artifact.
- **Inspect** — display format/version/size/flags without exposing secrets.

The UI must never implement encryption itself. It should call the Rust engine through a small, versioned command/API boundary.

## Roadmap

- PE/ELF/JAR structural analysis.
- Sections, resources and symbol/debug metadata reporting.
- Format-aware, compatibility-tested transformations.
- Reproducible protection profiles.
- Versioned authenticated container formats.
- Regression corpus and property tests.
- Benchmarks for throughput, memory and output-size overhead.
- Native desktop shell around the existing web UI.
