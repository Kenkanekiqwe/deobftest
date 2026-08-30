# DEOBF architecture

DEOBF is organized as a protection toolkit rather than a single monolithic obfuscator.

## Layers

1. **Artifact layer** — identify the input format and collect safe metadata.
2. **Profile layer** — select a reproducible protection policy (`safe`, `balanced`, `maximum`).
3. **Pipeline layer** — execute ordered, independently testable transforms.
4. **Container layer** — authenticated encryption, compression and framing.
5. **Integrity layer** — verify the final artifact before accepting output.
6. **CLI layer** — expose stable commands without putting implementation details into `main.rs`.

## Design rules

- Every transform must be deterministic unless randomness is explicitly part of the transform contract.
- Every transform must be independently testable.
- Verification is mandatory before producing a successful protected artifact.
- Cryptographic primitives are used for confidentiality/integrity, not as a substitute for code transformation.
- Format-specific transforms must not silently operate on an unsupported artifact.
- Failed transformations must never replace the original input.
- Temporary output files must be cleaned up after failures.

## Roadmap

- PE/ELF/JAR structural analysis
- section/resource metadata reporting
- symbol/debug metadata handling where the format supports it
- configurable string/resource protection for supported formats
- reproducible protection profiles
- authenticated container format with versioned headers
- end-to-end regression corpus and property tests
- benchmark suite for throughput, memory use and output-size overhead

The project deliberately keeps anti-analysis and runtime behavior separate from the core transformation pipeline. Protection should not depend on disabling debuggers, security software, or analysis tools.
