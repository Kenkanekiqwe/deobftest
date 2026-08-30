# Protection pipeline

DEOBF is organized as a deterministic pipeline:

1. **Input validation** — reject empty or oversized artifacts.
2. **Analysis** — identify the container/artifact family and architecture.
3. **Profile selection** — choose Safe, Balanced, or Maximum policy.
4. **Transform passes** — apply format-aware transformations through `Pipeline`.
5. **Per-pass verification** — validate invariants after each pass when enabled.
6. **Container/integrity** — serialize protected output with authenticated integrity metadata.
7. **Final validation** — reopen/verify the produced artifact before reporting success.

## Design rules

- The CLI is orchestration only; core logic belongs under `src/core`.
- Transformations must be deterministic unless randomness is explicitly part of the format.
- Every transformation must preserve the declared artifact contract.
- Authentication and integrity are mandatory for protected containers.
- Resource limits are checked before expensive processing.
- Unsupported formats fail closed rather than being guessed.
- Protection is intended for software the operator owns or is authorized to protect.

## Planned format adapters

- PE/COFF: header/section metadata, debug-directory analysis, import/export inventory.
- JVM/JAR: ZIP inventory, class-file metadata, manifest validation.
- ELF: program/section metadata and symbol/debug inventory.

Format adapters should expose analysis data to passes rather than allowing passes to parse bytes independently. This keeps validation centralized and makes the pipeline testable.
