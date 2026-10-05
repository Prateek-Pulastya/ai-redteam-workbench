# Changelog

## [Unreleased] — M2 statistics, reporting, replay (engine pieces)

### Added
- `core/stats.py`: Wilson 95% interval; regression verdicts PASS / FAIL / INCONCLUSIVE using the rule of three (spec §0A.5). Errored trials do not count toward N.
- `Reproducibility.ci95`: Wilson interval serialized with every finding.
- Measurement Card model and YAML loader with validation (spec §0A.6).
- JSON run report (`reports/json.py`), written by `airteam report --run RUN_ID` to `results/<run>/report.json`.
- `airteam replay RUN_ID --evidence`: renders a stored, chain-verified run with no network access. `--live` still exits 2 because it needs the executor.
- `exit_code_for_verdicts`: maps verdicts to exit codes (spec §0A.16). FAIL takes precedence over INCONCLUSIVE, and an empty set is INCONCLUSIVE.
- Trial outcomes are recorded in the hash-chained evidence (`record_trial`, `trials_by_attack`). Verdicts therefore cannot be flipped without failing chain verification.
- Induction, Breach and Containment metrics (spec §0A.6). Containment is undefined when induction is zero, unobserved, or smaller than the breach count.
- `airteam regression --run RUN_ID [--threshold 0.1]`: per-attack verdicts from recorded trials, with exit codes 0 / 1 / 3 (2 on tampering, malformed records, or a bad threshold).

### Fixed
- `RunStore.load` failed on any run that had findings, because the computed `rate` field was rejected by `extra="forbid"` on reload.
- `RunStore.load` now raises `StorageError`, not a raw `ValidationError`, for malformed run files.

## M0 Foundation

### Added
- Apache-2.0 license.
- Repository layout, packaging (uv + hatchling), CI, Dockerfile, pre-commit.
- CLI skeleton: `init`, `targets`; stubs for `scan`, `api scan`, `ai scan`, `benchmark`, `replay`, `report`.
- Domain model: `SecurityProperty`, `Oracle`/`OracleResult`, `Control`, `Variant`, `Attack`/`ExecutionPolicy`, `Trial`, `Finding`, `Reproducibility`, `RunMetadata`.
- Oracle-based confidence rules (spec §0A.4).
- Hash-chained evidence records with verification (spec §0A.9).
- Configuration with enforced authorization scope, ownership map, and config hashing.
