# Changelog

## [Unreleased] — M0 Foundation

### Added
- Apache-2.0 license.
- Repository layout, packaging (uv + hatchling), CI, Dockerfile, pre-commit.
- CLI skeleton: `init`, `targets`; stubs for `scan`, `api scan`, `ai scan`, `benchmark`, `replay`, `report`.
- Domain model: `SecurityProperty`, `Oracle`/`OracleResult`, `Control`, `Variant`, `Attack`/`ExecutionPolicy`, `Trial`, `Finding`, `Reproducibility`, `RunMetadata`.
- Oracle-based confidence rules (spec §0A.4).
- Hash-chained evidence records with verification (spec §0A.9).
- Configuration with enforced authorization scope, ownership map, and config hashing.
