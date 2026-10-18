# Changelog

## [Unreleased] — M2 providers

### Added
- `openai_compatible` provider (`providers/openai_compatible.py`) for OpenAI, vLLM, Ollama, LM Studio and gateways. Uses `scan.timeout_seconds`; 429, 5xx, timeouts and connection errors are retryable, other errors are not. Redirects are refused because they could leave the authorization scope. Tool-role case messages are sent as answers to a synthetic assistant tool call, so they stay in the tool channel.
- `ai.api_key_env`: the API key is read from the named environment variable at scan time. It is never stored in config, evidence or error messages, and is only sent over https or to a loopback host.

- `http` provider (`providers/http.py`) for custom chat endpoints, such as your own app's API. It POSTs the case messages under `ai.http.messages_field` and reads the reply at the dotted `ai.http.response_path`. It shares timeouts, retry classification, redirect refusal and API-key rules with `openai_compatible` through one `post_json` helper.

### Changed
- `ai.provider: http` requires `ai.endpoint` at config load.
- `ai.provider: openai_compatible` now requires `ai.endpoint` and `ai.model` at config load.

## M1 execution engine

### Added
- Case file format `airteam/case@1` (`docs/case-format.md`) and loader (`engine/cases.py`): pure YAML data, strict validation at load time. Canaries are allowed only in hidden context, placeholders are filled in a single pass, schema contracts use strict types, and an induction matcher may not match a canary.
- `airteam scan` / `airteam ai scan`: load config and cases, run, store the run, build findings (breaches ≥ `success_rule.k`, deterministic `F-001…` IDs, evidence refs), then exit 1 on `fail_on` findings, 3 if any case is inconclusive, 2 on load/config/provider errors.
- The `mock` provider stands in for the paired playground: the `vulnerable` variant echoes every message, other variants refuse.
- Provider interface (`providers/base.py`) and a deterministic `MockProvider`: the same request always gives the same completion; responders get an RNG seeded from the request hash.
- Canary oracle: exact match, then a normalized match that ignores case, spacing and punctuation. Canaries shorter than 12 alphanumerics are rejected to avoid false positives.
- Schema oracle: positive when the output is not JSON or fails a strict contract model.
- `BudgetTracker` (requests, tokens, run time; retries count as requests) and `RateLimiter`, both with injectable clocks.
- Trial runner (`engine/runner.py`): applies the attack's execution policy (per-trial seeds, temperature), retries transient provider errors, records every request, response and trial in the evidence chain. A budget stop is recorded and leaves the verdict INCONCLUSIVE instead of a false PASS.

### Changed
- Default `ExecutionPolicy.trials` 10 → 30, so 0 breaches can PASS at the default 10% threshold.
- Default scan budget: `max_requests` 100 → 1000, `max_tokens` 10,000 → 100,000.

## M2 statistics, reporting, replay (engine pieces)

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
