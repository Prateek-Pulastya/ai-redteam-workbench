# Architecture (M0)

The platform is run-centric. One `Run` executes `Attack`s against a `Target` built as a `Variant` (a declared set of enabled `Control`s). Each attack is executed as N `Trial`s; each trial produces `OracleResult`s; `Finding`s aggregate over trials.

```text
Project
  └── Target
       ├── Variant(s) ── Control(s)
       └── Run (RunMetadata)
            ├── Attack ── SecurityProperty
            ├── Trial(s) ── OracleResult(s)
            ├── Evidence (hash-chained)
            └── Finding(s) ── Reproducibility, FrameworkMapping(s)
```

## Key rules

| Rule | Where |
|---|---|
| A breach requires a deterministic oracle (canary, server_state, response_diff, schema) | `core/trials.py` |
| Confirmed = deterministic breach in ≥2 trials; High = 1; Medium = heuristic only; Low = judge only | `core/findings.py::assess_confidence` |
| Errored trials never count, and are excluded from the denominator | `Trial.valid`, `Reproducibility` |
| Evidence is append-only; each record hashes the previous one | `core/evidence.py` |
| Every endpoint must be in the authorization scope; `local` mode is loopback-only | `core/config.py` |
| Framework mappings always carry an edition version | `core/frameworks.py` |

## Module map

```text
src/airteam/
  core/        base, hashing, exit_codes, frameworks, oracles, properties, controls,
               variants, attacks, trials, findings, evidence, runs, config
  cli/         Typer entry point
  templates/   airteam.yaml written by `airteam init`
```

Engines (`api/`, `ai/`, `oracles/`, `reports/`, `replay/`, `benchmark/`) are added in M1–M4 when they have real code.
