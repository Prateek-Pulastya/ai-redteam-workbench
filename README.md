# AI Red-Team Workbench

**Open-source security testing for AI applications and their APIs.** Test LLM, RAG and agent attack paths and API authorization, prove impact with server-side evidence, and turn failures into regression tests.

> The model will be fooled. The workbench proves whether your application contained it.

**Status:** pre-alpha (milestone M0: foundation). Nothing here scans anything yet.

## What exists today

- `airteam` CLI skeleton (`init`, `targets`; other commands are stubs that exit with code 2)
- Domain model: security properties, oracles, controls, variants, trials, findings, oracle-based confidence rules, hash-chained evidence
- Configuration with enforced authorization scope (loopback-only in `local` mode)

## Quick start (development)

```bash
uv sync
uv run airteam --help
uv run airteam init
uv run airteam targets
uv run pytest
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No policy-breaking findings |
| 1 | Findings violate threshold / regression FAIL |
| 2 | Scanner or configuration error |
| 3 | Inconclusive: insufficient valid trials |

## Roadmap

See the project specification (v1.1, §0A.15): M0 foundation → M1 cross-layer walking skeleton → M2 statistics + replay → M3 breadth → M4 benchmark + v0.1.

## License

[Apache License 2.0](LICENSE)

## Responsible use

Only test systems you are authorized to test. The scanner refuses endpoints outside the configured scope and never infers authorization from reachability. See [SECURITY.md](SECURITY.md).
