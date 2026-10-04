# Contributing

## Setup

```bash
uv sync
uv run pre-commit install
```

## Checks (same as CI)

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

## Ground rules

- Every finding must be backed by an oracle (canary, server state, response diff, schema). LLM judges are supporting signals only.
- Synthetic data only. Never commit real credentials, tokens, or customer data.
- New feature ideas go to `docs/ideas.md` first and are classified CORE / MVP / VERSIONED FUTURE / REJECTED (spec §62).
