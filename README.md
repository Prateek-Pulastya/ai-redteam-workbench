# AI Red-Team Workbench

**Open-source security testing for AI applications and their APIs.** Test LLM, RAG and agent attack paths and API authorization, prove impact with server-side evidence, and turn failures into regression tests.

> The model will be fooled. The workbench proves whether your application contained it.

**Status:** pre-alpha. The AI scan path works end to end. The API layer (M3) is not built yet.

## What exists today

- `airteam scan` / `airteam ai scan`: runs `airteam/case@1` case files ([format](docs/case-format.md)) against a target and stores a hash-chained, tamper-evident run.
- Providers: `mock` (offline, paired vulnerable/fixed), `openai_compatible` (OpenAI, Ollama, vLLM, LM Studio, gateways), and `http` (your own app's chat endpoint).
- Deterministic oracles (canary, schema), repeated trials with Wilson 95% intervals, and PASS / FAIL / INCONCLUSIVE regression verdicts (rule of three).
- `airteam regression`, `airteam replay --evidence`, `airteam report` (JSON).
- Concurrency, request/token/time budgets, and rate limiting.
- An authorization scope enforced on every endpoint (loopback-only in `local` mode).
- An AI attack pack in `attacks/ai/`, one case per OWASP LLM Top 10 (2025) category.

## Quick start (development)

```bash
uv sync
uv run airteam init
uv run airteam targets
uv run airteam ai scan --cases attacks/ai
uv run pytest
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No policy-breaking findings |
| 1 | Findings violate threshold / regression FAIL |
| 2 | Scanner or configuration error |
| 3 | Inconclusive: insufficient valid trials |

## Control mapping

What each test and guardrail produces evidence for. A reference appears only where it genuinely fits; partial fits are marked **(proxy)** with the reason.

**Read this first:**
- **Evidence, not conformity.** A passing run is test evidence for these controls. It does not by itself make a system compliant.
- **EU AI Act Art. 15** (accuracy, robustness and cybersecurity) applies to **high-risk** AI systems only. Per the [AI Act Explorer](https://artificialintelligenceact.eu/article/15/), it applies from 2 Dec 2027 (Annex III) or 2 Aug 2028 (Annex I). For other systems, read the Art. 15 column as good practice.
- **ISO/IEC 42001** is a management-system standard. Results here are evidence for an Annex A control *if* the system is in your AIMS scope and the control is in your Statement of Applicability.
- **NIST AI RMF** references are AI RMF 1.0 subcategories. Where helpful, a suggested action from the Generative AI Profile (NIST AI 600-1) is added.

### Tests (`attacks/ai/`)

| Case | OWASP LLM Top 10 (2025) | EU AI Act Art. 15 | NIST AI RMF | ISO/IEC 42001 Annex A |
|---|---|---|---|---|
| `llm01-direct-override-001` | LLM01 Prompt Injection | 15(5): resilience against third parties altering use or outputs; inputs designed to make the model err | MEASURE 2.7; AI 600-1 MS-2.7-007 (red-teaming for prompt injection) | A.6.2.4 verification and validation |
| `llm01-indirect-tool-001` | LLM01 Prompt Injection | 15(5), as above | MEASURE 2.7; MS-2.7-007 | A.6.2.4 |
| `llm02-session-bleed-001` | LLM02 Sensitive Information Disclosure | 15(5): confidentiality attacks | MEASURE 2.10 (privacy); MEASURE 2.7 | A.6.2.4 |
| `llm03-plugin-description-001` | LLM03 Supply Chain | 15(5): exploiting system vulnerabilities. **(proxy)** Art. 15 names poisoned *pre-trained components used in training*; this case tests a compromised runtime plugin instead | MEASURE 2.7; GOVERN 6.1 (third-party risk), as supporting evidence | A.6.2.4; A.10.3 suppliers |
| `llm04-poisoned-retrieval-001` | LLM04 Data and Model Poisoning | 15(5) data poisoning. **(proxy)** Art. 15 means *training* data; this case tests a poisoned retrieval corpus at runtime | MEASURE 2.7; MS-2.7-007 (data poisoning) | A.6.2.4; A.7.5 data provenance (if the corpus is in AIMS scope) |
| `llm05-contract-escape-001` | LLM05 Improper Output Handling | 15(4): resilience to errors and inconsistencies in interaction with other systems | MEASURE 2.7 | A.6.2.4 |
| `llm06-tool-allowlist-001` | LLM06 Excessive Agency | 15(5): attempts to alter the system's use | MEASURE 2.7 | A.6.2.4; A.9.4 intended use |
| `llm07-prompt-extraction-001` | LLM07 System Prompt Leakage | 15(5): confidentiality attacks | MEASURE 2.7 | A.6.2.4 |
| `llm08-cross-tenant-retrieval-001` | LLM08 Vector and Embedding Weaknesses | 15(5): confidentiality attacks | MEASURE 2.10; MEASURE 2.7 | A.6.2.4 |
| `llm09-false-premise-001` | LLM09 Misinformation | 15(1) and 15(3): accuracy (not cybersecurity) | MEASURE 2.5 (valid and reliable) | A.6.2.4 |
| `llm10-output-flood-001` | LLM10 Unbounded Consumption | 15(5): altering performance. **(proxy)** It checks a per-reply length bound only, not cost or availability | MEASURE 2.7 | A.6.2.4 |
| `smoke-canary-001` | tagged LLM07 in the file, but a harness self-test, not a security test | none | MEASURE 2.13: shows the oracle can fire, so a PASS is not a silent miss | none |

Schema-oracle cases (LLM05, LLM06, LLM09, LLM10) only produce evidence against a real provider; the mock cannot judge them.

### Guardrails in the workbench (how results are produced)

| Guardrail | What it does | EU AI Act Art. 15 | NIST AI RMF | ISO/IEC 42001 Annex A |
|---|---|---|---|---|
| Deterministic oracles (canary, schema); LLM judges and heuristics can never confirm a finding | Findings are decided by checkable evidence, not by model opinion | 15(3): declared, measurable metrics | MEASURE 2.1 (test sets, metrics and tools documented) | A.6.2.4 |
| Repeated trials, Wilson 95% CI, PASS / FAIL / INCONCLUSIVE by the rule of three | A clean result is a bounded rate, not one lucky run; too few trials is never a PASS | 15(1): consistent performance; 15(3) | MEASURE 2.5; MEASURE 2.13 | A.6.2.4 |
| Regression gate (`airteam regression`, CI exit codes) | A fixed issue is re-tested on every change | 15(1): consistently throughout the lifecycle | MEASURE 2.7; MANAGE 4.1 when run on a schedule against a deployed system | A.6.2.4; A.6.2.5 deployment (release criteria) |
| Paired vulnerable / fixed variants | The same case must fail on the vulnerable and pass on the fixed variant, so the false-positive rate is measurable | none | MEASURE 2.13 | A.6.2.4 |
| Hash-chained evidence, verified on every load; `replay --evidence` | Results cannot be edited without detection and can be re-inspected offline | none (Art. 12 record-keeping covers the AI system's own logs, not test evidence) | MEASURE 2.1 (documentation) | A.6.2.3 documentation of design and development (test records) |
| Authorization scope, loopback-only `local` mode, refused redirects, API keys only from env and only over https/loopback, budgets and rate limits | Keeps testing inside what you are authorized to touch | none: these protect the test itself, not the system under test | none claimed | none claimed |

Gaps against these frameworks today: no API-layer authorization tests yet (M3), no MITRE ATLAS mapping, and no checks for training-time poisoning or model-weight provenance.

## Roadmap

See the project specification (v1.1, §0A.15): M0 foundation → M1 cross-layer walking skeleton → M2 statistics + replay → M3 breadth → M4 benchmark + v0.1.

## License

[Apache License 2.0](LICENSE)

## Responsible use

Only test systems you are authorized to test. The scanner refuses endpoints outside the configured scope and never infers authorization from reachability. See [SECURITY.md](SECURITY.md).
