"""``airteam scan``: load cases, run them, store the run, build findings, pick the exit code.

Exit codes (docs/case-format.md): 1 when a finding's severity is in ``policy.fail_on``,
otherwise 3 when any case is INCONCLUSIVE, otherwise 0. Errors (2) are raised to the
CLI before anything runs. ``airteam regression`` remains the statistical gate.
"""

import random
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from airteam import __version__
from airteam.core.config import AirteamConfig
from airteam.core.evidence import EvidenceChain, EvidenceRecord
from airteam.core.exit_codes import ExitCode
from airteam.core.findings import Finding, Reproducibility, assess_confidence
from airteam.core.runs import RunMetadata, new_run_id
from airteam.core.stats import RegressionResult, Verdict, regression_verdict_for_trials
from airteam.core.storage import RunStore
from airteam.core.trials import TRIAL_RECORD_KIND, Trial
from airteam.engine.budget import BudgetTracker, RateLimiter
from airteam.engine.cases import LoadedCase
from airteam.engine.runner import Runner
from airteam.providers.base import CompletionRequest, LLMProvider
from airteam.providers.mock import MockProvider

MOCK_REFUSAL = "I can't share internal details, but I'm happy to help otherwise."


class ScanError(Exception):
    """The scan cannot start: unsupported provider or missing configuration."""


def _echo_everything(request: CompletionRequest, _rng: random.Random) -> str:
    return "\n".join(m.content for m in request.messages)


def _refuse(_request: CompletionRequest, _rng: random.Random) -> str:
    return MOCK_REFUSAL


def select_provider(cfg: AirteamConfig) -> LLMProvider:
    if cfg.ai is None:
        raise ScanError("the config has no 'ai' section, so there is no model to scan")
    if cfg.ai.provider != "mock":
        raise ScanError(f"provider {cfg.ai.provider!r} is not implemented yet (M2); use 'mock'")
    # ponytail: the mock models the paired playground by variant name only; a real
    # playground target replaces this once the HTTP provider exists.
    if cfg.target.variant == "vulnerable":
        return MockProvider(_echo_everything, name="mock-vulnerable")
    return MockProvider(_refuse, name=f"mock-{cfg.target.variant}")


@dataclass(frozen=True)
class CaseOutcome:
    case: LoadedCase
    verdict: RegressionResult
    finding: Finding | None


@dataclass(frozen=True)
class ScanResult:
    meta: RunMetadata
    path: Path
    outcomes: tuple[CaseOutcome, ...]
    complete: bool
    exit_code: ExitCode


def _trials_with_seq(records: Sequence[EvidenceRecord]) -> dict[str, list[tuple[int, Trial]]]:
    grouped: dict[str, list[tuple[int, Trial]]] = {}
    for record in records:
        if record.kind == TRIAL_RECORD_KIND:
            attack_id = str(record.payload["attack_id"])
            trial = Trial.model_validate(record.payload["trial"])
            grouped.setdefault(attack_id, []).append((record.seq, trial))
    return grouped


def _finding(
    cfg: AirteamConfig, case: LoadedCase, recorded: list[tuple[int, Trial]], number: int
) -> Finding | None:
    attack, spec = case.spec.attack, case.spec.finding
    trials = [t for _, t in recorded]
    breached = [(seq, t) for seq, t in recorded if t.breached]
    confidence = assess_confidence(trials)
    if len(breached) < attack.execution.success_rule.k or confidence is None:
        return None
    first = next(r for r in breached[0][1].oracle_results if r.positive and r.oracle.deterministic)
    repro = Reproducibility.from_trials(trials)
    return Finding(
        finding_id=f"F-{number:03d}",
        severity=spec.severity,
        confidence=confidence,
        category=attack.category,
        attack_id=attack.id,
        property_id=attack.property_id,
        target=cfg.target.name,
        variant=cfg.target.variant,
        summary=f"{attack.name}: {repro} valid trials breached {attack.property_id}",
        observed_behavior=f"trial {breached[0][1].index}: {first.reason}",
        expected_behavior=spec.expected_behavior,
        reproducibility=repro,
        evidence_refs=tuple(str(seq) for seq, _ in breached),
        frameworks=attack.frameworks,
        remediation=spec.remediation,
        missing_control=spec.missing_control,
    )


def run_scan(
    cfg: AirteamConfig,
    cases: Sequence[LoadedCase],
    provider: LLMProvider,
    store: RunStore,
    threshold: float,
) -> ScanResult:
    meta = RunMetadata(
        run_id=new_run_id(),
        scanner_version=__version__,
        config_hash=cfg.config_hash(),
        target=cfg.target.name,
        variant=cfg.target.variant,
        model_ids=(provider.model_id,),
        started_at=datetime.now(UTC),
    )
    chain = EvidenceChain()
    # ponytail: no rate limit for the in-process mock; network providers get one.
    limiter = (
        None
        if cfg.ai is None or cfg.ai.provider == "mock"
        else RateLimiter(cfg.scan.rate_limit_per_second)
    )
    runner = Runner(provider, chain, BudgetTracker(cfg.scan), limiter)
    complete = runner.run_all([c.trial_case for c in cases])

    recorded = _trials_with_seq(chain.records)
    outcomes: list[CaseOutcome] = []
    for case in cases:  # already sorted by attack id, so finding numbers are stable
        trials = recorded.get(case.spec.attack.id, [])
        finding = _finding(
            cfg, case, trials, number=sum(o.finding is not None for o in outcomes) + 1
        )
        verdict = regression_verdict_for_trials([t for _, t in trials], threshold)
        outcomes.append(CaseOutcome(case=case, verdict=verdict, finding=finding))

    findings = [o.finding for o in outcomes if o.finding is not None]
    path = store.save(meta, chain, findings)

    if any(f.severity in cfg.policy.fail_on for f in findings):
        code = ExitCode.POLICY_VIOLATION
    elif any(o.verdict.verdict is Verdict.INCONCLUSIVE for o in outcomes):
        code = ExitCode.INCONCLUSIVE
    else:
        code = ExitCode.OK
    return ScanResult(
        meta=meta, path=path, outcomes=tuple(outcomes), complete=complete, exit_code=code
    )
