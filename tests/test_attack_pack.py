"""Guard for the case files shipped under ``attacks/``: a broken case fails CI.

Canary cases are also run against the paired mock: the vulnerable mock echoes hidden
context, so every trial must breach; the fixed mock refuses, so the case must PASS.
Schema cases only load here: the mock never returns JSON, so it cannot judge them.
"""

import random
from pathlib import Path

import pytest

from airteam.core.config import ScanBudget
from airteam.core.evidence import EvidenceChain
from airteam.core.stats import Verdict, regression_verdict_for_trials
from airteam.engine.budget import BudgetTracker
from airteam.engine.cases import CanaryOracleSpec, LoadedCase, load_cases
from airteam.engine.runner import Runner
from airteam.engine.scan import MOCK_REFUSAL
from airteam.providers.base import CompletionRequest
from airteam.providers.mock import MockProvider

ATTACKS = Path(__file__).resolve().parent.parent / "attacks"
CASES = load_cases(ATTACKS)


def _echo(request: CompletionRequest, _rng: random.Random) -> str:
    return "\n".join(m.content for m in request.messages)


def _run(case: LoadedCase, provider: MockProvider) -> Verdict:
    runner = Runner(provider, EvidenceChain(), BudgetTracker(ScanBudget()))
    trials = runner.run(case.trial_case)
    assert len(trials) == case.spec.attack.execution.trials
    return regression_verdict_for_trials(trials, threshold=0.1).verdict


def _is_canary_case(case: LoadedCase) -> bool:
    return all(isinstance(o, CanaryOracleSpec) for o in case.spec.oracles)


def test_pack_is_not_empty() -> None:
    assert len(CASES) >= 2


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.spec.attack.id)
def test_case_follows_conventions(case: LoadedCase) -> None:
    attack = case.spec.attack
    assert case.path.stem == attack.id, "file name must equal attack.id"
    assert case.path.parent.name == attack.category, "folder must equal attack.category"
    assert attack.execution.trials >= 30, "fewer than 30 trials can never PASS at 10%"
    assert attack.execution.seed is not None, "unseeded cases are not reproducible"


@pytest.mark.parametrize(
    "case", [c for c in CASES if _is_canary_case(c)], ids=lambda c: c.spec.attack.id
)
def test_canary_case_fails_vulnerable_and_passes_fixed(case: LoadedCase) -> None:
    assert _run(case, MockProvider(_echo, name="mock-vulnerable")) is Verdict.FAIL
    assert _run(case, MockProvider([MOCK_REFUSAL], name="mock-fixed")) is Verdict.PASS
