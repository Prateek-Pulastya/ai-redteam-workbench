import random
import threading

import pytest

from airteam.core.attacks import Attack, ExecutionPolicy
from airteam.core.config import ScanBudget
from airteam.core.evidence import EvidenceChain, verify_chain
from airteam.engine.budget import BudgetTracker, RateLimiter
from airteam.engine.runner import BUDGET_RECORD_KIND, Runner, TrialCase
from airteam.oracles.canary import CanaryOracle
from airteam.providers.base import Completion, CompletionRequest, Message
from airteam.providers.mock import MockProvider
from airteam.replay.regression import evaluate_run

CANARY = "AIRTEAM-CANARY-00112233aabbccdd"


def _case(trials: int, attack_id: str = "concurrency-check") -> TrialCase:
    attack = Attack(
        id=attack_id,
        name="Concurrency check",
        category="smoke",
        objective="Check that parallel trials record like sequential ones.",
        property_id="no-canary-egress",
        execution=ExecutionPolicy(trials=trials, seed=100),
    )
    return TrialCase(
        attack=attack,
        build_request=lambda i: CompletionRequest(
            messages=(
                Message(role="system", content=f"ref {CANARY}"),
                Message(role="user", content=f"question {i}"),
            )
        ),
        oracles=(CanaryOracle([CANARY]),),
    )


def _sometimes_echo(request: CompletionRequest, rng: random.Random) -> str:
    return request.messages[0].content if rng.random() < 0.5 else "We open at 11:00."


def _chain_for(concurrency: int, trials: int = 30) -> EvidenceChain:
    chain = EvidenceChain()
    runner = Runner(
        MockProvider(_sometimes_echo),
        chain,
        BudgetTracker(ScanBudget()),
        max_concurrency=concurrency,
    )
    runner.run_all([_case(trials)])
    return chain


def test_parallel_evidence_is_identical_to_sequential() -> None:
    sequential, parallel = _chain_for(1), _chain_for(8)
    assert verify_chain(parallel.records)
    assert parallel.head == sequential.head
    kinds = [r.kind for r in parallel.records[:3]]
    assert kinds == ["request", "response", "trial"]  # per-trial grouping, in index order


class BarrierProvider:
    """Answers only once ``parties`` calls are in flight at the same time."""

    model_id = "barrier"

    def __init__(self, parties: int) -> None:
        self.barrier = threading.Barrier(parties, timeout=5)

    def complete(self, request: CompletionRequest) -> Completion:
        self.barrier.wait()  # raises BrokenBarrierError if calls are serialised
        return Completion(text="ok", model_id=self.model_id, prompt_tokens=1, completion_tokens=1)


def test_trials_really_run_in_parallel() -> None:
    chain = EvidenceChain()
    runner = Runner(BarrierProvider(4), chain, BudgetTracker(ScanBudget()), max_concurrency=4)
    trials = runner.run(_case(trials=8))
    assert [t.index for t in trials] == list(range(8))
    assert all(t.valid for t in trials)


def test_budget_is_exact_under_concurrency() -> None:
    chain = EvidenceChain()
    tracker = BudgetTracker(ScanBudget(max_requests=12))
    runner = Runner(MockProvider(["We open at 11:00."]), chain, tracker, max_concurrency=8)
    assert not runner.run_all([_case(trials=30), _case(trials=5, attack_id="later-case")])
    assert tracker.requests == 12
    (stop,) = [r for r in chain.records if r.kind == BUDGET_RECORD_KIND]
    assert stop.payload["completed_trials"] == 12
    ((result, trials),) = evaluate_run(
        chain.records, threshold=0.1
    ).values()  # later case never ran
    assert len(trials) == 12
    assert result.verdict.value == "inconclusive"


def test_rate_limiter_is_safe_across_threads() -> None:
    now = [0.0]
    lock = threading.Lock()

    def sleep(seconds: float) -> None:
        with lock:
            now[0] += seconds

    limiter = RateLimiter(10.0, clock=lambda: now[0], sleep=sleep)
    threads = [threading.Thread(target=limiter.wait) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert now[0] == pytest.approx(1.9)  # 19 gaps of 0.1 s after the first call


def test_concurrency_must_be_positive() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        Runner(MockProvider(["x"]), EvidenceChain(), BudgetTracker(ScanBudget()), max_concurrency=0)
