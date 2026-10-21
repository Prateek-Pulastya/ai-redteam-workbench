"""Trial runner (spec §0A.3, §0A.5).

The engine never writes prompts. A :class:`TrialCase` supplies the request for
each trial and the oracles that judge it; the runner applies the attack's
execution policy, enforces the budget, and appends every request, response and
trial outcome to the evidence chain, where ``airteam regression`` reads them.

Redaction must happen before a payload reaches the chain: cases must not put
real credentials in requests. Canaries are synthetic and are recorded as-is.
"""

from collections.abc import Callable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass

from airteam.core.attacks import Attack
from airteam.core.evidence import EvidenceChain
from airteam.core.trials import Trial, record_trial
from airteam.engine.budget import BudgetExceeded, BudgetTracker, RateLimiter
from airteam.oracles.base import Observation, Oracle
from airteam.providers.base import (
    Completion,
    CompletionRequest,
    LLMProvider,
    ProviderError,
    TransientProviderError,
)

RequestBuilder = Callable[[int], CompletionRequest]
"""Trial index -> request. Temperature and seed are overwritten from the policy."""

InductionCheck = Callable[[Observation], bool]
"""Whether the model attempted the unsafe action, independent of whether it got through."""

BUDGET_RECORD_KIND = "budget_exhausted"


@dataclass(frozen=True)
class TrialCase:
    attack: Attack
    build_request: RequestBuilder
    oracles: tuple[Oracle, ...]
    induction: InductionCheck | None = None

    def __post_init__(self) -> None:
        if not self.oracles:
            raise ValueError(f"case {self.attack.id} has no oracles: nothing could judge it")


def trial_seed(base: int | None, index: int) -> int | None:
    """Per-trial seed: distinct across trials, identical across reruns."""
    return None if base is None else base + index


class Runner:
    def __init__(
        self,
        provider: LLMProvider,
        chain: EvidenceChain,
        budget: BudgetTracker,
        limiter: RateLimiter | None = None,
        max_concurrency: int = 1,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        self._provider = provider
        self._chain = chain
        self._budget = budget
        self._limiter = limiter
        self._concurrency = max_concurrency

    def run_all(self, cases: Sequence[TrialCase]) -> bool:
        """Run every case in order. False if the budget stopped the run early."""
        ids = [c.attack.id for c in cases]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"duplicate attack ids: {duplicates}")
        try:
            for case in cases:
                self.run(case)
        except BudgetExceeded:
            return False
        return True

    def run(self, case: TrialCase) -> list[Trial]:
        """Execute all planned trials of one case, up to ``max_concurrency`` at a time.

        Provider calls run in parallel, but evidence is appended afterwards in trial
        order, so the chain is identical to a sequential run and reruns reproduce.
        Every trial that was actually sent is recorded. On budget exhaustion a
        ``budget_exhausted`` record follows and the exception propagates: the
        missing trials lower N, so the verdict becomes INCONCLUSIVE rather than a
        false PASS.
        """
        # ponytail: parallel within a case only; cases still run one after another.
        policy = case.attack.execution
        requests = [
            case.build_request(i).model_copy(
                update={"temperature": policy.temperature, "seed": trial_seed(policy.seed, i)}
            )
            for i in range(policy.trials)
        ]
        with ThreadPoolExecutor(max_workers=self._concurrency) as pool:
            futures = [pool.submit(self._complete, r) for r in requests]
            outcomes = [_outcome(f) for f in futures]

        trials: list[Trial] = []
        stopped: BudgetExceeded | None = None
        for index, (request, outcome) in enumerate(zip(requests, outcomes, strict=True)):
            if isinstance(outcome, BudgetExceeded):
                stopped = stopped or outcome  # never sent: nothing to record
                continue
            trials.append(self._record(case, index, request, outcome))
        if stopped is not None:
            self._chain.append(
                BUDGET_RECORD_KIND,
                {
                    "attack_id": case.attack.id,
                    "completed_trials": len(trials),
                    "planned_trials": policy.trials,
                    "reason": str(stopped),
                },
            )
            raise stopped
        return trials

    def _record(
        self,
        case: TrialCase,
        index: int,
        request: CompletionRequest,
        outcome: Completion | ProviderError,
    ) -> Trial:
        attack_id = case.attack.id
        self._chain.append(
            "request",
            {"attack_id": attack_id, "trial": index, "request": request.model_dump(mode="json")},
        )
        if isinstance(outcome, ProviderError):
            trial = Trial(index=index, error=f"provider error: {outcome}")
        else:
            self._chain.append(
                "response",
                {
                    "attack_id": attack_id,
                    "trial": index,
                    "completion": outcome.model_dump(mode="json"),
                },
            )
            observation = Observation(text=outcome.text)
            trial = Trial(
                index=index,
                oracle_results=tuple(o.evaluate(observation) for o in case.oracles),
                induced=None if case.induction is None else case.induction(observation),
            )
        record_trial(self._chain, attack_id, trial)
        return trial

    def _complete(self, request: CompletionRequest) -> Completion:
        retries_left = self._budget.budget.max_retries
        while True:
            self._budget.before_request()
            if self._limiter is not None:
                self._limiter.wait()
            try:
                completion = self._provider.complete(request)
            except TransientProviderError:
                if retries_left == 0:
                    raise
                retries_left -= 1
                continue
            self._budget.add_tokens(completion.total_tokens)
            return completion


def _outcome(future: "Future[Completion]") -> Completion | ProviderError | BudgetExceeded:
    try:
        return future.result()
    except (ProviderError, BudgetExceeded) as exc:
        return exc
