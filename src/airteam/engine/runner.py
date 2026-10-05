"""Trial runner (spec §0A.3, §0A.5).

The engine never writes prompts. A :class:`TrialCase` supplies the request for
each trial and the oracles that judge it; the runner applies the attack's
execution policy, enforces the budget, and appends every request, response and
trial outcome to the evidence chain, where ``airteam regression`` reads them.

Redaction must happen before a payload reaches the chain: cases must not put
real credentials in requests. Canaries are synthetic and are recorded as-is.
"""

from collections.abc import Callable, Sequence
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
    ) -> None:
        self._provider = provider
        self._chain = chain
        self._budget = budget
        self._limiter = limiter

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
        """Execute all planned trials of one case.

        On budget exhaustion the completed trials stay recorded, a
        ``budget_exhausted`` record is appended, and the exception propagates:
        the missing trials lower N, so the verdict becomes INCONCLUSIVE rather
        than a false PASS.
        """
        policy = case.attack.execution
        trials: list[Trial] = []
        for index in range(policy.trials):
            try:
                trials.append(self._run_trial(case, index))
            except BudgetExceeded as exc:
                self._chain.append(
                    BUDGET_RECORD_KIND,
                    {
                        "attack_id": case.attack.id,
                        "completed_trials": len(trials),
                        "planned_trials": policy.trials,
                        "reason": str(exc),
                    },
                )
                raise
        return trials

    def _run_trial(self, case: TrialCase, index: int) -> Trial:
        policy = case.attack.execution
        request = case.build_request(index).model_copy(
            update={"temperature": policy.temperature, "seed": trial_seed(policy.seed, index)}
        )
        attack_id = case.attack.id
        self._chain.append(
            "request",
            {"attack_id": attack_id, "trial": index, "request": request.model_dump(mode="json")},
        )
        try:
            completion = self._complete(request)
        except ProviderError as exc:
            trial = Trial(index=index, error=f"provider error: {exc}")
        else:
            self._chain.append(
                "response",
                {
                    "attack_id": attack_id,
                    "trial": index,
                    "completion": completion.model_dump(mode="json"),
                },
            )
            observation = Observation(text=completion.text)
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
