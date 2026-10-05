import pytest

from airteam.core.config import ScanBudget
from airteam.engine.budget import BudgetExceeded, BudgetTracker, RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_request_budget() -> None:
    tracker = BudgetTracker(ScanBudget(max_requests=2))
    tracker.before_request()
    tracker.before_request()
    with pytest.raises(BudgetExceeded, match="request budget spent \\(2/2\\)"):
        tracker.before_request()
    assert tracker.requests == 2


def test_token_budget() -> None:
    tracker = BudgetTracker(ScanBudget(max_tokens=10))
    tracker.before_request()
    tracker.add_tokens(10)
    with pytest.raises(BudgetExceeded, match="token budget"):
        tracker.before_request()


def test_time_budget() -> None:
    clock = FakeClock()
    tracker = BudgetTracker(ScanBudget(max_run_seconds=60), clock=clock)
    tracker.before_request()
    clock.now += 60
    with pytest.raises(BudgetExceeded, match="run time budget"):
        tracker.before_request()


def test_rate_limiter_spaces_requests() -> None:
    clock = FakeClock()
    limiter = RateLimiter(4.0, clock=clock, sleep=clock.sleep)
    limiter.wait()
    limiter.wait()
    clock.now += 1.0
    limiter.wait()
    assert clock.slept == [0.25]


def test_rate_limiter_rejects_zero_rate() -> None:
    with pytest.raises(ValueError, match="positive"):
        RateLimiter(0)
