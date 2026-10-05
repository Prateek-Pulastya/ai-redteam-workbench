"""Scan budget and rate limiting (spec §31). Clocks are injectable for tests."""

import time
from collections.abc import Callable

from airteam.core.config import ScanBudget

Clock = Callable[[], float]
Sleep = Callable[[float], None]


class BudgetExceeded(Exception):
    """A scan limit was reached; no further provider requests may be sent."""


class BudgetTracker:
    def __init__(self, budget: ScanBudget, clock: Clock = time.monotonic) -> None:
        self.budget = budget
        self._clock = clock
        self._started = clock()
        self.requests = 0
        self.tokens = 0

    def before_request(self) -> None:
        """Reserve one request, or raise if any limit is already spent."""
        b = self.budget
        if self.requests >= b.max_requests:
            raise BudgetExceeded(f"request budget spent ({self.requests}/{b.max_requests})")
        if self.tokens >= b.max_tokens:
            raise BudgetExceeded(f"token budget spent ({self.tokens}/{b.max_tokens})")
        elapsed = self._clock() - self._started
        if elapsed >= b.max_run_seconds:
            raise BudgetExceeded(f"run time budget spent ({elapsed:.0f}s/{b.max_run_seconds:g}s)")
        self.requests += 1

    def add_tokens(self, count: int) -> None:
        self.tokens += count


class RateLimiter:
    """Spaces requests at least ``1 / rate`` seconds apart."""

    def __init__(
        self, rate_per_second: float, clock: Clock = time.monotonic, sleep: Sleep = time.sleep
    ) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self._interval = 1.0 / rate_per_second
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._last is not None:
            delay = self._last + self._interval - now
            if delay > 0:
                self._sleep(delay)
                now += delay
        self._last = now
