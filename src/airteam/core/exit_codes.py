"""CLI exit codes (spec §0A.16)."""

from collections.abc import Iterable
from enum import IntEnum

from airteam.core.stats import Verdict


class ExitCode(IntEnum):
    OK = 0
    """No policy-breaking findings; all regression cases PASS."""

    POLICY_VIOLATION = 1
    """Findings violate the configured threshold, or a regression FAILed."""

    ERROR = 2
    """Scanner or configuration error."""

    INCONCLUSIVE = 3
    """Not enough valid trials for a statistical verdict."""


def exit_code_for_verdicts(verdicts: Iterable[Verdict]) -> ExitCode:
    """Collapse regression verdicts into one exit code.

    Any FAIL wins over INCONCLUSIVE: a confirmed regression must never be hidden
    behind "not enough data" on another case. No verdicts at all is INCONCLUSIVE,
    so a gate that ran zero cases cannot pass green.
    """
    seen = set(verdicts)
    if Verdict.FAIL in seen:
        return ExitCode.POLICY_VIOLATION
    if not seen or Verdict.INCONCLUSIVE in seen:
        return ExitCode.INCONCLUSIVE
    return ExitCode.OK
