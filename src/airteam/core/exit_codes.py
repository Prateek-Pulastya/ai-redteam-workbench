"""CLI exit codes (spec §0A.16)."""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    """No policy-breaking findings; all regression cases PASS."""

    POLICY_VIOLATION = 1
    """Findings violate the configured threshold, or a regression FAILed."""

    ERROR = 2
    """Scanner or configuration error."""

    INCONCLUSIVE = 3
    """Not enough valid trials for a statistical verdict."""
