"""``airteam regression``: per-attack verdicts from the trials recorded in a run.

Trials are read from the verified evidence chain, never from a side file, so a
verdict cannot be flipped without breaking chain verification.
"""

from collections.abc import Mapping, Sequence

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from airteam.core.evidence import EvidenceRecord
from airteam.core.stats import (
    RegressionResult,
    Verdict,
    application_metrics,
    regression_verdict_for_trials,
    wilson_interval,
)
from airteam.core.trials import Trial, trials_by_attack

_STYLE = {Verdict.PASS: "green", Verdict.FAIL: "red", Verdict.INCONCLUSIVE: "yellow"}


def evaluate_run(
    records: Sequence[EvidenceRecord], threshold: float
) -> dict[str, tuple[RegressionResult, list[Trial]]]:
    """Verdict per attack, keyed by attack ID in sorted order."""
    grouped = trials_by_attack(records)
    return {
        attack_id: (regression_verdict_for_trials(trials, threshold), trials)
        for attack_id, trials in sorted(grouped.items())
    }


def _fraction(count: int | None, n: int) -> str:
    return "-" if count is None else f"{count}/{n}"


def render_regression(
    console: Console,
    run_id: str,
    results: Mapping[str, tuple[RegressionResult, list[Trial]]],
    threshold: float,
) -> None:
    console.print(
        f"[bold]Regression — {escape(run_id)}[/]  threshold {threshold * 100:g}% "
        "(rule of three), recorded trials only"
    )
    if not results:
        console.print("[yellow]No trials recorded in this run: nothing to judge.[/]")
        return

    table = Table()
    table.add_column("attack", no_wrap=True)
    table.add_column("verdict", no_wrap=True)
    for column in ("breach", "95% CI", "induced", "contained"):
        table.add_column(column)
    for attack_id, (result, trials) in results.items():
        metrics = application_metrics(trials)
        n = metrics.valid_trials
        ci = escape(str(wilson_interval(result.hits, n))) if n else "-"
        containment = metrics.containment_rate
        table.add_row(
            escape(attack_id),
            f"[{_STYLE[result.verdict]}]{result.verdict.value.upper()}[/]",
            _fraction(metrics.breached, n),
            ci,
            _fraction(metrics.induced, n),
            "-" if containment is None else f"{containment:.0%}",
        )
    console.print(table)
    for attack_id, (result, _) in results.items():
        console.print(f"  {escape(attack_id)}: {escape(result.reason)}")
