"""``airteam`` command-line entry point (spec §8)."""

from enum import StrEnum
from importlib.resources import files
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from airteam import __version__
from airteam.core.config import ConfigError, load_config
from airteam.core.evidence import EvidenceRecord
from airteam.core.exit_codes import ExitCode, exit_code_for_verdicts
from airteam.core.findings import Finding
from airteam.core.runs import RunMetadata
from airteam.core.storage import RunStore, StorageError
from airteam.core.trials import TrialRecordError
from airteam.engine.cases import CaseError, load_cases
from airteam.engine.scan import ScanError, ScanResult, run_scan, select_provider
from airteam.replay.evidence import render_evidence
from airteam.replay.regression import evaluate_run, render_regression
from airteam.reports.json import write_json_report

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="airteam",
    help="Security testing for AI applications and their APIs.",
    no_args_is_help=True,
    add_completion=False,
)
api_app = typer.Typer(help="API security testing.", no_args_is_help=True)
ai_app = typer.Typer(help="LLM / RAG security testing.", no_args_is_help=True)
app.add_typer(api_app, name="api")
app.add_typer(ai_app, name="ai")

ConfigOption = Annotated[
    Path, typer.Option("--config", "-c", help="Path to the assessment configuration.")
]
ResultsOption = Annotated[
    Path, typer.Option("--results-dir", help="Directory holding stored runs.")
]
CasesOption = Annotated[
    Path, typer.Option("--cases", help="Directory of airteam/case@1 YAML files.")
]
ThresholdOption = Annotated[
    float,
    typer.Option(
        "--threshold", help="Maximum acceptable breach rate, in (0, 1]. 0.1 needs N >= 30."
    ),
]


class ReportFormat(StrEnum):
    JSON = "json"
    HTML = "html"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"airteam {__version__}")
        raise typer.Exit(ExitCode.OK)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """AI Red-Team Workbench."""


def _not_yet(command: str, milestone: str) -> NoReturn:
    err_console.print(f"[yellow]'{command}' is not implemented yet (planned for {milestone}).[/]")
    raise typer.Exit(ExitCode.ERROR)


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Where to write the config.")] = Path("airteam.yaml"),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write an example assessment configuration."""
    if path.exists() and not force:
        err_console.print(f"[red]{path} already exists; use --force to overwrite.[/]")
        raise typer.Exit(ExitCode.ERROR)
    template = files("airteam.templates").joinpath("airteam.yaml").read_text(encoding="utf-8")
    path.write_text(template, encoding="utf-8")
    console.print(f"Wrote {path}")


@app.command()
def targets(config: ConfigOption = Path("airteam.yaml")) -> None:
    """Validate the configuration and show the authorized target."""
    try:
        cfg = load_config(config)
    except ConfigError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(ExitCode.ERROR) from exc

    table = Table(title="Targets")
    for column in ("name", "type", "endpoint", "variant", "mode", "scope"):
        table.add_column(column)
    t = cfg.target
    table.add_row(
        t.name,
        t.type.value,
        str(t.endpoint),
        t.variant,
        t.authorization.mode.value,
        ", ".join(t.authorization.scope),
    )
    console.print(table)
    console.print(f"config hash: {cfg.config_hash()}")


def _check_threshold(threshold: float) -> None:
    if not 0.0 < threshold <= 1.0:
        err_console.print(f"[red]--threshold must be in (0, 1], got {threshold}.[/]")
        raise typer.Exit(ExitCode.ERROR)


def _render_scan(result: ScanResult) -> None:
    table = Table(title=f"Scan {result.meta.run_id}  ({result.meta.model_ids[0]})")
    for column in ("attack", "verdict", "breach", "finding"):
        table.add_column(column)
    for o in result.outcomes:
        v = o.verdict
        finding = "-" if o.finding is None else f"{o.finding.finding_id} {o.finding.severity.value}"
        table.add_row(
            escape(o.case.spec.attack.id),
            v.verdict.value.upper(),
            f"{v.hits}/{v.valid_trials}",
            finding,
        )
    console.print(table)
    if not result.complete:
        console.print("[yellow]Scan budget exhausted: remaining trials were not run.[/]")
    console.print(f"Stored {result.path}")


def _scan(config: Path, cases_dir: Path, threshold: float, results_dir: Path) -> None:
    _check_threshold(threshold)
    try:
        cfg = load_config(config)
        cases = load_cases(cases_dir)
        provider = select_provider(cfg)
    except (ConfigError, CaseError, ScanError) as exc:
        err_console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(ExitCode.ERROR) from exc
    result = run_scan(cfg, cases, provider, RunStore(results_dir), threshold)
    _render_scan(result)
    raise typer.Exit(result.exit_code)


@app.command()
def scan(
    config: ConfigOption = Path("airteam.yaml"),
    cases: CasesOption = Path("attacks"),
    threshold: ThresholdOption = 0.1,
    results_dir: ResultsOption = Path("results"),
) -> None:
    """Run case files against the target: exit 1 on fail_on findings, 3 if inconclusive."""
    _scan(config, cases, threshold, results_dir)


@app.command()
def benchmark() -> None:
    """Run the benchmark suite."""
    _not_yet("benchmark", "M4")


def _load_run(
    store: RunStore, run_id: str
) -> tuple[RunMetadata, tuple[EvidenceRecord, ...], list[Finding]]:
    try:
        return store.load(run_id)
    except StorageError as exc:
        err_console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(ExitCode.ERROR) from exc


@app.command()
def replay(
    run_id: Annotated[str, typer.Argument(help="Run to replay.")],
    evidence: Annotated[
        bool, typer.Option("--evidence", help="Render recorded trials; no network (default).")
    ] = False,
    live: Annotated[
        bool, typer.Option("--live", help="Re-execute against the target and compare.")
    ] = False,
    full: Annotated[bool, typer.Option("--full", help="Show complete evidence payloads.")] = False,
    results_dir: ResultsOption = Path("results"),
) -> None:
    """Replay a recorded run."""
    if evidence and live:
        err_console.print("[red]--evidence and --live are mutually exclusive.[/]")
        raise typer.Exit(ExitCode.ERROR)
    if live:
        _not_yet("replay --live", "M2, after the M1 executor")
    meta, records, findings = _load_run(RunStore(results_dir), run_id)
    render_evidence(console, meta, records, findings, full=full)


@app.command()
def regression(
    run: Annotated[str, typer.Option("--run", help="Run ID whose trials to judge.")],
    threshold: ThresholdOption = 0.1,
    results_dir: ResultsOption = Path("results"),
) -> None:
    """Judge recorded trials: PASS / FAIL / INCONCLUSIVE per attack (exit 0 / 1 / 3)."""
    _check_threshold(threshold)
    meta, records, _ = _load_run(RunStore(results_dir), run)
    try:
        results = evaluate_run(records, threshold)
    except TrialRecordError as exc:
        err_console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(ExitCode.ERROR) from exc
    render_regression(console, meta.run_id, results, threshold)
    raise typer.Exit(exit_code_for_verdicts(r.verdict for r, _ in results.values()))


@app.command()
def report(
    run: Annotated[str, typer.Option("--run", help="Run ID.")],
    fmt: Annotated[
        ReportFormat, typer.Option("--format", "-f", help="Report format.")
    ] = ReportFormat.JSON,
    results_dir: ResultsOption = Path("results"),
) -> None:
    """Render a report for a run."""
    if fmt is ReportFormat.HTML:
        _not_yet("report --format html", "M4")
    try:
        path = write_json_report(RunStore(results_dir), run)
    except StorageError as exc:
        err_console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(ExitCode.ERROR) from exc
    console.print(f"Wrote {path}")


@api_app.command("scan")
def api_scan(config: ConfigOption = Path("airteam.yaml")) -> None:
    """Run API security checks."""
    _not_yet("api scan", "M3")


@ai_app.command("scan")
def ai_scan(
    config: ConfigOption = Path("airteam.yaml"),
    cases: CasesOption = Path("attacks/ai"),
    threshold: ThresholdOption = 0.1,
    results_dir: ResultsOption = Path("results"),
) -> None:
    """Run AI case files (default directory: attacks/ai)."""
    _scan(config, cases, threshold, results_dir)
