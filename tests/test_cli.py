from pathlib import Path

import pytest
from typer.testing import CliRunner

from airteam import __version__
from airteam.cli.main import app
from airteam.core.exit_codes import ExitCode
from airteam.core.runs import RunMetadata
from airteam.core.storage import EVIDENCE, RunStore
from airteam.reports.json import REPORT

runner = CliRunner()


def test_help_lists_core_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("init", "targets", "scan", "api", "ai", "benchmark", "replay", "report"):
        assert command in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_init_then_targets(tmp_path: Path) -> None:
    cfg = tmp_path / "airteam.yaml"
    assert runner.invoke(app, ["init", str(cfg)]).exit_code == 0
    assert cfg.exists()

    result = runner.invoke(app, ["targets", "--config", str(cfg)])
    assert result.exit_code == 0, result.output
    assert "playground" in result.output
    assert "config hash" in result.output


def test_init_refuses_to_overwrite(tmp_path: Path) -> None:
    cfg = tmp_path / "airteam.yaml"
    cfg.write_text("keep me", encoding="utf-8")
    result = runner.invoke(app, ["init", str(cfg)])
    assert result.exit_code == ExitCode.ERROR
    assert cfg.read_text(encoding="utf-8") == "keep me"


def test_targets_with_invalid_config_exits_2(tmp_path: Path) -> None:
    cfg = tmp_path / "airteam.yaml"
    cfg.write_text("project: {name: x}\n", encoding="utf-8")
    result = runner.invoke(app, ["targets", "--config", str(cfg)])
    assert result.exit_code == ExitCode.ERROR


def _results(store: RunStore) -> list[str]:
    return ["--results-dir", str(store.root)]


def test_replay_evidence_renders_stored_run(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    result = runner.invoke(app, ["replay", meta.run_id, "--evidence", *_results(store)])
    assert result.exit_code == ExitCode.OK, result.output
    for expected in (meta.run_id, "verified", "2 records", "F-001", "7/10", "Root: BOLA"):
        assert expected in result.output
    # Payload text is escaped, not interpreted as Rich markup.
    assert "[bold]x[/bold]" in result.output


def test_replay_defaults_to_evidence(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    result = runner.invoke(app, ["replay", meta.run_id, *_results(store)])
    assert result.exit_code == ExitCode.OK
    assert "no network" in result.output


def test_replay_tampered_run_exits_2(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    evidence = store.run_dir(meta.run_id) / EVIDENCE
    evidence.write_text(evidence.read_text().replace("200", "403"), encoding="utf-8")
    result = runner.invoke(app, ["replay", meta.run_id, *_results(store)])
    assert result.exit_code == ExitCode.ERROR


@pytest.mark.parametrize("args", [["--live"], ["--evidence", "--live"]])
def test_replay_live_not_available_yet(
    stored_run: tuple[RunStore, RunMetadata], args: list[str]
) -> None:
    store, meta = stored_run
    result = runner.invoke(app, ["replay", meta.run_id, *args, *_results(store)])
    assert result.exit_code == ExitCode.ERROR


def test_replay_missing_run_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["replay", "run-x", "--results-dir", str(tmp_path)])
    assert result.exit_code == ExitCode.ERROR


def test_report_writes_json(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    result = runner.invoke(app, ["report", "--run", meta.run_id, *_results(store)])
    assert result.exit_code == ExitCode.OK, result.output
    assert (store.run_dir(meta.run_id) / REPORT).exists()


@pytest.mark.parametrize(
    "args",
    [
        ["report", "--run", "run-x"],
        ["report", "--run", "run-x", "--format", "html"],
    ],
)
def test_report_errors_exit_2(tmp_path: Path, args: list[str]) -> None:
    result = runner.invoke(app, [*args, "--results-dir", str(tmp_path)])
    assert result.exit_code == ExitCode.ERROR


@pytest.mark.parametrize(
    "args",
    [
        ["scan"],
        ["benchmark"],
        ["api", "scan"],
        ["ai", "scan"],
    ],
)
def test_unimplemented_commands_exit_with_error(args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == ExitCode.ERROR
