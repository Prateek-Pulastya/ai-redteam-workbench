from pathlib import Path

import pytest
from typer.testing import CliRunner

from airteam import __version__
from airteam.cli.main import app
from airteam.core.exit_codes import ExitCode

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


@pytest.mark.parametrize(
    "args",
    [
        ["scan"],
        ["benchmark"],
        ["replay", "run-x"],
        ["report", "--run", "x"],
        ["api", "scan"],
        ["ai", "scan"],
    ],
)
def test_unimplemented_commands_exit_with_error(args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == ExitCode.ERROR
