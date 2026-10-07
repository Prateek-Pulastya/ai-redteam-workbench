import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from airteam.cli.main import app
from airteam.core.exit_codes import ExitCode
from airteam.core.storage import FINDINGS, RunStore

FIXTURES = Path(__file__).parent / "fixtures" / "cases"
runner = CliRunner()


def _config(tmp_path: Path, variant: str = "vulnerable", provider: str = "mock") -> Path:
    assert runner.invoke(app, ["init", str(tmp_path / "airteam.yaml")]).exit_code == 0
    path = tmp_path / "airteam.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["target"]["variant"] = variant
    data["ai"]["provider"] = provider
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _cases(tmp_path: Path, **attack_changes: Any) -> Path:
    data = yaml.safe_load((FIXTURES / "smoke.yaml").read_text(encoding="utf-8"))
    data["attack"].update(attack_changes.pop("attack", {}))
    data["finding"].update(attack_changes)
    root = tmp_path / "cases"
    root.mkdir(exist_ok=True)
    (root / "smoke.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return root


def _scan(tmp_path: Path, config: Path, cases: Path, *extra: str) -> Any:
    return runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(config),
            "--cases",
            str(cases),
            "--results-dir",
            str(tmp_path / "results"),
            *extra,
        ],
    )


def _only_run(tmp_path: Path) -> tuple[RunStore, str]:
    store = RunStore(tmp_path / "results")
    (run_dir,) = (tmp_path / "results").iterdir()
    return store, run_dir.name


def test_vulnerable_info_finding_exits_0_but_regression_fails(tmp_path: Path) -> None:
    result = _scan(tmp_path, _config(tmp_path), _cases(tmp_path))
    assert result.exit_code == ExitCode.OK, result.output
    for expected in ("FAIL", "30/30", "F-001 info"):
        assert expected in result.output

    store, run_id = _only_run(tmp_path)
    _, records, findings = store.load(run_id)
    (finding,) = findings
    assert finding.confidence.value == "confirmed"
    assert finding.reproducibility.hits == 30
    assert len(finding.evidence_refs) == 30
    assert all(records[int(ref)].kind == "trial" for ref in finding.evidence_refs)

    gate = runner.invoke(app, ["regression", "--run", run_id, "--results-dir", str(store.root)])
    assert gate.exit_code == ExitCode.POLICY_VIOLATION


def test_fail_on_severity_exits_1(tmp_path: Path) -> None:
    result = _scan(tmp_path, _config(tmp_path), _cases(tmp_path, severity="high"))
    assert result.exit_code == ExitCode.POLICY_VIOLATION, result.output


def test_fixed_variant_passes(tmp_path: Path) -> None:
    result = _scan(tmp_path, _config(tmp_path, variant="fixed"), _cases(tmp_path, severity="high"))
    assert result.exit_code == ExitCode.OK, result.output
    assert "PASS" in result.output
    store, run_id = _only_run(tmp_path)
    assert json.loads((store.run_dir(run_id) / FINDINGS).read_text(encoding="utf-8")) == []


def test_too_few_trials_is_inconclusive(tmp_path: Path) -> None:
    cases = _cases(tmp_path, attack={"execution": {"trials": 10, "seed": 1}})
    result = _scan(tmp_path, _config(tmp_path, variant="fixed"), cases)
    assert result.exit_code == ExitCode.INCONCLUSIVE, result.output


def test_k_above_trials_is_a_load_error(tmp_path: Path) -> None:
    cases = _cases(tmp_path, attack={"execution": {"trials": 30, "success_rule": "k_of_n(31)"}})
    result = _scan(tmp_path, _config(tmp_path), cases)
    assert result.exit_code == ExitCode.ERROR  # k > trials is a load error


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ("provider", "not implemented yet"),
        ("cases", "does not exist"),
        ("threshold", "--threshold"),
    ],
)
def test_scan_errors_exit_2(tmp_path: Path, setup: str, message: str) -> None:
    config = _config(tmp_path, provider="openai_compatible" if setup == "provider" else "mock")
    cases = tmp_path / "missing" if setup == "cases" else _cases(tmp_path)
    extra = ["--threshold", "0"] if setup == "threshold" else []
    result = _scan(tmp_path, config, cases, *extra)
    assert result.exit_code == ExitCode.ERROR
    assert message in result.output
    assert not (tmp_path / "results").exists()  # nothing ran, nothing stored


def test_ai_scan_runs_the_same_pipeline(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "ai",
            "scan",
            "--config",
            str(_config(tmp_path, variant="fixed")),
            "--cases",
            str(_cases(tmp_path)),
            "--results-dir",
            str(tmp_path / "results"),
        ],
    )
    assert result.exit_code == ExitCode.OK, result.output
