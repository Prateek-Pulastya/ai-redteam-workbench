"""The README control-mapping table must list every shipped case, so it cannot drift."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_every_case_has_a_control_mapping_row() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    case_ids = sorted(p.stem for p in (ROOT / "attacks").rglob("*.yaml"))
    missing = [c for c in case_ids if f"| `{c}` |" not in readme]
    assert not missing, f"add these cases to the README control-mapping table: {missing}"
