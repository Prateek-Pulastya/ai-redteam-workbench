"""AI Red-Team Workbench: security testing for AI applications and their APIs."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("airteam")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
