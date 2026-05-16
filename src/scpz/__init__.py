"""scpz — Intelligently optimize AWS SCP JSONs."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("scpz")
except PackageNotFoundError:
    __version__ = "unknown"
