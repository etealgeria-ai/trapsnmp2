"""Where trapsnmp keeps its settings and certificates."""

from __future__ import annotations

import os
from pathlib import Path

_LEGACY_DATA = Path("/workspace/data")


def _data_dir() -> Path:
    """TRAPSNMP_DATA if set, the old /workspace/data if it already exists, else ./data."""
    configured = os.environ.get("TRAPSNMP_DATA", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    if _LEGACY_DATA.is_dir():
        return _LEGACY_DATA
    return (Path.cwd() / "data").resolve()


DATA_DIR = _data_dir()
