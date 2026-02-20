"""Run-metadata sidecar — writes run-metadata.json alongside reports."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def write_run_metadata(meta: dict[str, str], out_path: Path) -> Path:
    """Write run-metadata.json to *out_path* and return the written path."""
    from pathlib import Path as _Path

    _Path(str(out_path)).mkdir(parents=True, exist_ok=True)
    out_file = _Path(str(out_path), "run-metadata.json")
    out_file.write_text(
        json.dumps(meta, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return out_file
