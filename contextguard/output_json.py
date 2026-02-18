"""JSON output — deterministic report.json generation."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from contextguard.model import AnalysisResult


def render_json(result: AnalysisResult, out_path: Path) -> None:
    """Write byte-deterministic report.json."""
    from pathlib import Path as _Path

    sorted_result = _sort_for_determinism(result)
    data = sorted_result.model_dump(mode="json")
    _Path(str(out_path)).mkdir(parents=True, exist_ok=True)
    _Path(str(out_path), "report.json").write_text(
        json.dumps(data, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _sort_for_determinism(result: AnalysisResult) -> AnalysisResult:
    sorted_nodes = sorted(result.nodes, key=lambda n: n.id)
    sorted_edges = sorted(result.edges, key=lambda e: (e.from_id, e.to_id, e.type))

    sorted_findings = sorted(
        result.findings,
        key=lambda f: (f.context_severity, f.rule_id, f.node_id),
    )
    for f in sorted_findings:
        f.breakpoints = sorted(f.breakpoints, key=lambda bp: bp.node_id)

    return AnalysisResult(
        nodes=sorted_nodes,
        edges=sorted_edges,
        findings=sorted_findings,
        stats=result.stats,
    )
