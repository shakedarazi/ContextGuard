"""Console output — TTY summary with Rich tables."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contextguard.core.model import AnalysisResult

from contextguard.core.model import Severity


def render_console(result: AnalysisResult, gate_passed: bool) -> None:
    """Print a TTY-friendly summary to stdout."""
    try:
        import rich  # noqa: F401

        _render_rich(result, gate_passed)
    except ImportError:
        _render_plain(result, gate_passed)


def _render_rich(result: AnalysisResult, gate_passed: bool) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()

    table = Table(title="Severity Distribution")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in Severity:
        count = sum(1 for f in result.findings if f.context_severity == sev)
        if count > 0:
            table.add_row(sev.value, str(count))
    console.print(table)

    if result.attack_paths:
        console.print("\n[bold]Top Attack Paths:[/bold]")
        for ap in result.attack_paths[:3]:
            path_str = " -> ".join(ap.path)
            console.print(f"  ({ap.hops} hops) {path_str}")

    # Collect unique breakpoints, deduplicated by node_id, ranked by paths_broken desc
    seen_bp_ids: set[str] = set()
    all_bps = []
    for f in result.findings:
        for bp in f.breakpoints:
            if bp.node_id not in seen_bp_ids:
                seen_bp_ids.add(bp.node_id)
                all_bps.append(bp)
    all_bps.sort(key=lambda bp: -bp.paths_broken)
    if all_bps:
        console.print("\n[bold]Top Breakpoints:[/bold]")
        for bp in all_bps[:5]:
            console.print(
                f"  [{bp.type.value}] {bp.node_id} "
                f"(breaks {bp.paths_broken} path(s)) — {bp.recommendation}"
            )

    console.print(f"\nResources: {result.stats.supported} analyzed, {result.stats.skipped} skipped")
    status = "[green]PASSED[/green]" if gate_passed else "[red]FAILED[/red]"
    console.print(f"Gate: {status}")


def _render_plain(result: AnalysisResult, gate_passed: bool) -> None:
    print("--- Severity Distribution ---")
    for sev in Severity:
        count = sum(1 for f in result.findings if f.context_severity == sev)
        if count > 0:
            print(f"  {sev.value}: {count}")

    print(f"\nResources: {result.stats.supported} analyzed, {result.stats.skipped} skipped")
    status = "PASSED" if gate_passed else "FAILED"
    print(f"Gate: {status}")
    sys.stdout.flush()
