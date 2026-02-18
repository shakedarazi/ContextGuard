"""Markdown output — report.md generation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from contextguard.model import AnalysisResult, Finding, Severity


def render_markdown(result: AnalysisResult, out_path: Path, gate_passed: bool) -> None:
    """Write report.md to the given directory."""
    from pathlib import Path as _Path

    lines: list[str] = []
    lines.append("# ContextGuard Report\n")

    _executive_summary(lines, result, gate_passed)
    _findings_section(lines, result)
    _attack_paths_section(lines, result)
    _methodology_section(lines)
    _scope_section(lines, result)

    _Path(str(out_path)).mkdir(parents=True, exist_ok=True)
    _Path(str(out_path), "report.md").write_text("\n".join(lines), encoding="utf-8")


def _executive_summary(lines: list[str], result: AnalysisResult, gate_passed: bool) -> None:
    lines.append("## Executive Summary\n")
    total = len(result.findings)
    lines.append(f"**Total findings:** {total}\n")

    for sev in Severity:
        count = sum(1 for f in result.findings if f.context_severity == sev)
        if count > 0:
            lines.append(f"- {sev.value}: {count}")
    lines.append("")

    status = "PASSED" if gate_passed else "FAILED"
    lines.append(f"**Gate status:** {status}\n")


def _findings_section(lines: list[str], result: AnalysisResult) -> None:
    lines.append("## Findings\n")

    if not result.findings:
        lines.append("No findings.\n")
        return

    severity_order = list(Severity)
    sorted_findings = sorted(
        result.findings,
        key=lambda f: severity_order.index(f.context_severity),
    )

    for finding in sorted_findings:
        _render_finding(lines, finding)


def _render_finding(lines: list[str], f: Finding) -> None:
    lines.append(f"### {f.title}\n")

    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Base Severity | {f.base_severity.value} |")
    lines.append(f"| Context Severity | {f.context_severity.value} |")
    lines.append(f"| Override Reason | {f.override_reason} |")
    lines.append("")

    if f.attack_path:
        lines.append(f"**Attack Path:** {' -> '.join(f.attack_path)}\n")

    if f.breakpoints:
        lines.append("**Recommended Breakpoints:**\n")
        for i, bp in enumerate(f.breakpoints, 1):
            lines.append(f"{i}. [{bp.type.value}] {bp.node_id} — {bp.recommendation}")
        lines.append("")

    if f.context_severity == Severity.CRITICAL and f.attack_path:
        lines.append("> **What you learned**")
        hops = f.shortest_path_length or len(f.attack_path) - 1
        lines.append(
            f"> - This finding is critical because it sits on a {hops}-hop "
            f"path from the internet to a crown jewel."
        )
        if f.breakpoints:
            bp = f.breakpoints[0]
            lines.append(
                f"> - Applying controls at {bp.node_id} would break this attack path."
            )
        lines.append("")


def _attack_paths_section(lines: list[str], result: AnalysisResult) -> None:
    lines.append("## Attack Paths\n")
    paths_seen: set[str] = set()
    for f in result.findings:
        if f.attack_path:
            path_str = " -> ".join(f.attack_path)
            if path_str not in paths_seen:
                paths_seen.add(path_str)
                hops = f.shortest_path_length or len(f.attack_path) - 1
                lines.append(f"- ({hops} hops) {path_str}")
    if not paths_seen:
        lines.append("No attack paths identified.\n")
    else:
        lines.append("")


def _methodology_section(lines: list[str]) -> None:
    lines.append("## Methodology\n")
    lines.append(
        "ContextGuard builds a reachability graph from the Terraform plan. "
        "Each finding receives a base severity from static rules, then a contextual "
        "override based on whether the finding's node is reachable from the internet "
        "and whether an attack path exists to a crown jewel. Shorter paths to crown "
        "jewels produce higher severity. Path breakpoints identify where to sever "
        "the attack path.\n"
    )


def _scope_section(lines: list[str], result: AnalysisResult) -> None:
    lines.append("## Scope\n")
    lines.append(f"- Supported resources analyzed: {result.stats.supported}")
    lines.append(f"- Unsupported resources skipped: {result.stats.skipped}")
    lines.append(f"- Total resources in plan: {result.stats.total}")
    lines.append("")
