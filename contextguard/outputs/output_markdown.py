"""Markdown output — SaaS-grade report.md generation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from contextguard.core.model import AnalysisResult, AttackPath, Finding, Severity


def render_markdown(
    result: AnalysisResult,
    out_path: Path,
    gate_passed: bool,
    run_meta: dict[str, str],
    include_mermaid: bool = True,
) -> Path:
    """Write report.md to *out_path* and return the written path."""
    from pathlib import Path as _Path

    lines: list[str] = []
    lines.append("# ContextGuard Report\n")

    _run_metadata_section(lines, run_meta)
    _executive_summary(lines, result, gate_passed)
    _exposure_section(lines, result, include_mermaid)
    _consolidated_breakpoints(lines, result)
    _findings_section(lines, result)
    _methodology_section(lines)
    _scope_section(lines, result)

    _Path(str(out_path)).mkdir(parents=True, exist_ok=True)
    out_file = _Path(str(out_path), "report.md")
    out_file.write_text("\n".join(lines), encoding="utf-8")
    return out_file


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _run_metadata_section(lines: list[str], run_meta: dict[str, str]) -> None:
    lines.append("## Run Metadata\n")
    lines.append(f"- Timestamp (UTC): {run_meta.get('timestamp_utc', 'unknown')}")
    lines.append(f"- Plan path: `{run_meta.get('plan_path', 'unknown')}`")
    lines.append(f"- Output directory: `{run_meta.get('output_dir', 'unknown')}`")
    lines.append("")


def _executive_summary(lines: list[str], result: AnalysisResult, gate_passed: bool) -> None:
    lines.append("## Executive Risk Summary\n")

    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in Severity:
        count = sum(1 for f in result.findings if f.context_severity == sev)
        if count > 0:
            lines.append(f"| {sev.value} | {count} |")
    lines.append("")

    status = "PASSED ✓" if gate_passed else "FAILED ✗"
    lines.append(f"**Gate:** {status}\n")

    if result.crown_jewel_ids:
        if result.attack_paths:
            min_hops = min(ap.hops for ap in result.attack_paths)
            lines.append(
                f"**Crown jewel reachable:** Yes — shortest path is "
                f"{min_hops} hop(s) from internet\n"
            )
        else:
            lines.append("**Crown jewel reachable:** No internet-to-crown-jewel path found\n")
    else:
        lines.append("**Crown jewels:** None identified in this plan\n")


def _exposure_section(
    lines: list[str], result: AnalysisResult, include_mermaid: bool
) -> None:
    lines.append("## Internet-to-Crown-Jewel Exposure\n")

    if not result.attack_paths:
        lines.append("No internet-reachable path to any crown jewel was found.\n")
        return

    crown_jewel_set = set(result.crown_jewel_ids)

    for i, ap in enumerate(result.attack_paths):
        label = "Primary path" if i == 0 else f"Path {i + 1}"
        path_str = " → ".join(ap.path)
        lines.append(f"**{label}** ({ap.hops} hops): {path_str}\n")

        if include_mermaid and i == 0:
            lines.extend(_mermaid_block(ap, crown_jewel_set))
            lines.append("")

        finding_titles = []
        for f in result.findings:
            if f.id in ap.finding_ids:
                finding_titles.append(f"[{f.context_severity.value}] {f.title}")
        if finding_titles:
            lines.append("Findings on this path: " + ", ".join(finding_titles) + "\n")


def _mermaid_block(ap: AttackPath, crown_jewel_ids: set[str]) -> list[str]:
    lines = ["```mermaid", "graph LR"]
    path = ap.path
    for i in range(len(path) - 1):
        src = path[i]
        dst = path[i + 1]
        src_id = _mermaid_node_id(src)
        dst_id = _mermaid_node_id(dst)

        src_shape = '["🌐 Internet"]' if src == "__internet__" else f'["{src}"]'
        dst_shape = f'[("{dst} 👑")]' if dst in crown_jewel_ids else f'["{dst}"]'

        if i == 0:
            lines.append(f"    {src_id}{src_shape} --> {dst_id}{dst_shape}")
        else:
            lines.append(f"    {src_id} --> {dst_id}{dst_shape}")

    lines.append("```")
    return lines


def _mermaid_node_id(node_id: str) -> str:
    return node_id.replace(".", "_").replace("-", "_").replace("/", "_").replace("__", "")


def _consolidated_breakpoints(lines: list[str], result: AnalysisResult) -> None:
    seen: dict[str, list[str]] = {}
    for f in result.findings:
        for bp in f.breakpoints:
            if bp.node_id not in seen:
                seen[bp.node_id] = []

    if not seen:
        return

    all_bps = {
        bp.node_id: bp
        for f in result.findings
        for bp in f.breakpoints
    }
    ranked = sorted(all_bps.values(), key=lambda bp: (-bp.paths_broken, bp.node_id))

    lines.append("## Consolidated Breakpoints\n")
    lines.append("| Node | Category | Type | Paths Broken | Recommendation |")
    lines.append("|------|----------|------|:------------:|----------------|")
    for bp in ranked:
        rec = bp.recommendation.replace("|", "\\|")
        lines.append(
            f"| {bp.node_id} | {bp.category.value} | {bp.type.value} "
            f"| {bp.paths_broken} | {rec} |"
        )
    lines.append("")


def _findings_section(lines: list[str], result: AnalysisResult) -> None:
    severity_order = list(Severity)

    actionable = [
        f for f in result.findings if f.context_severity != Severity.NOISE
    ]
    noise = [
        f for f in result.findings if f.context_severity == Severity.NOISE
    ]

    actionable_sorted = sorted(
        actionable,
        key=lambda f: severity_order.index(f.context_severity),
    )

    lines.append("## Actionable Findings\n")
    if not actionable_sorted:
        lines.append("No actionable findings.\n")
    else:
        # "What you learned" once globally for the primary attack path
        primary_criticals = [
            f for f in actionable_sorted
            if f.context_severity == Severity.CRITICAL and f.attack_path
        ]
        if primary_criticals and result.attack_paths:
            primary_ap = result.attack_paths[0]
            hops = primary_ap.hops
            lines.append("> **What you learned**")
            lines.append(
                f"> - The primary attack path reaches a crown jewel in **{hops} hop(s)** "
                f"from the internet."
            )
            if result.crown_jewel_ids:
                lines.append(
                    f"> - Crown jewel(s): {', '.join(f'`{cj}`' for cj in result.crown_jewel_ids)}"
                )
            lines.append("")

        for f in actionable_sorted:
            _render_finding(lines, f)

    if noise:
        lines.append("## Non-Exploitable / Noise\n")
        lines.append("| Finding | Node | Override Reason |")
        lines.append("|---------|------|-----------------|")
        for f in noise:
            lines.append(f"| {f.title} | `{f.node_id}` | {f.override_reason} |")
        lines.append("")


def _render_finding(lines: list[str], f: Finding) -> None:
    lines.append(f"### {f.title}\n")

    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Node | `{f.node_id}` |")
    lines.append(f"| Base Severity | {f.base_severity.value} |")
    lines.append(f"| Context Severity | {f.context_severity.value} |")
    lines.append(f"| Override Reason | {f.override_reason} |")
    lines.append("")

    if f.breakpoints:
        lines.append("**Breakpoints:**\n")
        for i, bp in enumerate(f.breakpoints, 1):
            lines.append(
                f"{i}. [{bp.type.value}] `{bp.node_id}` "
                f"(breaks {bp.paths_broken} path(s)) — {bp.recommendation}"
            )
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
