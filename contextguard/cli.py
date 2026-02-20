"""CLI entry point and pipeline orchestration."""

from __future__ import annotations

import datetime
from collections import defaultdict
from pathlib import Path
from typing import Annotated

import typer

from contextguard.adapters.adapter_protocol import get_adapter
from contextguard.adapters.terraform_aws import ParseError
from contextguard.core.findings import extract_findings
from contextguard.core.graph import bfs, build_graph
from contextguard.core.model import (
    INTERNET_NODE_ID,
    AnalysisResult,
    AttackPath,
    Severity,
)
from contextguard.core.scoring import score_findings
from contextguard.outputs.output_console import render_console
from contextguard.outputs.output_json import render_json
from contextguard.outputs.output_markdown import render_markdown
from contextguard.outputs.output_run_metadata import write_run_metadata
from contextguard.policy.config import load_config

app = typer.Typer(no_args_is_help=True)


@app.callback(invoke_without_command=True)
def _callback() -> None:
    """ContextGuard — IaC Attack Path Prioritizer."""


def _parse_fail_on(value: str | None) -> list[Severity] | None:
    if value is None:
        return None
    severities: list[Severity] = []
    for token in value.split(","):
        token = token.strip().upper()
        if not token:
            continue
        try:
            severities.append(Severity(token))
        except ValueError:
            valid = ", ".join(s.value for s in Severity)
            typer.echo(
                f"Error: invalid severity '{token}'. Valid values: {valid}.",
                err=True,
            )
            raise SystemExit(2)  # noqa: B904
    return severities


@app.command()
def analyze(
    plan: Annotated[Path, typer.Option("--plan", help="Path to Terraform plan JSON file")],
    config_path: Annotated[
        Path | None, typer.Option("--config", help="Path to contextguard.yml")
    ] = None,
    out: Annotated[Path, typer.Option("--out", help="Output directory for reports")] = Path("."),
    fail_on: Annotated[
        str | None, typer.Option("--fail-on", help="Comma-separated severities")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", help="Enable verbose logging")] = False,
    no_mermaid: Annotated[
        bool, typer.Option("--no-mermaid", help="Suppress Mermaid diagram in report.md")
    ] = False,
) -> None:
    """Analyze a Terraform plan for attack paths."""
    if verbose:
        import logging

        logging.basicConfig(level=logging.DEBUG)

    try:
        adapter = get_adapter("terraform")
        adapter_output = adapter.parse(plan)
    except ParseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise SystemExit(2)  # noqa: B904

    cfg = load_config(config_path)

    fail_on_severities = _parse_fail_on(fail_on)
    if fail_on_severities is not None:
        cfg.gating.fail_on = fail_on_severities

    graph = build_graph(adapter_output.nodes, adapter_output.edges)
    bfs_result = bfs(graph, INTERNET_NODE_ID)
    raw_findings = extract_findings(adapter_output.nodes, graph)
    scored = score_findings(raw_findings, bfs_result, graph, cfg)

    # --- Post-scoring enrichment (deterministic) ---

    # 1. Crown jewel IDs
    crown_jewel_ids = sorted(
        n.id for n in adapter_output.nodes if n.flags.crown_jewel
    )

    # 2. Deduplicated attack paths, sorted by hops then lexicographic path
    path_to_finding_ids: dict[str, list[str]] = defaultdict(list)
    for f in scored:
        if f.attack_path:
            key = "\x00".join(f.attack_path)
            path_to_finding_ids[key].append(f.id)

    attack_paths = sorted(
        [
            AttackPath(
                path=key.split("\x00"),
                hops=len(key.split("\x00")) - 1,
                finding_ids=sorted(fids),
            )
            for key, fids in path_to_finding_ids.items()
        ],
        key=lambda ap: (ap.hops, ap.path),
    )

    # 3. paths_broken: count how many attack paths each breakpoint intermediate appears on
    bp_path_count: dict[str, int] = defaultdict(int)
    for ap in attack_paths:
        for node_id in ap.path[1:-1]:
            bp_path_count[node_id] += 1

    for f in scored:
        for bp in f.breakpoints:
            bp.paths_broken = bp_path_count.get(bp.node_id, 1)

    result = AnalysisResult(
        nodes=adapter_output.nodes,
        edges=adapter_output.edges,
        findings=scored,
        stats=adapter_output.stats,
        crown_jewel_ids=crown_jewel_ids,
        attack_paths=attack_paths,
    )

    gate_passed = not any(
        f.context_severity in cfg.gating.fail_on for f in result.findings
    )

    run_meta: dict[str, str] = {
        "timestamp_utc": (
            datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
        ),
        "plan_path": str(plan.resolve()),
        "output_dir": str(out.resolve()),
    }

    render_console(result, gate_passed)

    try:
        md_path = render_markdown(
            result, out, gate_passed, run_meta, include_mermaid=not no_mermaid
        )
        typer.echo(f"Wrote report (MD): {md_path.resolve()}")
    except Exception as e:
        typer.echo(f"Error writing markdown: {e}", err=True)
        raise

    try:
        json_path = render_json(result, out)
        typer.echo(f"Wrote report (JSON): {json_path.resolve()}")
    except Exception as e:
        typer.echo(f"Error writing JSON: {e}", err=True)
        raise

    try:
        meta_path = write_run_metadata(run_meta, out)
        typer.echo(f"Wrote run metadata (JSON): {meta_path.resolve()}")
    except Exception as e:
        typer.echo(f"Error writing run metadata: {e}", err=True)
        raise

    if not gate_passed:
        raise SystemExit(1)
