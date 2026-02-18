"""CLI entry point and pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from contextguard.config import load_config
from contextguard.findings import extract_findings
from contextguard.graph import bfs, build_graph
from contextguard.model import (
    INTERNET_NODE_ID,
    AnalysisResult,
    Severity,
)
from contextguard.output_console import render_console
from contextguard.output_json import render_json
from contextguard.output_markdown import render_markdown
from contextguard.scoring import score_findings
from contextguard.terraform_adapter import ParseError, parse_plan

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
) -> None:
    """Analyze a Terraform plan for attack paths."""
    if verbose:
        import logging

        logging.basicConfig(level=logging.DEBUG)

    try:
        adapter_output = parse_plan(plan)
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

    result = AnalysisResult(
        nodes=adapter_output.nodes,
        edges=adapter_output.edges,
        findings=scored,
        stats=adapter_output.stats,
    )

    gate_passed = not any(
        f.context_severity in cfg.gating.fail_on for f in result.findings
    )

    render_console(result, gate_passed)
    try:
        md_path = render_markdown(result, out, gate_passed, plan)
        typer.echo(f"Wrote report (MD): {md_path}")
    except Exception as e:
        typer.echo(f"Error writing markdown: {e}", err=True)
        raise

    try:
        json_path = render_json(result, out, plan)
        typer.echo(f"Wrote report (JSON): {json_path}")
    except Exception as e:
        typer.echo(f"Error writing JSON: {e}", err=True)
        raise

    if not gate_passed:
        raise SystemExit(1)
