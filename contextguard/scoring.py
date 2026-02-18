"""Severity scoring — two-layer contextual override and breakpoint recommendation."""

from __future__ import annotations

# ARCHITECTURAL BOUNDARY: This module must remain provider-agnostic.
# Do not introduce provider-specific strings or assumptions about providers.
# Depend only on canonical model types and graph relationships.
from contextguard.graph import BfsResult, Graph, shortest_path
from contextguard.model import (
    Breakpoint,
    BreakpointType,
    CanonicalAction,
    ContextGuardConfig,
    Finding,
    NodeCategory,
    Severity,
)


def _has_crown_jewel_impact(node_actions: set[CanonicalAction]) -> bool:
    """Check if node has actions that impact crown jewels."""
    impact_actions = {
        CanonicalAction.DATABASE_ADMIN,
        CanonicalAction.SECRET_READ,
        CanonicalAction.STORAGE_READ,
        CanonicalAction.PRIVILEGE_ESCALATION,
    }
    return bool(node_actions & impact_actions)

_BREAKPOINT_TEMPLATES: dict[NodeCategory, tuple[BreakpointType, str]] = {
    NodeCategory.LOAD_BALANCER: (
        BreakpointType.NETWORK,
        "Add WAF or restrict listener rules on {node_id} to limit inbound traffic",
    ),
    NodeCategory.FIREWALL: (
        BreakpointType.NETWORK,
        "Restrict ingress on {node_id} to known CIDR ranges, remove 0.0.0.0/0 rules",
    ),
    NodeCategory.COMPUTE: (
        BreakpointType.NETWORK,
        "Remove public IP from {node_id} or place behind a private subnet with NAT; "
        "ensure launch templates do not assign public IPs",
    ),
    NodeCategory.IDENTITY: (
        BreakpointType.IDENTITY,
        "Remove wildcard actions and scope down trust policies on {node_id}; "
        "apply least-privilege permissions",
    ),
    NodeCategory.DATABASE: (
        BreakpointType.DATA,
        "Disable public accessibility on {node_id}, move to private subnet",
    ),
}


def score_findings(
    findings: list[Finding],
    bfs_result: BfsResult,
    graph: Graph,
    config: ContextGuardConfig,
) -> list[Finding]:
    """Apply contextual severity override and breakpoint recommendations."""
    crown_jewel_ids = _get_crown_jewel_ids(graph)
    scored: list[Finding] = []

    for finding in findings:
        f = finding.model_copy()
        _apply_severity_override(f, bfs_result, graph, crown_jewel_ids)
        _apply_breakpoints(f, graph)
        scored.append(f)

    return scored


def _get_crown_jewel_ids(graph: Graph) -> set[str]:
    return {
        node_id
        for node_id, node in graph.nodes.items()
        if node.flags.crown_jewel
    }


def _apply_severity_override(
    finding: Finding,
    bfs_result: BfsResult,
    graph: Graph,
    crown_jewel_ids: set[str],
) -> None:
    node_id = finding.node_id
    is_reachable = node_id in bfs_result.reachable

    if not is_reachable:
        finding.context_severity = Severity.NOISE
        finding.override_reason = "Not reachable from internet"
        return

    best_path: list[str] = []
    best_hops = float("inf")
    for cj_id in crown_jewel_ids:
        result = shortest_path(bfs_result.parents, cj_id)
        if result.path and result.hops < best_hops:
            best_hops = result.hops
            best_path = result.path

    if finding.category.value == "iam" and best_path and _iam_impacts_crown_jewel(finding, graph):
        finding.context_severity = Severity.CRITICAL
        finding.override_reason = (
            f"IAM policy with crown jewel impact actions, reachable path ({int(best_hops)} hops)"
        )
        finding.attack_path = best_path
        finding.shortest_path_length = int(best_hops)
        return

    if not best_path:
        sev = finding.base_severity
        if _severity_rank(sev) < _severity_rank(Severity.HIGH):
            finding.context_severity = sev
        else:
            finding.context_severity = Severity.HIGH
        finding.override_reason = "Reachable from internet but no path to crown jewel"
        return

    hops = int(best_hops)
    finding.attack_path = best_path
    finding.shortest_path_length = hops
    if hops <= 3:
        finding.context_severity = Severity.CRITICAL
        finding.override_reason = f"Reachable crown jewel within {hops} hops"
    elif hops <= 5:
        finding.context_severity = Severity.HIGH
        finding.override_reason = f"Reachable crown jewel within {hops} hops"
    else:
        finding.context_severity = Severity.MEDIUM
        finding.override_reason = f"Reachable crown jewel at {hops} hops (distant)"


def _iam_impacts_crown_jewel(finding: Finding, graph: Graph) -> bool:
    node = graph.nodes.get(finding.node_id)
    if node is None:
        return False
    return _has_crown_jewel_impact(node.canonical_actions)


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.NOISE: 4,
    }.get(severity, 4)


def _apply_breakpoints(finding: Finding, graph: Graph) -> None:
    if finding.context_severity not in (Severity.CRITICAL, Severity.HIGH):
        return
    if len(finding.attack_path) < 3:
        return

    intermediates = finding.attack_path[1:-1]
    if not intermediates:
        return

    breakpoints: list[Breakpoint] = []

    first = intermediates[0]
    bp = _make_breakpoint(first, graph)
    if bp is not None:
        breakpoints.append(bp)

    if len(finding.attack_path) - 1 >= 4 and len(intermediates) >= 2:
        last = intermediates[-1]
        if last != first:
            bp2 = _make_breakpoint(last, graph)
            if bp2 is not None:
                breakpoints.append(bp2)

    finding.breakpoints = breakpoints


def _make_breakpoint(node_id: str, graph: Graph) -> Breakpoint | None:
    node = graph.nodes.get(node_id)
    if node is None:
        return None
    template_entry = _BREAKPOINT_TEMPLATES.get(node.category)
    if template_entry is None:
        return None
    bp_type, template = template_entry
    return Breakpoint(
        node_id=node_id,
        category=node.category,
        type=bp_type,
        recommendation=template.format(node_id=node_id),
    )
