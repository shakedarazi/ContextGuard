"""Finding extraction — security rules and finding generation."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contextguard.graph import Graph

# ARCHITECTURAL BOUNDARY: This module must remain provider-agnostic.
# Do not introduce provider-specific strings (e.g., "iam:PassRole", "rds:*")
# or source-specific logic here. Use canonical types from model.py only.

from contextguard.model import (
    CanonicalAction,
    Finding,
    FindingCategory,
    Node,
    NodeCategory,
    Severity,
)


def extract_findings(nodes: list[Node], graph: Graph) -> list[Finding]:
    """Run all rules against nodes and return findings with base severity set."""
    findings: list[Finding] = []
    for node in nodes:
        for rule in _RULES:
            finding = rule(node, graph)
            if finding is not None:
                findings.append(finding)
    return findings


def _make_id(rule_id: str, node_id: str) -> str:
    raw = f"{rule_id}:{node_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _rule_sg_open_to_world(node: Node, graph: Graph) -> Finding | None:
    if node.category != NodeCategory.FIREWALL:
        return None
    if not (node.meta and node.meta.get("open_to_world") is True):
        return None
    return Finding(
        id=_make_id("sg-open-to-world", node.id),
        node_id=node.id,
        rule_id="sg-open-to-world",
        category=FindingCategory.NETWORK,
        title="Security group open to 0.0.0.0/0",
        description=f"Security group {node.id} allows ingress from 0.0.0.0/0.",
        base_severity=Severity.HIGH,
    )


def _rule_public_lb(node: Node, graph: Graph) -> Finding | None:
    if node.category != NodeCategory.LOAD_BALANCER:
        return None
    if not node.flags.internet_facing:
        return None
    return Finding(
        id=_make_id("public-lb", node.id),
        node_id=node.id,
        rule_id="public-lb",
        category=FindingCategory.NETWORK,
        title="Public load balancer",
        description=f"Load balancer {node.id} is internet-facing.",
        base_severity=Severity.MEDIUM,
    )


def _rule_wildcard_iam(node: Node, graph: Graph) -> Finding | None:
    if node.category != NodeCategory.IDENTITY:
        return None
    actions = _get_actions(node)
    if "*" not in actions:
        return None
    return Finding(
        id=_make_id("wildcard-iam", node.id),
        node_id=node.id,
        rule_id="wildcard-iam",
        category=FindingCategory.IAM,
        title="Wildcard IAM action",
        description=f"IAM policy {node.id} grants Action: * on Resource: *.",
        base_severity=Severity.HIGH,
    )


def _rule_pass_role(node: Node, graph: Graph) -> Finding | None:
    if node.category != NodeCategory.IDENTITY:
        return None
    has_pass_role = CanonicalAction.PRIVILEGE_ESCALATION in node.canonical_actions
    if not has_pass_role:
        return None
    if "*" in _get_actions(node):
        return None
    return Finding(
        id=_make_id("pass-role", node.id),
        node_id=node.id,
        rule_id="pass-role",
        category=FindingCategory.IAM,
        title="IAM PassRole permission",
        description=f"IAM policy {node.id} grants privilege escalation permissions.",
        base_severity=Severity.HIGH,
    )


def _rule_db_publicly_accessible(node: Node, graph: Graph) -> Finding | None:
    if node.category != NodeCategory.DATABASE:
        return None
    if not (node.meta and node.meta.get("publicly_accessible") is True):
        return None
    return Finding(
        id=_make_id("db-public", node.id),
        node_id=node.id,
        rule_id="db-public",
        category=FindingCategory.DATA,
        title="Database publicly accessible",
        description=f"Database {node.id} has publicly_accessible = true.",
        base_severity=Severity.CRITICAL,
    )


def _get_actions(node: Node) -> list[str]:
    if node.meta is None:
        return []
    actions = node.meta.get("actions", [])
    if isinstance(actions, list):
        return [a for a in actions if isinstance(a, str)]
    return []


_RULES = [
    _rule_sg_open_to_world,
    _rule_public_lb,
    _rule_wildcard_iam,
    _rule_pass_role,
    _rule_db_publicly_accessible,
]
