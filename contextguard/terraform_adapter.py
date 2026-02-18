"""Terraform plan JSON adapter — parses tfplan.json into canonical model."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from contextguard.logger import logger
from contextguard.model import (
    INTERNET_NODE_ID,
    AdapterOutput,
    AdapterStats,
    Edge,
    EdgeType,
    Node,
    NodeFlags,
    NodeKind,
)


class ParseError(Exception):
    """Raised when the Terraform plan JSON is malformed or invalid."""


SUPPORTED_TYPES: dict[str, NodeKind] = {
    "aws_security_group": NodeKind.SECURITY_GROUP,
    "aws_lb": NodeKind.LOAD_BALANCER,
    "aws_instance": NodeKind.INSTANCE,
    "aws_autoscaling_group": NodeKind.AUTOSCALING_GROUP,
    "aws_db_instance": NodeKind.DB_INSTANCE,
    "aws_iam_role": NodeKind.IAM_ROLE,
    "aws_iam_policy": NodeKind.IAM_POLICY,
    "aws_iam_role_policy": NodeKind.IAM_POLICY,
    "aws_iam_role_policy_attachment": NodeKind.IAM_POLICY,
    "aws_iam_policy_attachment": NodeKind.IAM_POLICY,
}


def parse_plan(path: Path) -> AdapterOutput:
    """Parse a Terraform plan JSON file and return canonical nodes and edges."""
    raw = _load_json(path)
    resource_changes = _extract_resource_changes(raw)

    nodes: list[Node] = []
    edges: list[Edge] = []
    supported = 0
    skipped = 0

    for rc in resource_changes:
        rc_type = rc.get("type", "")
        if rc_type not in SUPPORTED_TYPES:
            skipped += 1
            continue
        supported += 1
        kind = SUPPORTED_TYPES[rc_type]
        address = rc.get("address", rc_type)
        values = _get_values(rc)
        _extract_resource(address, kind, values, rc, nodes, edges)

    internet_node = Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET)
    nodes.insert(0, internet_node)
    _add_internet_edges(nodes, edges)

    total = supported + skipped
    if skipped > 0:
        logger.info("Skipped %d unsupported resource(s) out of %d total", skipped, total)

    return AdapterOutput(
        nodes=nodes,
        edges=edges,
        stats=AdapterStats(total=total, supported=supported, skipped=skipped),
    )


def _load_json(path: Path) -> dict[str, Any]:
    from pathlib import Path as _Path

    p = _Path(str(path))
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ParseError(f"File not found: {path}") from None
    except OSError as e:
        raise ParseError(f"Cannot read file {path}: {e}") from None
    try:
        data: object = json.loads(text)
    except json.JSONDecodeError as e:
        raise ParseError(
            f"{path} is not valid JSON. "
            "Run 'terraform show -json tfplan > tfplan.json' to generate a valid plan file."
        ) from e
    if not isinstance(data, dict):
        raise ParseError(f"{path} is not a valid Terraform plan (expected JSON object).")
    return data


def _extract_resource_changes(raw: dict[str, Any]) -> list[dict[str, Any]]:
    rc = raw.get("resource_changes")
    if rc is None:
        raise ParseError(
            "Missing 'resource_changes' key. "
            "This does not appear to be a valid Terraform plan JSON."
        )
    if not isinstance(rc, list):
        raise ParseError("'resource_changes' must be an array.")
    return rc


def _get_values(rc: dict[str, Any]) -> dict[str, Any]:
    change = rc.get("change", {})
    after = change.get("after")
    if isinstance(after, dict):
        return after
    return {}


def _extract_resource(
    address: str,
    kind: NodeKind,
    values: dict[str, Any],
    rc: dict[str, Any],
    nodes: list[Node],
    edges: list[Edge],
) -> None:
    if kind == NodeKind.SECURITY_GROUP:
        _extract_security_group(address, values, nodes, edges)
    elif kind == NodeKind.LOAD_BALANCER:
        _extract_load_balancer(address, values, nodes, edges)
    elif kind == NodeKind.INSTANCE:
        _extract_instance(address, values, nodes, edges)
    elif kind == NodeKind.AUTOSCALING_GROUP:
        _extract_autoscaling_group(address, values, nodes, edges)
    elif kind == NodeKind.DB_INSTANCE:
        _extract_db_instance(address, values, nodes, edges)
    elif kind == NodeKind.IAM_ROLE:
        _extract_iam_role(address, values, nodes, edges)
    elif kind == NodeKind.IAM_POLICY:
        _extract_iam_policy(address, values, rc, nodes, edges)


def _extract_security_group(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    ingress_rules = values.get("ingress", [])
    open_to_world = False
    if isinstance(ingress_rules, list):
        for rule in ingress_rules:
            if isinstance(rule, dict):
                cidr_blocks = rule.get("cidr_blocks", [])
                if isinstance(cidr_blocks, list) and "0.0.0.0/0" in cidr_blocks:
                    open_to_world = True
                    break

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.SECURITY_GROUP,
            meta={"open_to_world": open_to_world},
        )
    )


def _extract_load_balancer(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    scheme = values.get("internal", False)
    is_public = not scheme
    if "scheme" in values:
        is_public = values["scheme"] == "internet-facing"

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.LOAD_BALANCER,
            flags=NodeFlags(internet_facing=is_public),
        )
    )

    sg_ids = values.get("security_groups", [])
    if isinstance(sg_ids, list):
        for sg_id in sg_ids:
            if isinstance(sg_id, str):
                edges.append(Edge(from_id=sg_id, to_id=address, type=EdgeType.ASSOCIATION))


def _extract_instance(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    has_public_ip = values.get("associate_public_ip_address", False) is True

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.INSTANCE,
            flags=NodeFlags(internet_facing=has_public_ip),
        )
    )

    sg_ids = values.get("vpc_security_group_ids", [])
    if isinstance(sg_ids, list):
        for sg_id in sg_ids:
            if isinstance(sg_id, str):
                edges.append(Edge(from_id=sg_id, to_id=address, type=EdgeType.ASSOCIATION))


def _extract_autoscaling_group(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    nodes.append(Node(id=address, kind=NodeKind.AUTOSCALING_GROUP))


def _extract_db_instance(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    publicly_accessible = values.get("publicly_accessible", False) is True

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.DB_INSTANCE,
            flags=NodeFlags(crown_jewel=True),
            meta={"publicly_accessible": publicly_accessible},
        )
    )


def _extract_iam_role(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    nodes.append(
        Node(
            id=address,
            kind=NodeKind.IAM_ROLE,
            meta={"assume_role_policy": values.get("assume_role_policy")},
        )
    )


def _extract_iam_policy(
    address: str,
    values: dict[str, Any],
    rc: dict[str, Any],
    nodes: list[Node],
    edges: list[Edge],
) -> None:
    rc_type = rc.get("type", "")
    actions = _extract_policy_actions(values)

    if rc_type in ("aws_iam_role_policy_attachment", "aws_iam_policy_attachment"):
        role = values.get("role", values.get("roles", [None]))
        policy_arn = values.get("policy_arn", "")
        if isinstance(role, str) and policy_arn:
            edges.append(Edge(from_id=role, to_id=policy_arn, type=EdgeType.IAM_BINDING))
        elif isinstance(role, list):
            for r in role:
                if isinstance(r, str) and policy_arn:
                    edges.append(Edge(from_id=r, to_id=policy_arn, type=EdgeType.IAM_BINDING))
        return

    if rc_type == "aws_iam_role_policy":
        role_name = values.get("role", "")
        if isinstance(role_name, str) and role_name:
            edges.append(Edge(from_id=role_name, to_id=address, type=EdgeType.IAM_BINDING))

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.IAM_POLICY,
            meta={"actions": actions},
        )
    )


def _extract_policy_actions(values: dict[str, Any]) -> list[str]:
    policy_str = values.get("policy", "")
    if not isinstance(policy_str, str) or not policy_str:
        return []
    try:
        policy_doc = json.loads(policy_str)
    except (json.JSONDecodeError, TypeError):
        return []

    actions: list[str] = []
    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        return []
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        stmt_actions = stmt.get("Action", [])
        if isinstance(stmt_actions, str):
            actions.append(stmt_actions)
        elif isinstance(stmt_actions, list):
            actions.extend(a for a in stmt_actions if isinstance(a, str))
    return actions


def _add_internet_edges(nodes: list[Node], edges: list[Edge]) -> None:
    """Add network_exposure edges from INTERNET to true entrypoints only."""
    for node in nodes:
        if node.kind in (NodeKind.LOAD_BALANCER, NodeKind.INSTANCE) and node.flags.internet_facing:
            edges.append(
                Edge(from_id=INTERNET_NODE_ID, to_id=node.id, type=EdgeType.NETWORK_EXPOSURE)
            )
