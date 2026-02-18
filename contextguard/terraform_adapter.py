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


_LB_FORWARD_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})

_ENGINE_DEFAULT_PORTS: dict[str, int] = {
    "postgres": 5432,
    "mysql": 3306,
    "mariadb": 3306,
    "oracle-ee": 1521,
    "oracle-se2": 1521,
    "sqlserver-ee": 1433,
    "sqlserver-se": 1433,
    "sqlserver-ex": 1433,
    "sqlserver-web": 1433,
}

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
    _derive_forward_edges(nodes, edges)

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
    canonical_rules: list[dict[str, object]] = []

    if isinstance(ingress_rules, list):
        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            cidr_blocks = rule.get("cidr_blocks", [])
            if not isinstance(cidr_blocks, list):
                cidr_blocks = []
            ipv6_cidr_blocks = rule.get("ipv6_cidr_blocks", [])
            if not isinstance(ipv6_cidr_blocks, list):
                ipv6_cidr_blocks = []
            source_sgs = rule.get("security_groups", [])
            if not isinstance(source_sgs, list):
                source_sgs = []

            if "0.0.0.0/0" in cidr_blocks or "::/0" in ipv6_cidr_blocks:
                open_to_world = True

            canonical_rules.append({
                "from_port": rule.get("from_port", 0),
                "to_port": rule.get("to_port", 0),
                "protocol": rule.get("protocol", "tcp"),
                "cidr_blocks": sorted(str(c) for c in cidr_blocks),
                "ipv6_cidr_blocks": sorted(str(c) for c in ipv6_cidr_blocks),
                "source_security_groups": sorted(str(s) for s in source_sgs),
            })

    canonical_rules.sort(key=lambda r: (
        r["from_port"],
        r["to_port"],
        r["protocol"],
        ",".join(r["source_security_groups"]),  # type: ignore[arg-type]
        ",".join(r["cidr_blocks"]),  # type: ignore[arg-type]
        ",".join(r["ipv6_cidr_blocks"]),  # type: ignore[arg-type]
    ))

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.SECURITY_GROUP,
            meta={"open_to_world": open_to_world, "ingress_rules": canonical_rules},
        )
    )


def _extract_load_balancer(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    scheme = values.get("internal", False)
    is_public = not scheme
    if "scheme" in values:
        is_public = values["scheme"] == "internet-facing"

    sg_ids = values.get("security_groups", [])
    sg_refs: list[str] = []
    if isinstance(sg_ids, list):
        for sg_id in sg_ids:
            if isinstance(sg_id, str):
                sg_refs.append(sg_id)
                edges.append(Edge(from_id=sg_id, to_id=address, type=EdgeType.ASSOCIATION))

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.LOAD_BALANCER,
            flags=NodeFlags(internet_facing=is_public),
            meta={"sg_refs": sorted(sg_refs)},
        )
    )


def _extract_instance(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    has_public_ip = values.get("associate_public_ip_address", False) is True

    sg_ids = values.get("vpc_security_group_ids", [])
    sg_refs: list[str] = []
    if isinstance(sg_ids, list):
        for sg_id in sg_ids:
            if isinstance(sg_id, str):
                sg_refs.append(sg_id)
                edges.append(Edge(from_id=sg_id, to_id=address, type=EdgeType.ASSOCIATION))

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.INSTANCE,
            flags=NodeFlags(internet_facing=has_public_ip),
            meta={"sg_refs": sorted(sg_refs)},
        )
    )


def _extract_autoscaling_group(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    nodes.append(Node(id=address, kind=NodeKind.AUTOSCALING_GROUP))


def _extract_db_instance(
    address: str, values: dict[str, Any], nodes: list[Node], edges: list[Edge]
) -> None:
    publicly_accessible = values.get("publicly_accessible", False) is True

    sg_ids = values.get("vpc_security_group_ids", [])
    sg_refs: list[str] = []
    if isinstance(sg_ids, list):
        for sg_id in sg_ids:
            if isinstance(sg_id, str):
                sg_refs.append(sg_id)
                edges.append(Edge(from_id=sg_id, to_id=address, type=EdgeType.ASSOCIATION))

    meta: dict[str, object] = {
        "publicly_accessible": publicly_accessible,
        "sg_refs": sorted(sg_refs),
    }
    engine = values.get("engine")
    if isinstance(engine, str):
        meta["engine"] = engine
    port = values.get("port")
    if isinstance(port, int):
        meta["port"] = port

    nodes.append(
        Node(
            id=address,
            kind=NodeKind.DB_INSTANCE,
            flags=NodeFlags(crown_jewel=True),
            meta=meta,
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


def _build_sg_ingress_index(
    nodes: list[Node],
) -> dict[str, list[dict[str, object]]]:
    """Map SG node ID → sorted canonical ingress rules."""
    index: dict[str, list[dict[str, object]]] = {}
    for node in nodes:
        if node.kind == NodeKind.SECURITY_GROUP and node.meta:
            rules = node.meta.get("ingress_rules", [])
            if isinstance(rules, list):
                index[node.id] = rules
    return index


def _build_node_sg_index(nodes: list[Node]) -> dict[str, list[str]]:
    """Map node ID → sorted list of attached SG addresses."""
    index: dict[str, list[str]] = {}
    for node in nodes:
        if node.meta and "sg_refs" in node.meta:
            refs = node.meta["sg_refs"]
            if isinstance(refs, list):
                index[node.id] = sorted(str(r) for r in refs)
    return index


def _get_db_port(node: Node) -> int | None:
    """Determine the DB service port from meta, or None if unknown."""
    if not node.meta:
        return None
    port = node.meta.get("port")
    if isinstance(port, int):
        return port
    engine = node.meta.get("engine")
    if isinstance(engine, str):
        return _ENGINE_DEFAULT_PORTS.get(engine)
    return None


def _port_in_range(port: int, from_port: object, to_port: object, protocol: object) -> bool:
    """Check if a single port falls within a rule's port range."""
    if protocol == "-1":
        return True
    fp = from_port if isinstance(from_port, int) else 0
    tp = to_port if isinstance(to_port, int) else 0
    if fp == 0 and tp == 65535:
        return True
    return fp <= port <= tp


def _port_range_overlaps_lb_ports(
    from_port: object, to_port: object, protocol: object,
) -> int | None:
    """Return the first well-known LB port covered by the range, or None."""
    if protocol == "-1":
        return min(_LB_FORWARD_PORTS)
    fp = from_port if isinstance(from_port, int) else 0
    tp = to_port if isinstance(to_port, int) else 0
    if fp == 0 and tp == 65535:
        return min(_LB_FORWARD_PORTS)
    for p in sorted(_LB_FORWARD_PORTS):
        if fp <= p <= tp:
            return p
    return None


def _derive_forward_edges(nodes: list[Node], edges: list[Edge]) -> None:
    """Derive forward reachability edges from SG ingress rule evidence."""
    sg_ingress = _build_sg_ingress_index(nodes)
    node_sgs = _build_node_sg_index(nodes)

    lbs = sorted((n for n in nodes if n.kind == NodeKind.LOAD_BALANCER), key=lambda n: n.id)
    instances = sorted((n for n in nodes if n.kind == NodeKind.INSTANCE), key=lambda n: n.id)
    dbs = sorted((n for n in nodes if n.kind == NodeKind.DB_INSTANCE), key=lambda n: n.id)

    # LB → Instance (FORWARD_REACHABILITY, MEDIUM)
    for lb in lbs:
        lb_sgs = set(node_sgs.get(lb.id, []))
        if not lb_sgs:
            continue
        for inst in instances:
            inst_sgs = node_sgs.get(inst.id, [])
            edge_emitted = False
            for inst_sg in inst_sgs:
                if edge_emitted:
                    break
                for rule in sg_ingress.get(inst_sg, []):
                    src_sgs = rule.get("source_security_groups", [])
                    if not isinstance(src_sgs, list):
                        continue
                    if not lb_sgs.intersection(src_sgs):
                        continue
                    matched = _port_range_overlaps_lb_ports(
                        rule.get("from_port", 0),
                        rule.get("to_port", 0),
                        rule.get("protocol", "tcp"),
                    )
                    if matched is not None:
                        matching_src = sorted(lb_sgs.intersection(src_sgs))[0]
                        edges.append(Edge(
                            from_id=lb.id,
                            to_id=inst.id,
                            type=EdgeType.FORWARD_REACHABILITY,
                            meta={
                                "confidence": "MEDIUM",
                                "evidence": {
                                    "kind": "sg_rule",
                                    "dst_sg": inst_sg,
                                    "src_sg": matching_src,
                                    "from_port": rule.get("from_port", 0),
                                    "to_port": rule.get("to_port", 0),
                                    "protocol": rule.get("protocol", "tcp"),
                                    "matched_port": matched,
                                },
                            },
                        ))
                        edge_emitted = True
                        break

    # Instance → DB (DATA_ACCESS, HIGH or MEDIUM for cidr-open)
    for inst in instances:
        inst_sg_set = set(node_sgs.get(inst.id, []))
        for db in dbs:
            db_port = _get_db_port(db)
            if db_port is None:
                continue
            db_sgs_list = node_sgs.get(db.id, [])
            edge_emitted = False
            for db_sg in db_sgs_list:
                if edge_emitted:
                    break
                for rule in sg_ingress.get(db_sg, []):
                    port_ok = _port_in_range(
                        db_port,
                        rule.get("from_port", 0),
                        rule.get("to_port", 0),
                        rule.get("protocol", "tcp"),
                    )
                    if not port_ok:
                        continue

                    src_sgs = rule.get("source_security_groups", [])
                    if isinstance(src_sgs, list) and inst_sg_set.intersection(src_sgs):
                        matching_src = sorted(inst_sg_set.intersection(src_sgs))[0]
                        edges.append(Edge(
                            from_id=inst.id,
                            to_id=db.id,
                            type=EdgeType.DATA_ACCESS,
                            meta={
                                "confidence": "HIGH",
                                "evidence": {
                                    "kind": "sg_rule",
                                    "dst_sg": db_sg,
                                    "src_sg": matching_src,
                                    "from_port": rule.get("from_port", 0),
                                    "to_port": rule.get("to_port", 0),
                                    "protocol": rule.get("protocol", "tcp"),
                                    "db_port": db_port,
                                },
                            },
                        ))
                        edge_emitted = True
                        break

                    cidr_blocks = rule.get("cidr_blocks", [])
                    ipv6_blocks = rule.get("ipv6_cidr_blocks", [])
                    cidr_open = (
                        (isinstance(cidr_blocks, list) and "0.0.0.0/0" in cidr_blocks)
                        or (isinstance(ipv6_blocks, list) and "::/0" in ipv6_blocks)
                    )
                    if cidr_open:
                        edges.append(Edge(
                            from_id=inst.id,
                            to_id=db.id,
                            type=EdgeType.DATA_ACCESS,
                            meta={
                                "confidence": "MEDIUM",
                                "evidence": {
                                    "kind": "cidr_open",
                                    "dst_sg": db_sg,
                                    "from_port": rule.get("from_port", 0),
                                    "to_port": rule.get("to_port", 0),
                                    "protocol": rule.get("protocol", "tcp"),
                                    "db_port": db_port,
                                },
                            },
                        ))
                        edge_emitted = True
                        break
