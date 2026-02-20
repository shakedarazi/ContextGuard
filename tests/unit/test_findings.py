"""Tests for findings.extract_findings()."""

from __future__ import annotations

from contextguard.core.findings import extract_findings
from contextguard.core.graph import Graph, build_graph
from contextguard.core.model import (
    INTERNET_NODE_ID,
    CanonicalAction,
    Edge,
    Node,
    NodeCategory,
    NodeFlags,
    NodeKind,
    Severity,
)


def _build(nodes: list[Node], edges: list[Edge] | None = None) -> Graph:
    return build_graph(nodes, edges or [])


class TestSGOpenToWorld:
    def test_fires_on_open_sg(self) -> None:
        nodes = [
            Node(
                id="sg-1",
                kind=NodeKind.SECURITY_GROUP,
                category=NodeCategory.FIREWALL,
                meta={"open_to_world": True},
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        assert len(findings) == 1
        assert findings[0].rule_id == "sg-open-to-world"
        assert findings[0].base_severity == Severity.HIGH

    def test_does_not_fire_on_closed_sg(self) -> None:
        nodes = [
            Node(
                id="sg-1",
                kind=NodeKind.SECURITY_GROUP,
                category=NodeCategory.FIREWALL,
                meta={"open_to_world": False},
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        assert len(findings) == 0

    def test_does_not_fire_on_non_sg(self) -> None:
        nodes = [
            Node(
                id="inst-1",
                kind=NodeKind.INSTANCE,
                category=NodeCategory.COMPUTE,
                meta={"open_to_world": True},
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        sg_findings = [f for f in findings if f.rule_id == "sg-open-to-world"]
        assert len(sg_findings) == 0


class TestPublicLB:
    def test_fires_on_public_lb(self) -> None:
        nodes = [
            Node(
                id="alb-1",
                kind=NodeKind.LOAD_BALANCER,
                category=NodeCategory.LOAD_BALANCER,
                flags=NodeFlags(internet_facing=True),
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        assert len(findings) == 1
        assert findings[0].rule_id == "public-lb"
        assert findings[0].base_severity == Severity.MEDIUM

    def test_does_not_fire_on_private_lb(self) -> None:
        nodes = [
            Node(id="alb-1", kind=NodeKind.LOAD_BALANCER, category=NodeCategory.LOAD_BALANCER),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        assert len(findings) == 0


class TestWildcardIAM:
    def test_fires_on_wildcard_policy(self) -> None:
        nodes = [
            Node(
                id="pol-1",
                kind=NodeKind.IAM_POLICY,
                category=NodeCategory.IDENTITY,
                meta={"actions": ["*"]},
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        wildcard = [f for f in findings if f.rule_id == "wildcard-iam"]
        assert len(wildcard) == 1
        assert wildcard[0].base_severity == Severity.HIGH

    def test_does_not_fire_on_scoped_policy(self) -> None:
        nodes = [
            Node(
                id="pol-1",
                kind=NodeKind.IAM_POLICY,
                category=NodeCategory.IDENTITY,
                meta={"actions": ["s3:GetObject"]},
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        wildcard = [f for f in findings if f.rule_id == "wildcard-iam"]
        assert len(wildcard) == 0


class TestPassRole:
    def test_fires_on_pass_role(self) -> None:
        nodes = [
            Node(
                id="pol-1",
                kind=NodeKind.IAM_POLICY,
                category=NodeCategory.IDENTITY,
                meta={"actions": ["iam:PassRole", "s3:GetObject"]},
                canonical_actions={
                    CanonicalAction.PRIVILEGE_ESCALATION,
                    CanonicalAction.STORAGE_READ,
                },
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        pr = [f for f in findings if f.rule_id == "pass-role"]
        assert len(pr) == 1

    def test_does_not_double_fire_with_wildcard(self) -> None:
        nodes = [
            Node(
                id="pol-1",
                kind=NodeKind.IAM_POLICY,
                category=NodeCategory.IDENTITY,
                meta={"actions": ["*"]},
                canonical_actions=set(CanonicalAction),
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        pr = [f for f in findings if f.rule_id == "pass-role"]
        assert len(pr) == 0


class TestDBPubliclyAccessible:
    def test_fires_on_public_db(self) -> None:
        nodes = [
            Node(
                id="db-1",
                kind=NodeKind.DB_INSTANCE,
                category=NodeCategory.DATABASE,
                flags=NodeFlags(crown_jewel=True),
                meta={"publicly_accessible": True},
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        assert len(findings) == 1
        assert findings[0].rule_id == "db-public"
        assert findings[0].base_severity == Severity.CRITICAL

    def test_does_not_fire_on_private_db(self) -> None:
        nodes = [
            Node(
                id="db-1",
                kind=NodeKind.DB_INSTANCE,
                category=NodeCategory.DATABASE,
                flags=NodeFlags(crown_jewel=True),
                meta={"publicly_accessible": False},
            ),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        assert len(findings) == 0


class TestNoFindings:
    def test_no_findings_for_internet_node(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET, category=NodeCategory.INTERNET),
        ]
        graph = _build(nodes)
        findings = extract_findings(nodes, graph)
        assert len(findings) == 0
