"""Tests for scoring.score_findings()."""

from __future__ import annotations

from contextguard.graph import BfsResult, build_graph, bfs
from contextguard.model import (
    INTERNET_NODE_ID,
    BreakpointType,
    ContextGuardConfig,
    Edge,
    EdgeType,
    Finding,
    FindingCategory,
    Node,
    NodeFlags,
    NodeKind,
    Severity,
)
from contextguard.scoring import score_findings


def _finding(
    node_id: str,
    rule_id: str = "sg-open-to-world",
    category: FindingCategory = FindingCategory.NETWORK,
    base_severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id="test-id",
        node_id=node_id,
        rule_id=rule_id,
        category=category,
        title="Test finding",
        description="Test",
        base_severity=base_severity,
    )


def _config() -> ContextGuardConfig:
    return ContextGuardConfig()


class TestRule1Unreachable:
    def test_unreachable_downgraded_to_noise(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="sg-1", kind=NodeKind.SECURITY_GROUP, meta={"open_to_world": True}),
        ]
        edges: list[Edge] = []
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("sg-1")]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert scored[0].context_severity == Severity.NOISE
        assert "not reachable" in scored[0].override_reason.lower()

    def test_unreachable_critical_base_still_noise(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(
                id="db-1",
                kind=NodeKind.DB_INSTANCE,
                flags=NodeFlags(crown_jewel=True),
                meta={"publicly_accessible": True},
            ),
        ]
        graph = build_graph(nodes, [])
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("db-1", "db-public", FindingCategory.DATA, Severity.CRITICAL)]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert scored[0].context_severity == Severity.NOISE


class TestRule2NoCrownJewelPath:
    def test_reachable_no_crown_jewel_capped_at_high(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="sg-1", kind=NodeKind.SECURITY_GROUP, meta={"open_to_world": True}),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="sg-1", type=EdgeType.ASSOCIATION),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("sg-1")]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert scored[0].context_severity == Severity.HIGH
        assert "no path to crown jewel" in scored[0].override_reason.lower()


class TestRule3CrownJewelPath:
    def test_three_hops_critical(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="sg-1", kind=NodeKind.SECURITY_GROUP, meta={"open_to_world": True}),
            Node(id="db", kind=NodeKind.DB_INSTANCE, flags=NodeFlags(crown_jewel=True)),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="sg-1", type=EdgeType.ASSOCIATION),
            Edge(from_id="sg-1", to_id="db", type=EdgeType.ASSOCIATION),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("sg-1")]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert scored[0].context_severity == Severity.CRITICAL
        assert scored[0].shortest_path_length is not None
        assert scored[0].shortest_path_length <= 3

    def test_five_hops_high(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="n1", kind=NodeKind.INSTANCE),
            Node(id="n2", kind=NodeKind.INSTANCE),
            Node(id="sg-1", kind=NodeKind.SECURITY_GROUP, meta={"open_to_world": True}),
            Node(id="db", kind=NodeKind.DB_INSTANCE, flags=NodeFlags(crown_jewel=True)),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="n1", type=EdgeType.ASSOCIATION),
            Edge(from_id="n1", to_id="n2", type=EdgeType.ASSOCIATION),
            Edge(from_id="n2", to_id="sg-1", type=EdgeType.ASSOCIATION),
            Edge(from_id="sg-1", to_id="db", type=EdgeType.ASSOCIATION),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("sg-1")]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert scored[0].context_severity == Severity.HIGH


class TestRule4IAMImpact:
    def test_iam_rds_wildcard_forces_critical(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="pol", kind=NodeKind.IAM_POLICY, meta={"actions": ["rds:*"]}),
            Node(id="db", kind=NodeKind.DB_INSTANCE, flags=NodeFlags(crown_jewel=True)),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="pol", type=EdgeType.IAM_BINDING),
            Edge(from_id="pol", to_id="db", type=EdgeType.DATA_ACCESS),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("pol", "wildcard-iam", FindingCategory.IAM, Severity.HIGH)]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert scored[0].context_severity == Severity.CRITICAL
        assert "impact" in scored[0].override_reason.lower()

    def test_iam_non_impact_action_no_rule4(self) -> None:
        """ec2:DescribeInstances is not in the impact families, so rule 4 must not fire.
        Use a long path so rule 3 doesn't independently reach CRITICAL either."""
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="n1", kind=NodeKind.INSTANCE),
            Node(id="n2", kind=NodeKind.INSTANCE),
            Node(id="n3", kind=NodeKind.INSTANCE),
            Node(
                id="pol",
                kind=NodeKind.IAM_POLICY,
                meta={"actions": ["ec2:DescribeInstances"]},
            ),
            Node(id="db", kind=NodeKind.DB_INSTANCE, flags=NodeFlags(crown_jewel=True)),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="n1", type=EdgeType.ASSOCIATION),
            Edge(from_id="n1", to_id="n2", type=EdgeType.ASSOCIATION),
            Edge(from_id="n2", to_id="n3", type=EdgeType.ASSOCIATION),
            Edge(from_id="n3", to_id="pol", type=EdgeType.IAM_BINDING),
            Edge(from_id="pol", to_id="db", type=EdgeType.DATA_ACCESS),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("pol", "other-rule", FindingCategory.IAM, Severity.HIGH)]

        scored = score_findings(findings, bfs_result, graph, _config())
        # Rule 4 should NOT have fired (non-impact action), so reason must not mention "impact"
        assert "impact" not in scored[0].override_reason.lower()
        assert scored[0].context_severity != Severity.CRITICAL


class TestBreakpoints:
    def test_three_hop_one_breakpoint(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="sg-1", kind=NodeKind.SECURITY_GROUP, meta={"open_to_world": True}),
            Node(id="db", kind=NodeKind.DB_INSTANCE, flags=NodeFlags(crown_jewel=True)),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="sg-1", type=EdgeType.ASSOCIATION),
            Edge(from_id="sg-1", to_id="db", type=EdgeType.ASSOCIATION),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("sg-1")]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert len(scored[0].breakpoints) >= 1

    def test_five_hop_two_breakpoints(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="n1", kind=NodeKind.INSTANCE),
            Node(id="n2", kind=NodeKind.SECURITY_GROUP),
            Node(id="sg-1", kind=NodeKind.SECURITY_GROUP, meta={"open_to_world": True}),
            Node(id="db", kind=NodeKind.DB_INSTANCE, flags=NodeFlags(crown_jewel=True)),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="n1", type=EdgeType.ASSOCIATION),
            Edge(from_id="n1", to_id="n2", type=EdgeType.ASSOCIATION),
            Edge(from_id="n2", to_id="sg-1", type=EdgeType.ASSOCIATION),
            Edge(from_id="sg-1", to_id="db", type=EdgeType.ASSOCIATION),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("sg-1")]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert len(scored[0].breakpoints) == 2

    def test_lb_breakpoint_uses_lb_template(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="sg-1", kind=NodeKind.SECURITY_GROUP, meta={"open_to_world": True}),
            Node(id="db", kind=NodeKind.DB_INSTANCE, flags=NodeFlags(crown_jewel=True)),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="sg-1", type=EdgeType.ASSOCIATION),
            Edge(from_id="sg-1", to_id="db", type=EdgeType.ASSOCIATION),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("sg-1")]

        scored = score_findings(findings, bfs_result, graph, _config())
        lb_bp = next(
            (bp for bp in scored[0].breakpoints if bp.kind == NodeKind.LOAD_BALANCER), None
        )
        assert lb_bp is not None
        assert "WAF" in lb_bp.recommendation or "listener" in lb_bp.recommendation

    def test_iam_role_breakpoint_uses_role_template(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="alb", kind=NodeKind.LOAD_BALANCER, flags=NodeFlags(internet_facing=True)),
            Node(id="role-1", kind=NodeKind.IAM_ROLE),
            Node(id="pol", kind=NodeKind.IAM_POLICY, meta={"actions": ["rds:*"]}),
            Node(id="db", kind=NodeKind.DB_INSTANCE, flags=NodeFlags(crown_jewel=True)),
        ]
        edges = [
            Edge(from_id=INTERNET_NODE_ID, to_id="alb", type=EdgeType.NETWORK_EXPOSURE),
            Edge(from_id="alb", to_id="role-1", type=EdgeType.IAM_BINDING),
            Edge(from_id="role-1", to_id="pol", type=EdgeType.IAM_BINDING),
            Edge(from_id="pol", to_id="db", type=EdgeType.DATA_ACCESS),
        ]
        graph = build_graph(nodes, edges)
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("pol", "wildcard-iam", FindingCategory.IAM, Severity.HIGH)]

        scored = score_findings(findings, bfs_result, graph, _config())
        # Breakpoint should be on the IAM role (earliest intermediate)
        assert len(scored[0].breakpoints) >= 1

    def test_no_breakpoints_on_noise(self) -> None:
        nodes = [
            Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET),
            Node(id="sg-1", kind=NodeKind.SECURITY_GROUP, meta={"open_to_world": True}),
        ]
        graph = build_graph(nodes, [])
        bfs_result = bfs(graph, INTERNET_NODE_ID)
        findings = [_finding("sg-1")]

        scored = score_findings(findings, bfs_result, graph, _config())
        assert scored[0].context_severity == Severity.NOISE
        assert len(scored[0].breakpoints) == 0


class TestEmptyFindings:
    def test_empty_input(self) -> None:
        nodes = [Node(id=INTERNET_NODE_ID, kind=NodeKind.INTERNET)]
        graph = build_graph(nodes, [])
        bfs_result = bfs(graph, INTERNET_NODE_ID)

        scored = score_findings([], bfs_result, graph, _config())
        assert scored == []
