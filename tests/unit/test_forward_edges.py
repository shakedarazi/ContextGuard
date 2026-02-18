"""Tests for forward edge derivation logic (_derive_forward_edges)."""

from __future__ import annotations

from contextguard.model import INTERNET_NODE_ID, Edge, EdgeType, Node, NodeCategory, NodeFlags, NodeKind
from contextguard.terraform_adapter import _derive_forward_edges


def _sg(
    address: str,
    ingress_rules: list[dict[str, object]] | None = None,
    open_to_world: bool = False,
) -> Node:
    rules = ingress_rules or []
    return Node(
        id=address,
        kind=NodeKind.SECURITY_GROUP,
        category=NodeCategory.FIREWALL,
        meta={"open_to_world": open_to_world, "ingress_rules": rules},
    )


def _lb(address: str, sg_refs: list[str]) -> Node:
    return Node(
        id=address,
        kind=NodeKind.LOAD_BALANCER,
        category=NodeCategory.LOAD_BALANCER,
        flags=NodeFlags(internet_facing=True),
        meta={"sg_refs": sorted(sg_refs)},
    )


def _instance(address: str, sg_refs: list[str]) -> Node:
    return Node(
        id=address,
        kind=NodeKind.INSTANCE,
        category=NodeCategory.COMPUTE,
        meta={"sg_refs": sorted(sg_refs)},
    )


def _db(
    address: str,
    sg_refs: list[str],
    engine: str | None = None,
    port: int | None = None,
) -> Node:
    meta: dict[str, object] = {
        "publicly_accessible": True,
        "sg_refs": sorted(sg_refs),
    }
    if engine is not None:
        meta["engine"] = engine
    if port is not None:
        meta["port"] = port
    return Node(
        id=address,
        kind=NodeKind.DB_INSTANCE,
        category=NodeCategory.DATABASE,
        flags=NodeFlags(crown_jewel=True),
        meta=meta,
    )


def _rule(
    from_port: int = 0,
    to_port: int = 0,
    protocol: str = "tcp",
    source_security_groups: list[str] | None = None,
    cidr_blocks: list[str] | None = None,
    ipv6_cidr_blocks: list[str] | None = None,
) -> dict[str, object]:
    return {
        "from_port": from_port,
        "to_port": to_port,
        "protocol": protocol,
        "cidr_blocks": sorted(cidr_blocks or []),
        "ipv6_cidr_blocks": sorted(ipv6_cidr_blocks or []),
        "source_security_groups": sorted(source_security_groups or []),
    }


def _forward_edges(edges: list[Edge]) -> list[Edge]:
    return [
        e for e in edges
        if e.type in (EdgeType.FORWARD_REACHABILITY, EdgeType.DATA_ACCESS)
        and e.meta is not None
    ]


class TestLBInstanceEdges:
    def test_sg_rule_allows_source_sg(self) -> None:
        """Instance SG ingress allows LB SG on port 8080 → LB→Instance edge."""
        nodes = [
            _sg("sg.web"),
            _sg("sg.app", [_rule(8080, 8080, "tcp", source_security_groups=["sg.web"])]),
            _lb("lb.web", ["sg.web"]),
            _instance("inst.app", ["sg.app"]),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)

        fwd = _forward_edges(edges)
        assert len(fwd) == 1
        assert fwd[0].from_id == "lb.web"
        assert fwd[0].to_id == "inst.app"
        assert fwd[0].type == EdgeType.FORWARD_REACHABILITY
        assert fwd[0].meta is not None
        assert fwd[0].meta["confidence"] == "MEDIUM"

    def test_shared_sg_no_rule_no_edge(self) -> None:
        """LB and Instance share same SG but no ingress rule references it as source → 0 edges."""
        nodes = [
            _sg("sg.shared", [_rule(443, 443, "tcp", cidr_blocks=["0.0.0.0/0"])]),
            _lb("lb.web", ["sg.shared"]),
            _instance("inst.app", ["sg.shared"]),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)
        assert len(_forward_edges(edges)) == 0

    def test_lb_irrelevant_port_no_edge(self) -> None:
        """Instance SG allows LB SG on port 22 only → no edge (22 not in LB ports)."""
        nodes = [
            _sg("sg.web"),
            _sg("sg.app", [_rule(22, 22, "tcp", source_security_groups=["sg.web"])]),
            _lb("lb.web", ["sg.web"]),
            _instance("inst.app", ["sg.app"]),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)
        assert len(_forward_edges(edges)) == 0

    def test_lb_port_range_overlaps_well_known(self) -> None:
        """Instance SG rule allows LB SG on ports 8000-8100 → covers 8080."""
        nodes = [
            _sg("sg.web"),
            _sg("sg.app", [_rule(8000, 8100, "tcp", source_security_groups=["sg.web"])]),
            _lb("lb.web", ["sg.web"]),
            _instance("inst.app", ["sg.app"]),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)

        fwd = _forward_edges(edges)
        assert len(fwd) == 1
        assert fwd[0].meta is not None
        assert fwd[0].meta["confidence"] == "MEDIUM"


class TestInstanceDBEdges:
    def test_cidr_open_to_world_creates_edge(self) -> None:
        """DB SG allows 0.0.0.0/0 on DB port → NETWORK_EXPOSURE from INTERNET."""
        nodes = [
            _sg("sg.data", [_rule(5432, 5432, "tcp", cidr_blocks=["0.0.0.0/0"])]),
            _instance("inst.app", ["sg.app"]),
            _sg("sg.app"),
            _db("db.prod", ["sg.data"], engine="postgres"),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)

        fwd = [e for e in edges if e.type == EdgeType.NETWORK_EXPOSURE and e.meta is not None]
        assert len(fwd) == 1
        assert fwd[0].from_id == INTERNET_NODE_ID
        assert fwd[0].to_id == "db.prod"
        assert fwd[0].meta is not None
        assert fwd[0].meta["confidence"] == "MEDIUM"
        evidence = fwd[0].meta["evidence"]
        assert isinstance(evidence, dict)
        assert evidence["kind"] == "cidr_open"

    def test_no_sg_refs_no_edge(self) -> None:
        """DB has no vpc_security_group_ids → 0 forward edges."""
        nodes = [
            _sg("sg.app"),
            _instance("inst.app", ["sg.app"]),
            _db("db.prod", [], engine="postgres"),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)
        assert len(_forward_edges(edges)) == 0

    def test_db_port_range_covers_service_port(self) -> None:
        """SG rule port range 5000-6000 covers DB port 5432 → edge created."""
        nodes = [
            _sg("sg.app"),
            _sg("sg.data", [_rule(5000, 6000, "tcp", source_security_groups=["sg.app"])]),
            _instance("inst.app", ["sg.app"]),
            _db("db.prod", ["sg.data"], engine="postgres"),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)

        fwd = [e for e in edges if e.type == EdgeType.DATA_ACCESS and e.meta is not None]
        assert len(fwd) == 1

    def test_db_port_mismatch_no_edge(self) -> None:
        """SG rule allows Instance SG on port 22, DB listens on 5432 → no edge."""
        nodes = [
            _sg("sg.app"),
            _sg("sg.data", [_rule(22, 22, "tcp", source_security_groups=["sg.app"])]),
            _instance("inst.app", ["sg.app"]),
            _db("db.prod", ["sg.data"], engine="postgres"),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)
        assert len(_forward_edges(edges)) == 0

    def test_db_engine_default_port(self) -> None:
        """DB has engine: 'mysql' but no explicit port → uses default 3306."""
        nodes = [
            _sg("sg.app"),
            _sg("sg.data", [_rule(3306, 3306, "tcp", source_security_groups=["sg.app"])]),
            _instance("inst.app", ["sg.app"]),
            _db("db.prod", ["sg.data"], engine="mysql"),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)

        fwd = [e for e in edges if e.type == EdgeType.DATA_ACCESS and e.meta is not None]
        assert len(fwd) == 1
        assert fwd[0].meta is not None
        evidence = fwd[0].meta["evidence"]
        assert isinstance(evidence, dict)
        assert evidence["db_port"] == 3306

    def test_db_unknown_engine_no_port(self) -> None:
        """DB has no engine or port → 0 forward edges (safe false-negative)."""
        nodes = [
            _sg("sg.app"),
            _sg("sg.data", [_rule(5432, 5432, "tcp", source_security_groups=["sg.app"])]),
            _instance("inst.app", ["sg.app"]),
            _db("db.prod", ["sg.data"]),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)
        assert len(_forward_edges(edges)) == 0


class TestProtocolAndDeterminism:
    def test_protocol_all_match(self) -> None:
        """SG rule with protocol '-1' (all traffic) → edge created."""
        nodes = [
            _sg("sg.web"),
            _sg("sg.app", [_rule(0, 0, "-1", source_security_groups=["sg.web"])]),
            _lb("lb.web", ["sg.web"]),
            _instance("inst.app", ["sg.app"]),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)
        assert len(_forward_edges(edges)) == 1

    def test_multiple_sgs_first_match_deterministic(self) -> None:
        """Instance has 2 SGs, both allow LB SG → exactly 1 edge (first sorted match)."""
        nodes = [
            _sg("sg.web"),
            _sg("sg.app1", [_rule(443, 443, "tcp", source_security_groups=["sg.web"])]),
            _sg("sg.app2", [_rule(80, 80, "tcp", source_security_groups=["sg.web"])]),
            _lb("lb.web", ["sg.web"]),
            _instance("inst.app", ["sg.app1", "sg.app2"]),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)

        fwd = _forward_edges(edges)
        assert len(fwd) == 1
        assert fwd[0].meta is not None
        evidence = fwd[0].meta["evidence"]
        assert isinstance(evidence, dict)
        assert evidence["dst_sg"] == "sg.app1"

    def test_derivation_ordering_stable(self) -> None:
        """Multiple LBs and instances → edges emitted in sorted (from_id, to_id) order."""
        nodes = [
            _sg("sg.web"),
            _sg("sg.app1", [_rule(8080, 8080, "tcp", source_security_groups=["sg.web"])]),
            _sg("sg.app2", [_rule(443, 443, "tcp", source_security_groups=["sg.web"])]),
            _lb("lb.a", ["sg.web"]),
            _lb("lb.b", ["sg.web"]),
            _instance("inst.x", ["sg.app1"]),
            _instance("inst.y", ["sg.app2"]),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)

        fwd = _forward_edges(edges)
        pairs = [(e.from_id, e.to_id) for e in fwd]
        assert pairs == sorted(pairs)

    def test_meta_evidence_structure(self) -> None:
        """Verify edge.meta contains all required fields."""
        nodes = [
            _sg("sg.app"),
            _sg("sg.data", [_rule(5432, 5432, "tcp", source_security_groups=["sg.app"])]),
            _instance("inst.app", ["sg.app"]),
            _db("db.prod", ["sg.data"], engine="postgres"),
        ]
        edges: list[Edge] = []
        _derive_forward_edges(nodes, edges)

        fwd = [e for e in edges if e.type == EdgeType.DATA_ACCESS and e.meta is not None]
        assert len(fwd) == 1
        meta = fwd[0].meta
        assert meta is not None
        assert set(meta.keys()) == {"confidence", "evidence"}
        assert meta["confidence"] in ("HIGH", "MEDIUM")
        evidence = meta["evidence"]
        assert isinstance(evidence, dict)
        assert "kind" in evidence
        assert "dst_sg" in evidence
        assert "src_sg" in evidence
        assert "from_port" in evidence
        assert "to_port" in evidence
        assert "protocol" in evidence
        assert "db_port" in evidence
