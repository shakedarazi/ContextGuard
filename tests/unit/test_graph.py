"""Tests for graph.build_graph, bfs, shortest_path."""

from __future__ import annotations

from contextguard.graph import bfs, build_graph, shortest_path
from contextguard.model import (
    INTERNET_NODE_ID,
    Edge,
    EdgeType,
    Node,
    NodeKind,
)


def _node(id: str, kind: NodeKind = NodeKind.INSTANCE) -> Node:
    return Node(id=id, kind=kind)


def _edge(from_id: str, to_id: str) -> Edge:
    return Edge(from_id=from_id, to_id=to_id, type=EdgeType.NETWORK_EXPOSURE)


class TestBfsLinearPath:
    def test_internet_alb_instance_db(self) -> None:
        nodes = [
            _node(INTERNET_NODE_ID, NodeKind.INTERNET),
            _node("alb", NodeKind.LOAD_BALANCER),
            _node("inst", NodeKind.INSTANCE),
            _node("db", NodeKind.DB_INSTANCE),
        ]
        edges = [
            _edge(INTERNET_NODE_ID, "alb"),
            _edge("alb", "inst"),
            _edge("inst", "db"),
        ]
        graph = build_graph(nodes, edges)
        result = bfs(graph, INTERNET_NODE_ID)

        assert "alb" in result.reachable
        assert "inst" in result.reachable
        assert "db" in result.reachable
        assert INTERNET_NODE_ID not in result.reachable

        path = shortest_path(result.parents, "db")
        assert path.hops == 3
        assert path.path == [INTERNET_NODE_ID, "alb", "inst", "db"]


class TestDisconnectedGraph:
    def test_isolated_sg_not_reachable(self) -> None:
        nodes = [
            _node(INTERNET_NODE_ID, NodeKind.INTERNET),
            _node("alb", NodeKind.LOAD_BALANCER),
            _node("sg-isolated", NodeKind.SECURITY_GROUP),
        ]
        edges = [_edge(INTERNET_NODE_ID, "alb")]
        graph = build_graph(nodes, edges)
        result = bfs(graph, INTERNET_NODE_ID)

        assert "alb" in result.reachable
        assert "sg-isolated" not in result.reachable


class TestMultiplePaths:
    def test_shortest_path_selected(self) -> None:
        nodes = [
            _node(INTERNET_NODE_ID, NodeKind.INTERNET),
            _node("alb", NodeKind.LOAD_BALANCER),
            _node("inst", NodeKind.INSTANCE),
            _node("db", NodeKind.DB_INSTANCE),
        ]
        edges = [
            _edge(INTERNET_NODE_ID, "alb"),
            _edge(INTERNET_NODE_ID, "inst"),
            _edge("alb", "db"),
            _edge("inst", "db"),
        ]
        graph = build_graph(nodes, edges)
        result = bfs(graph, INTERNET_NODE_ID)
        path = shortest_path(result.parents, "db")

        assert path.hops == 2


class TestEmptyGraph:
    def test_internet_only(self) -> None:
        nodes = [_node(INTERNET_NODE_ID, NodeKind.INTERNET)]
        edges: list[Edge] = []
        graph = build_graph(nodes, edges)
        result = bfs(graph, INTERNET_NODE_ID)

        assert len(result.reachable) == 0

    def test_path_to_unreachable_returns_empty(self) -> None:
        result_parents: dict[str, str] = {}
        path = shortest_path(result_parents, "nonexistent")
        assert path.path == []
        assert path.hops == 0


class TestSGReachableOnlyViaInstance:
    def test_sg_three_hops(self) -> None:
        nodes = [
            _node(INTERNET_NODE_ID, NodeKind.INTERNET),
            _node("alb", NodeKind.LOAD_BALANCER),
            _node("inst", NodeKind.INSTANCE),
            _node("sg-back", NodeKind.SECURITY_GROUP),
        ]
        edges = [
            _edge(INTERNET_NODE_ID, "alb"),
            _edge("alb", "inst"),
            _edge("inst", "sg-back"),
        ]
        graph = build_graph(nodes, edges)
        result = bfs(graph, INTERNET_NODE_ID)

        assert "sg-back" in result.reachable
        path = shortest_path(result.parents, "sg-back")
        assert path.hops == 3
        assert path.path[0] == INTERNET_NODE_ID
