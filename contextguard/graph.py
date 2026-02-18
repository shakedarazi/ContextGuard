"""Graph engine — build_graph, bfs, shortest_path."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contextguard.model import Edge, Node


@dataclass
class Graph:
    adjacency: dict[str, list[str]] = field(default_factory=dict)
    nodes: dict[str, Node] = field(default_factory=dict)


@dataclass
class BfsResult:
    reachable: set[str] = field(default_factory=set)
    parents: dict[str, str] = field(default_factory=dict)


@dataclass
class PathResult:
    path: list[str] = field(default_factory=list)
    hops: int = 0


def build_graph(nodes: list[Node], edges: list[Edge]) -> Graph:
    """Build an adjacency list graph from canonical nodes and edges."""
    g = Graph()
    for node in nodes:
        g.nodes[node.id] = node
        if node.id not in g.adjacency:
            g.adjacency[node.id] = []
    for edge in edges:
        if edge.from_id not in g.adjacency:
            g.adjacency[edge.from_id] = []
        g.adjacency[edge.from_id].append(edge.to_id)
    
    # Sort adjacency lists for deterministic BFS traversal
    for node_id in g.adjacency:
        g.adjacency[node_id].sort()
    
    return g


def bfs(graph: Graph, start_id: str) -> BfsResult:
    """BFS from a single start node. Returns reachable set and parent map."""
    result = BfsResult()
    if start_id not in graph.adjacency:
        return result

    visited: set[str] = {start_id}
    queue: deque[str] = deque([start_id])

    while queue:
        current = queue.popleft()
        for neighbor in graph.adjacency.get(current, []):
            if neighbor not in visited:
                visited.add(neighbor)
                result.parents[neighbor] = current
                queue.append(neighbor)

    visited.discard(start_id)
    result.reachable = visited
    return result


def shortest_path(parents: dict[str, str], target_id: str) -> PathResult:
    """Reconstruct the shortest path from BFS start to target using parent map."""
    if target_id not in parents:
        return PathResult()

    path: list[str] = [target_id]
    current = target_id
    while current in parents:
        current = parents[current]
        path.append(current)
    path.reverse()

    return PathResult(path=path, hops=len(path) - 1)
