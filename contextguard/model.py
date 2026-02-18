"""Canonical model — nodes, edges, findings, config."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

INTERNET_NODE_ID = "__internet__"


class NodeKind(StrEnum):
    INTERNET = "internet"
    SECURITY_GROUP = "security_group"
    LOAD_BALANCER = "load_balancer"
    INSTANCE = "instance"
    AUTOSCALING_GROUP = "autoscaling_group"
    DB_INSTANCE = "db_instance"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"


class EdgeType(StrEnum):
    NETWORK_EXPOSURE = "network_exposure"
    IAM_BINDING = "iam_binding"
    DATA_ACCESS = "data_access"
    ASSOCIATION = "association"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOISE = "NOISE"


class FindingCategory(StrEnum):
    NETWORK = "network"
    IAM = "iam"
    DATA = "data"


class BreakpointType(StrEnum):
    NETWORK = "network"
    IDENTITY = "identity"
    DATA = "data"


class NodeFlags(BaseModel):
    internet_facing: bool = False
    crown_jewel: bool = False


class Node(BaseModel):
    id: str
    kind: NodeKind
    flags: NodeFlags = Field(default_factory=NodeFlags)
    meta: dict[str, object] | None = None


class Edge(BaseModel):
    from_id: str
    to_id: str
    type: EdgeType


class Breakpoint(BaseModel):
    node_id: str
    kind: NodeKind
    type: BreakpointType
    recommendation: str


class Finding(BaseModel):
    id: str
    node_id: str
    rule_id: str
    category: FindingCategory
    title: str
    description: str
    base_severity: Severity
    context_severity: Severity = Severity.NOISE
    override_reason: str = ""
    attack_path: list[str] = Field(default_factory=list)
    shortest_path_length: int | None = None
    breakpoints: list[Breakpoint] = Field(default_factory=list)


class CrownJewelRule(BaseModel):
    kind: NodeKind | None = None
    tag: str | None = None


class GatingConfig(BaseModel):
    fail_on: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL])
    max_path_to_crown_jewel: int = 4


class ContextGuardConfig(BaseModel):
    crown_jewels: list[CrownJewelRule] = Field(
        default_factory=lambda: [CrownJewelRule(kind=NodeKind.DB_INSTANCE)]
    )
    gating: GatingConfig = Field(default_factory=GatingConfig)


class AdapterStats(BaseModel):
    total: int
    supported: int
    skipped: int


class AdapterOutput(BaseModel):
    """Returned by terraform_adapter.parse_plan(). Contains only graph data."""

    nodes: list[Node]
    edges: list[Edge]
    stats: AdapterStats


class AnalysisResult(BaseModel):
    """Assembled at the end of the pipeline, after findings and scoring."""

    nodes: list[Node]
    edges: list[Edge]
    findings: list[Finding]
    stats: AdapterStats
