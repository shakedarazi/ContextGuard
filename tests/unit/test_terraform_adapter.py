"""Tests for terraform_adapter.parse_plan()."""

from __future__ import annotations

from pathlib import Path

import pytest

from contextguard.model import INTERNET_NODE_ID, EdgeType, NodeCategory
from contextguard.terraform_adapter import ParseError, parse_plan

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestInternetNode:
    def test_internet_node_present_on_empty_plan(self) -> None:
        result = parse_plan(FIXTURES / "empty-plan.json")
        ids = [n.id for n in result.nodes]
        assert INTERNET_NODE_ID in ids

    def test_internet_node_present_on_full_plan(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        ids = [n.id for n in result.nodes]
        assert INTERNET_NODE_ID in ids

    def test_internet_node_category(self) -> None:
        result = parse_plan(FIXTURES / "empty-plan.json")
        internet = next(n for n in result.nodes if n.id == INTERNET_NODE_ID)
        assert internet.category == NodeCategory.INTERNET


class TestInternetEdges:
    def test_internet_edges_target_public_lb(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        internet_edges = [e for e in result.edges if e.from_id == INTERNET_NODE_ID]
        targets = {e.to_id for e in internet_edges}
        assert "aws_lb.web" in targets

    def test_internet_edges_target_public_instance(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        internet_edges = [e for e in result.edges if e.from_id == INTERNET_NODE_ID]
        targets = {e.to_id for e in internet_edges}
        assert "aws_instance.web" in targets

    def test_internet_edges_do_not_target_sg(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        internet_edges = [e for e in result.edges if e.from_id == INTERNET_NODE_ID]
        targets = {e.to_id for e in internet_edges}
        sg_ids = {n.id for n in result.nodes if n.category == NodeCategory.FIREWALL}
        assert targets.isdisjoint(sg_ids), "INTERNET should not connect to security groups"

    def test_internet_edges_do_not_target_private_instance(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        internet_edges = [e for e in result.edges if e.from_id == INTERNET_NODE_ID]
        targets = {e.to_id for e in internet_edges}
        assert "aws_instance.backend" not in targets

    def test_internet_edges_are_network_exposure(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        internet_edges = [e for e in result.edges if e.from_id == INTERNET_NODE_ID]
        for edge in internet_edges:
            assert edge.type == EdgeType.NETWORK_EXPOSURE

    def test_sg_open_to_world_gets_no_internet_edge(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        internet_targets = {
            e.to_id for e in result.edges if e.from_id == INTERNET_NODE_ID
        }
        assert "aws_security_group.web" not in internet_targets


class TestSkipCounts:
    def test_empty_plan_counts(self) -> None:
        result = parse_plan(FIXTURES / "empty-plan.json")
        assert result.stats.total == 0
        assert result.stats.supported == 0
        assert result.stats.skipped == 0

    def test_unknown_only_all_skipped(self) -> None:
        result = parse_plan(FIXTURES / "unknown-only.json")
        assert result.stats.skipped == 2
        assert result.stats.supported == 0
        assert result.stats.total == 2

    def test_mixed_plan_counts(self) -> None:
        result = parse_plan(FIXTURES / "mixed-plan.json")
        assert result.stats.supported == 2
        assert result.stats.skipped == 2
        assert result.stats.total == 4

    def test_full_plan_all_supported(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        assert result.stats.skipped == 0
        assert result.stats.supported == 12


class TestMalformedInput:
    def test_malformed_json_raises_parse_error(self) -> None:
        with pytest.raises(ParseError, match="not valid JSON"):
            parse_plan(FIXTURES / "malformed.json")

    def test_missing_file_raises_parse_error(self) -> None:
        with pytest.raises(ParseError, match="File not found"):
            parse_plan(FIXTURES / "nonexistent.json")

    def test_no_resource_changes_key(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text('{"some_key": 123}')
        with pytest.raises(ParseError, match="resource_changes"):
            parse_plan(bad)


class TestSGAssociationEdges:
    def test_sg_has_association_edge_to_lb(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        assoc_edges = [
            e
            for e in result.edges
            if e.type == EdgeType.ASSOCIATION and e.from_id == "aws_security_group.web"
        ]
        targets = {e.to_id for e in assoc_edges}
        assert "aws_lb.web" in targets

    def test_sg_has_association_edge_to_instance(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        assoc_edges = [
            e
            for e in result.edges
            if e.type == EdgeType.ASSOCIATION and e.from_id == "aws_security_group.web"
        ]
        targets = {e.to_id for e in assoc_edges}
        assert "aws_instance.web" in targets


class TestCrownJewelFlag:
    def test_db_instance_is_crown_jewel(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        db = next(n for n in result.nodes if n.category == NodeCategory.DATABASE)
        assert db.flags.crown_jewel is True


class TestIAMExtraction:
    def test_iam_policy_actions_extracted(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        wide = next(
            (n for n in result.nodes if n.id == "aws_iam_policy.wide"), None
        )
        assert wide is not None
        assert wide.meta is not None
        assert "*" in wide.meta.get("actions", [])

    def test_iam_binding_edges_created(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        binding_edges = [e for e in result.edges if e.type == EdgeType.IAM_BINDING]
        assert len(binding_edges) > 0


class TestNodeProviderAndCategory:
    def test_lb_node_has_aws_provider_and_category(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        lbs = [n for n in result.nodes if n.category == NodeCategory.LOAD_BALANCER]
        assert len(lbs) > 0
        for lb in lbs:
            assert lb.provider == "aws"
            assert lb.kind == "aws_lb"

    def test_db_node_has_database_category(self) -> None:
        result = parse_plan(FIXTURES / "full-plan.json")
        dbs = [n for n in result.nodes if n.category == NodeCategory.DATABASE]
        assert len(dbs) > 0
        for db in dbs:
            assert db.provider == "aws"
            assert db.kind == "aws_db_instance"
