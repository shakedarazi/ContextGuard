"""Integration tests for the full ContextGuard pipeline."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from contextguard.cli import app
from contextguard.model import AnalysisResult

FIXTURES = Path(__file__).parent.parent / "fixtures"
runner = CliRunner()


class TestFullPlan:
    def test_end_to_end(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["analyze", "--plan", str(FIXTURES / "full-plan.json"), "--out", str(tmp_path)]
        )
        assert result.exit_code in (0, 1)

        report_json = tmp_path / "report.json"
        assert report_json.exists()
        data = json.loads(report_json.read_text(encoding="utf-8"))
        parsed = AnalysisResult.model_validate(data)

        assert len(parsed.findings) > 0

        critical_findings = [
            f for f in parsed.findings if f.context_severity == "CRITICAL"
        ]
        for f in critical_findings:
            if f.attack_path:
                assert len(f.breakpoints) > 0

        report_md = tmp_path / "report.md"
        assert report_md.exists()
        md_text = report_md.read_text(encoding="utf-8")
        assert "## Run Metadata" in md_text
        assert "## Executive Risk Summary" in md_text

    def test_json_determinism(self, tmp_path: Path) -> None:
        out1 = tmp_path / "run1"
        out2 = tmp_path / "run2"
        runner.invoke(
            app, ["analyze", "--plan", str(FIXTURES / "full-plan.json"), "--out", str(out1)]
        )
        runner.invoke(
            app, ["analyze", "--plan", str(FIXTURES / "full-plan.json"), "--out", str(out2)]
        )
        json1 = (out1 / "report.json").read_text(encoding="utf-8")
        json2 = (out2 / "report.json").read_text(encoding="utf-8")
        assert json1 == json2

    def test_sidecar_written(self, tmp_path: Path) -> None:
        runner.invoke(
            app, ["analyze", "--plan", str(FIXTURES / "full-plan.json"), "--out", str(tmp_path)]
        )
        meta_file = tmp_path / "run-metadata.json"
        assert meta_file.exists()
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        assert "timestamp_utc" in meta
        assert meta["timestamp_utc"].endswith("Z")
        assert "plan_path" in meta
        assert "output_dir" in meta


class TestUnknownOnly:
    def test_valid_empty_report(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["analyze", "--plan", str(FIXTURES / "unknown-only.json"), "--out", str(tmp_path)],
        )
        assert result.exit_code == 0

        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        parsed = AnalysisResult.model_validate(data)

        assert len(parsed.findings) == 0
        assert parsed.stats.skipped == 2
        assert parsed.stats.total == 2
        assert parsed.crown_jewel_ids == []
        assert parsed.attack_paths == []


class TestEmptyPlan:
    def test_valid_empty_report(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["analyze", "--plan", str(FIXTURES / "empty-plan.json"), "--out", str(tmp_path)],
        )
        assert result.exit_code == 0

        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        parsed = AnalysisResult.model_validate(data)

        assert len(parsed.findings) == 0
        internet_nodes = [n for n in parsed.nodes if n.id == "__internet__"]
        assert len(internet_nodes) == 1


class TestMalformedJSON:
    def test_exit_code_2_friendly_error(self) -> None:
        result = runner.invoke(
            app, ["analyze", "--plan", str(FIXTURES / "malformed.json"), "--out", "/tmp/cg"]
        )
        assert result.exit_code == 2
        assert "not valid JSON" in result.output or "not valid JSON" in (result.stderr or "")


class TestInvalidFailOn:
    def test_invalid_severity_exit_2(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "analyze",
                "--plan", str(FIXTURES / "full-plan.json"),
                "--out", str(tmp_path),
                "--fail-on", "bogus",
            ],
        )
        assert result.exit_code == 2
        output = result.output + (result.stderr or "")
        assert "invalid severity" in output.lower()


class TestCaseInsensitiveFailOn:
    def test_mixed_case_accepted(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "analyze",
                "--plan", str(FIXTURES / "empty-plan.json"),
                "--out", str(tmp_path),
                "--fail-on", "critical,HIGH",
            ],
        )
        assert result.exit_code == 0


class TestAttackPath:
    """E2E test for the attackpath-plan.json fixture — validates SC-1 through SC-7."""

    def test_critical_findings_and_attack_path(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["analyze", "--plan", str(FIXTURES / "attackpath-plan.json"), "--out", str(tmp_path)],
        )

        # SC-5: exit code 1 (CRITICAL breaches gate)
        assert result.exit_code == 1

        report_json = tmp_path / "report.json"
        assert report_json.exists()
        data = json.loads(report_json.read_text(encoding="utf-8"))
        parsed = AnalysisResult.model_validate(data)

        # SC-1: at least 1 CRITICAL finding
        critical_findings = [
            f for f in parsed.findings if f.context_severity == "CRITICAL"
        ]
        assert len(critical_findings) >= 1

        # SC-2: at least 1 CRITICAL finding has attack_path starting with __internet__
        # and ending with a crown-jewel node
        crown_jewel_ids = set(parsed.crown_jewel_ids)
        paths_valid = [
            f
            for f in critical_findings
            if f.attack_path
            and f.attack_path[0] == "__internet__"
            and f.attack_path[-1] in crown_jewel_ids
        ]
        assert len(paths_valid) >= 1

        # SC-3: at least 1 CRITICAL finding has non-empty breakpoints,
        # each breakpoint node_id is an intermediate on the attack path
        bp_valid = [
            f
            for f in critical_findings
            if f.breakpoints
            and all(bp.node_id in f.attack_path[1:-1] for bp in f.breakpoints)
        ]
        assert len(bp_valid) >= 1

        # SC-4: report.md contains "What you learned"
        report_md = tmp_path / "report.md"
        assert report_md.exists()
        md_text = report_md.read_text(encoding="utf-8")
        assert "What you learned" in md_text

        # SC-7: at least 1 edge has type forward_reachability with non-null meta
        forward_edges = [
            e
            for e in parsed.edges
            if e.type == "forward_reachability" and e.meta is not None
        ]
        assert len(forward_edges) >= 1

        # New: crown_jewel_ids populated
        assert len(parsed.crown_jewel_ids) >= 1

        # New: attack_paths populated and sorted by hops
        assert len(parsed.attack_paths) >= 1
        for ap in parsed.attack_paths:
            assert ap.hops >= 1
            assert len(ap.path) >= 2
            assert len(ap.finding_ids) >= 1

        # New: breakpoints have paths_broken >= 1
        for f in parsed.findings:
            for bp in f.breakpoints:
                assert bp.paths_broken >= 1

    def test_json_determinism(self, tmp_path: Path) -> None:
        """SC-6: byte-identical JSON across two runs."""
        out1 = tmp_path / "run1"
        out2 = tmp_path / "run2"
        runner.invoke(
            app,
            ["analyze", "--plan", str(FIXTURES / "attackpath-plan.json"), "--out", str(out1)],
        )
        runner.invoke(
            app,
            ["analyze", "--plan", str(FIXTURES / "attackpath-plan.json"), "--out", str(out2)],
        )
        json1 = (out1 / "report.json").read_text(encoding="utf-8")
        json2 = (out2 / "report.json").read_text(encoding="utf-8")
        assert json1 == json2

    def test_fail_on_critical_and_high(self, tmp_path: Path) -> None:
        """--fail-on uses exact match; CRITICAL,HIGH catches CRITICAL findings."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "--plan", str(FIXTURES / "attackpath-plan.json"),
                "--out", str(tmp_path),
                "--fail-on", "CRITICAL,HIGH",
            ],
        )
        assert result.exit_code == 1

    def test_no_mermaid_flag(self, tmp_path: Path) -> None:
        """--no-mermaid suppresses the Mermaid block in report.md."""
        runner.invoke(
            app,
            [
                "analyze",
                "--plan", str(FIXTURES / "attackpath-plan.json"),
                "--out", str(tmp_path),
                "--no-mermaid",
            ],
        )
        md_text = (tmp_path / "report.md").read_text(encoding="utf-8")
        assert "```mermaid" not in md_text

    def test_sidecar_run_metadata(self, tmp_path: Path) -> None:
        """run-metadata.json exists with required ISO8601 UTC timestamp."""
        runner.invoke(
            app,
            ["analyze", "--plan", str(FIXTURES / "attackpath-plan.json"), "--out", str(tmp_path)],
        )
        meta_file = tmp_path / "run-metadata.json"
        assert meta_file.exists()
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        assert set(meta.keys()) == {"output_dir", "plan_path", "timestamp_utc"}
        assert meta["timestamp_utc"].endswith("Z")
        assert "attackpath-plan.json" in meta["plan_path"]


class TestBoundaryEnforcement:
    """Verify output_* modules do not import graph or scoring (analysis/render boundary)."""

    _OUTPUT_MODULES = [
        Path(__file__).parent.parent.parent / "contextguard" / "output_markdown.py",
        Path(__file__).parent.parent.parent / "contextguard" / "output_json.py",
        Path(__file__).parent.parent.parent / "contextguard" / "output_console.py",
        Path(__file__).parent.parent.parent / "contextguard" / "output_run_metadata.py",
    ]

    _FORBIDDEN_IMPORTS = {"contextguard.graph", "contextguard.scoring"}

    def test_no_forbidden_imports(self) -> None:
        for module_path in self._OUTPUT_MODULES:
            source = module_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(module_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name not in self._FORBIDDEN_IMPORTS, (
                            f"{module_path.name} must not import {alias.name}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    assert module not in self._FORBIDDEN_IMPORTS, (
                        f"{module_path.name} must not import from {module}"
                    )
