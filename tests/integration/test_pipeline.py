"""Integration tests for the full ContextGuard pipeline."""

from __future__ import annotations

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
        if critical_findings:
            assert "What you learned" in md_text

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
