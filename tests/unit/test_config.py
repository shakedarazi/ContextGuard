"""Tests for config.load_config()."""

from __future__ import annotations

from pathlib import Path

from contextguard.config import load_config
from contextguard.model import NodeKind, Severity


class TestDefaults:
    def test_default_config_no_file(self) -> None:
        config = load_config(None)
        assert len(config.crown_jewels) == 1
        assert config.crown_jewels[0].kind == NodeKind.DB_INSTANCE
        assert config.gating.fail_on == [Severity.CRITICAL]
        assert config.gating.max_path_to_crown_jewel == 4

    def test_default_config_missing_file(self, tmp_path: Path) -> None:
        config = load_config(tmp_path / "nonexistent.yml")
        assert config.gating.fail_on == [Severity.CRITICAL]


class TestCustomConfig:
    def test_custom_config(self, tmp_path: Path) -> None:
        cfg = tmp_path / "custom.yml"
        cfg.write_text(
            "crown_jewels:\n"
            "  - kind: db_instance\n"
            "  - tag: 'sensitivity=high'\n"
            "gating:\n"
            "  fail_on:\n"
            "    - CRITICAL\n"
            "    - HIGH\n"
            "  max_path_to_crown_jewel: 3\n"
        )
        config = load_config(cfg)
        assert len(config.crown_jewels) == 2
        assert config.gating.fail_on == [Severity.CRITICAL, Severity.HIGH]
        assert config.gating.max_path_to_crown_jewel == 3


class TestMalformedYAML:
    def test_malformed_yaml_returns_defaults(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("{{{{not yaml!!!!")
        config = load_config(bad)
        assert config.gating.fail_on == [Severity.CRITICAL]

    def test_non_mapping_returns_defaults(self, tmp_path: Path) -> None:
        bad = tmp_path / "list.yml"
        bad.write_text("- item1\n- item2\n")
        config = load_config(bad)
        assert config.gating.fail_on == [Severity.CRITICAL]
