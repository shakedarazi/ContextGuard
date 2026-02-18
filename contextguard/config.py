"""Configuration loader — contextguard.yml parsing and defaults."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import yaml
from pydantic import ValidationError

from contextguard.logger import logger
from contextguard.model import ContextGuardConfig


def load_config(path: Path | None = None) -> ContextGuardConfig:
    """Load config from YAML file, or return defaults if no path given."""
    if path is None:
        logger.debug("No config file provided, using defaults")
        return ContextGuardConfig()

    from pathlib import Path as _Path

    p = _Path(str(path))

    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("Config file not found: %s — using defaults", path)
        return ContextGuardConfig()
    except OSError as e:
        logger.warning("Cannot read config file %s: %s — using defaults", path, e)
        return ContextGuardConfig()

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        logger.warning("Malformed YAML in %s: %s — using defaults", path, e)
        return ContextGuardConfig()

    if not isinstance(raw, dict):
        logger.warning("Config file %s is not a YAML mapping — using defaults", path)
        return ContextGuardConfig()

    try:
        return ContextGuardConfig.model_validate(raw)
    except ValidationError as e:
        logger.warning("Invalid config in %s: %s — using defaults", path, e)
        return ContextGuardConfig()
