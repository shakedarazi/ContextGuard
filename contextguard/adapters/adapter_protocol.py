"""Adapter protocol and registry for IaC source parsers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pathlib import Path

    from contextguard.core.model import AdapterOutput


class IacAdapter(Protocol):
    """Protocol for parsing IaC sources into canonical model."""

    def parse(self, path: Path) -> AdapterOutput:
        """Parse IaC file into canonical nodes/edges."""
        ...

    @property
    def supported_formats(self) -> list[str]:
        """File extensions this adapter handles (e.g., ['.json'])."""
        ...


class TerraformAwsAdapter:
    """Adapter for Terraform plan JSON (AWS provider)."""

    @property
    def supported_formats(self) -> list[str]:
        return [".json"]

    def parse(self, path):  # type: ignore[no-untyped-def]
        from contextguard.adapters.terraform_aws import parse_plan
        
        return parse_plan(path)


# Registry of available adapters
ADAPTERS: dict[str, IacAdapter] = {
    "terraform": TerraformAwsAdapter(),
}


def get_adapter(adapter_name: str) -> IacAdapter:
    """Get adapter by name, raise KeyError if not found."""
    return ADAPTERS[adapter_name]
