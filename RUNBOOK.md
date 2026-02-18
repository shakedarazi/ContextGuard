# ContextGuard — Runbook

## Installation

### With pipx (recommended)

```bash
pipx install .
```

### With uv

```bash
uv tool install .
```

### Development

```bash
uv sync --dev
```

## Generating a Terraform Plan

ContextGuard requires a Terraform plan in JSON format:

```bash
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > tfplan.json
```

## CLI Usage

### Basic Analysis

```bash
contextguard analyze --plan tfplan.json
```

This produces:
- Console summary (severity distribution, top attack paths, breakpoints)
- `report.md` — detailed Markdown report
- `report.json` — machine-readable JSON report

### Custom Output Directory

```bash
contextguard analyze --plan tfplan.json --out ./reports
```

### Custom Configuration

```bash
contextguard analyze --plan tfplan.json --config contextguard.yml
```

### Override Gating Threshold

The `--fail-on` flag overrides the gating configuration at runtime:

```bash
contextguard analyze --plan tfplan.json --fail-on critical,high
```

Values are case-insensitive. Valid severities: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NOISE`.

### Verbose Mode

```bash
contextguard analyze --plan tfplan.json --verbose
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Analysis passed gating |
| 1 | Analysis completed but gating threshold breached |
| 2 | Input error (malformed JSON, missing file, invalid --fail-on) |

## CI Integration

### GitHub Actions

```yaml
- name: Run ContextGuard
  run: contextguard analyze --plan tfplan.json --fail-on critical
```

The exit code drives the pipeline: `0` = pass, `1` = fail (security gate), `2` = bad input.

### GitLab CI

```yaml
security-scan:
  script:
    - contextguard analyze --plan tfplan.json --fail-on critical,high --out reports/
  artifacts:
    paths:
      - reports/
```

## Configuration File

Create `contextguard.yml` in your project root:

```yaml
crown_jewels:
  - kind: db_instance
  - tag: "sensitivity=high"

gating:
  fail_on:
    - CRITICAL
  max_path_to_crown_jewel: 4
```

### Crown Jewels

Define which resources are crown jewels by kind or tag. Default: all `db_instance` resources.

### Gating

- `fail_on`: list of severities that trigger exit code 1. Default: `[CRITICAL]`.
- `max_path_to_crown_jewel`: maximum hops for severity escalation. Default: `4`.

## Adding New Resource Types

ContextGuard supports 11 AWS resource types in v1. To add a new type:

1. Add a `NodeKind` variant to `contextguard/model.py`.
2. Add the AWS type mapping to `SUPPORTED_TYPES` in `contextguard/terraform_adapter.py`.
3. Write an `_extract_<type>` function in `terraform_adapter.py`.
4. Add any new finding rules to `contextguard/findings.py`.
5. Add a breakpoint template to `contextguard/scoring.py` if applicable.
6. Add test fixtures and unit tests.
