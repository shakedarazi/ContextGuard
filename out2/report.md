# ContextGuard Report

## Run Metadata

- Timestamp (UTC): 2026-02-18T23:43:36.398820Z
- Plan path: `C:\Users\shaked arazi\Desktop\Projects\ContextGuard\tests\fixtures\full-plan.json`
- Output directory: `C:\Users\shaked arazi\Desktop\Projects\ContextGuard\out2`

## Executive Risk Summary

| Severity | Count |
|----------|-------|
| HIGH | 1 |
| NOISE | 3 |

**Gate:** PASSED ✓

**Crown jewel reachable:** No internet-to-crown-jewel path found

## Internet-to-Crown-Jewel Exposure

No internet-reachable path to any crown jewel was found.

## Actionable Findings

### Public load balancer

| Field | Value |
|-------|-------|
| Node | `aws_lb.web` |
| Base Severity | MEDIUM |
| Context Severity | HIGH |
| Override Reason | Reachable from internet but no path to crown jewel |

## Non-Exploitable / Noise

| Finding | Node | Override Reason |
|---------|------|-----------------|
| Security group open to 0.0.0.0/0 | `aws_security_group.web` | Not reachable from internet |
| Wildcard IAM action | `aws_iam_policy.wide` | Not reachable from internet |
| IAM PassRole permission | `aws_iam_role_policy.inline` | Not reachable from internet |

## Methodology

ContextGuard builds a reachability graph from the Terraform plan. Each finding receives a base severity from static rules, then a contextual override based on whether the finding's node is reachable from the internet and whether an attack path exists to a crown jewel. Shorter paths to crown jewels produce higher severity. Path breakpoints identify where to sever the attack path.

## Scope

- Supported resources analyzed: 12
- Unsupported resources skipped: 0
- Total resources in plan: 12
