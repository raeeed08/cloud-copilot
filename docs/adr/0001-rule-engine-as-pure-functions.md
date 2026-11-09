# ADR 0001: Rules are pure functions over normalised data

**Status:** accepted

## Context
v1 mixed API calls and decisions in places, and supported one region. Adding Azure, more AWS services, tests and
an MCP server needs a uniform contract.

## Decision
Scanners (I/O) and rules (logic) are separate, registered by decorators. Scanners return plain dicts. Rules are
`dict -> Iterable[Hit]` with rich metadata (severity, category, rationale, remediation, Terraform, CIS, NIST).

## Consequences
- Every rule is unit-testable with a dict, and the demo estate exercises all of them (`test_registry.py`).
- The API, dashboard, compliance view, knowledge base (one document per rule) and MCP catalogue are generated
  from the registry, so there is one source of truth.
- Scanner normalisation must be tested separately (moto for AWS, SDK-shaped fakes for Azure).
