# docs/ddr/README.md

# Development Decision Records

DDRs capture implementation-level decisions: how architecture is realized in code.
They are complementary to ADRs (Architecture Decision Records), which capture system-level
structure and long-lived architectural tradeoffs.

## When to write a DDR

Write a DDR when a decision:
- changes module boundaries or import structure
- constrains future refactors or adds a long-lived convention
- affects testing strategy, file layout, or Home Assistant integration wiring
- clarifies "how" an ADR is implemented

Examples:
- Dispatcher module location
- Inventory file as authoritative API surface
- Functional framer/deframer API

## Where DDRs live

- Individual files under: docs/ddr/
- Naming: DDR-000X-<short-slug>.md

## DDR template

Each DDR should include:

- Status: Proposed | Accepted | Superseded
- Date: YYYY-MM-DD
- Related ADRs: optional references
- Context: what prompted the decision
- Decision: what was decided
- Rationale: why this option was chosen
- Consequences: concrete impacts on code/tests/workflow

## Lifecycle

- Proposed: under discussion, not yet binding
- Accepted: authoritative guidance for implementation
- Superseded: replaced by a newer DDR (link to the superseding DDR)

## Relationship to ADRs

- ADRs explain the architecture and "why"
- DDRs explain code-level implementation choices and "how"
- DDRs may reference ADRs to show alignment with architectural intent
