# Architecture Decision Records (ADR)

This directory contains Architecture Decision Records (ADRs) for the elkm1 project.

ADRs capture architectural decisions:
what we decided, why we decided it, and what constraints it creates.

They are the authoritative architectural contract for the project.

---

## Purpose of ADRs

ADRs exist to:

- Record long-lived architectural decisions
- Provide a stable reference for design and implementation work
- Prevent architectural drift across parallel development efforts
- Make architectural intent explicit and reviewable

ADRs answer questions like:
- Why is E27 implemented as a separate backend?
- Who owns protocol state vs semantic state?
- What guarantees must code and tests preserve?

They do not describe how code is written or tested — that belongs in DDRs.

---

## Relationship to DDRs

This directory is a peer to:

    elkm1/docs/ddr/

- ADRs define what and why (architecture)
- DDRs define how and where (design, implementation, tests)

Every DDR must reference one or more ADRs that it implements.

Chain of authority:

    ADR  ->  DDR  ->  Code / Tests

If a DDR conflicts with an ADR, the ADR wins.

---

## Directory Structure

    elkm1/docs/
    ├── adr/
    │   ├── README.md
    │   ├── ADR-0001-<slug>.md
    │   ├── ADR-0002-<slug>.md
    │   └── ...
    └── ddr/
        └── ...

- Each ADR lives in its own file
- ADR numbers are stable and never reused
- Filenames are human-friendly; the ADR number is the canonical identifier

---

## ADR File Naming

Format:

    ADR-XXXX-short-descriptive-slug.md

Examples:
- ADR-0001-e27-first-class-backend.md
- ADR-0021-e27-discovery-udp-2362.md

Rules:
- Numbers are zero-padded
- Slug is lowercase and hyphen-separated
- Never renumber an ADR once published

---

## ADR Template

Each ADR should follow this structure:

    ADR-XXXX: <Title>

    Status
    Proposed | Accepted | Superseded

    Context
    What problem or situation led to this decision?

    Decision
    What was decided? Be precise and declarative.

    Rationale
    Why this decision was chosen over alternatives.

    Consequences
    What this decision enables, restricts, or requires.

    Scope / Non-Goals
    What this ADR applies to — and explicitly does not apply to.

    References
    Related documents, specifications, or prior ADRs.

Keep ADRs implementation-free.
No code, diffs, or low-level mechanics.

---

## ADR Lifecycle

1. Proposed
   - Drafted in the architecture thread
   - May be referenced experimentally by DDRs

2. Accepted
   - Explicitly agreed upon
   - Binding for all design, implementation, and testing work

3. Superseded
   - Replaced by a newer ADR
   - Must reference the ADR that supersedes it

ADRs are append-only history — we do not rewrite past decisions.

---

## Governance Rules

- ADRs are owned by the architecture discussion, not coding threads
- Design and implementation threads may propose ADRs but do not finalize them
- All architectural changes must land here before being implemented

---

## What Belongs in an ADR (and What Doesn’t)

Belongs here:
- Protocol boundaries and ownership
- State models and lifetimes
- Security and key-management rules
- Semantic contracts and invariants
- UX and discovery models
- Non-negotiable constraints

Does not belong here:
- Code structure
- Algorithms
- Performance tuning
- Test cases
- Patch details

Those belong in DDRs.

---

## Guiding Principle

ADRs define the rules of the game.
DDRs describe how we play it.

If something feels architectural, it probably belongs here.
